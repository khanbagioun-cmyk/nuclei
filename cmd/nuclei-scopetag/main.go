package main

// nuclei-scopetag: Auto-tags redirect-prone templates with scope:final-only.
//
// Background:
// Nuclei's HTTP response chain processes responses in reverse order (final
// response first, then redirect responses via Previous()). By default, matchers
// evaluate against ALL responses in the chain (scope:all). This causes false
// positives when a matcher word like "admin" or "login" appears in a 302
// redirect's headers (e.g., Location: /admin-redirect).
//
// The scope:final-only field (implemented in pkg/operators/matchers/matchers.go)
// restricts matcher evaluation to only the final (non-redirect) response,
// eliminating redirect-chain FPs.
//
// Body vs Header behavior:
// Nuclei's ResponseChain.Fill() intentionally skips loading redirect response
// bodies (per RFC 7231: redirects happen with empty body). This means body-based
// matchers on redirect responses already won't match — scope:final-only is
// primarily effective for HEADER-based matchers. However, body matchers are
// still tagged because:
//   1. Future nuclei versions may load redirect bodies (custom transports)
//   2. Defense-in-depth: explicit scope is safer than relying on engine behavior
//   3. Some redirect responses DO have bodies (non-RFC-compliant servers)
//
// Usage:
//   nuclei-scopetag -t ~/.local/nuclei-templates-dev -dry-run    # preview
//   nuclei-scopetag -t ~/.local/nuclei-templates-dev             # apply
//   nuclei-scopetag -t ~/.local/nuclei-templates-dev -v          # verbose

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"gopkg.in/yaml.v3"
)

const banner = `
  _____           _____              _____            
 / ____|         / ____|       /\   |_   _|           
| (___   ___ ___| |  __       /  \    | |  _ __  ___  
 \___ \ / __/ __| | |_ |     / /\ \   | | | '__|/ _ \ 
 ____) | (__\__ \ |__| |    / ____ \ _| |_ | | | (_) |
|_____/ \___|___/\_____|   /_/    \_\_____||_|  \___/ 
                                                       v1.0.0 - Redirect-Scope Auto-Tagger
`

// highRiskWords are extremely common standalone words that appear in
// redirect bodies, login pages, error stubs, and 302/404 pages.
// These are the primary FP source when matchers fire on redirect bodies.
// We keep this list deliberately small: only words that are near-certain
// to appear in non-vulnerable redirect/error responses.
var highRiskWords = map[string]struct{}{
	"error":        {},
	"login":        {},
	"admin":        {},
	"warning":      {},
	"success":      {},
	"failed":       {},
	"denied":       {},
	"forbidden":    {},
	"unauthorized": {},
	"not found":    {},
	"404":          {},
	"403":          {},
	"500":          {},
	"index of":     {},
	"sign in":      {},
	"password":     {},
	"welcome":      {},
	"true":         {},
	"false":        {},
	"null":         {},
}

// genericWords is a broader set used only when the word list is very small (<=3).
// These are common but less certain than highRiskWords.
var genericWords = map[string]struct{}{
	"home":          {},
	"default":       {},
	"test":          {},
	"example":       {},
	"sample":        {},
	"demo":          {},
	"setup":         {},
	"install":       {},
	"configuration": {},
	"server":        {},
	"page":          {},
	"file":          {},
	"document":      {},
	"php":           {},
	"html":          {},
	"script":        {},
}

// stats tracks counts across all processed templates.
type stats struct {
	totalTemplates int
	modifiedCount  int
	skippedExists  int
	skippedNoBody  int
	skippedNoHTTP  int
	errorCount     int
}

// scopeDecision determines whether a word matcher is redirect-prone.
// Returns true if the matcher should get scope: final-only.
//
// Heuristic:
//   - If ANY word is in highRiskWords, flag it (these are near-certain FP sources).
//   - If the word list is small (<=3 words) AND any word is in genericWords, flag it.
//   - Otherwise, leave alone (CVE-specific word lists are unlikely to FP).
func scopeDecision(words []string) bool {
	if len(words) == 0 {
		return false
	}
	for _, w := range words {
		lw := strings.ToLower(strings.TrimSpace(w))
		if lw == "" {
			continue
		}
		if _, ok := highRiskWords[lw]; ok {
			return true
		}
	}
	// Only check generic words for small word lists
	if len(words) <= 3 {
		for _, w := range words {
			lw := strings.ToLower(strings.TrimSpace(w))
			if lw == "" {
				continue
			}
			if _, ok := genericWords[lw]; ok {
				return true
			}
		}
	}
	return false
}

// redirectProneDirs lists subdirectory paths under the templates root
// where redirect responses are common and body-word matchers are FP-prone.
// Templates outside these dirs (e.g. token-spray, osint, detections) typically
// target API endpoints where body words are reliable signals, not redirect FPs.
var redirectProneDirs = []string{
	"http/cves/",
	"http/vulnerabilities/",
	"http/misconfiguration/",
	"http/exposures/",
	"http/default-logins/",
}

// isRedirectProne checks if a template path falls under a redirect-prone directory.
func isRedirectProne(path string, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	for _, dir := range redirectProneDirs {
		if strings.HasPrefix(rel, dir) {
			return true
		}
	}
	return false
}

// matcherInfo captures data extracted from a YAML matcher node.
type matcherInfo struct {
	node      *yaml.Node // the matcher mapping node
	hasBody   bool       // matcher targets body part
	hasHeader bool       // matcher targets header part
	hasScope  bool       // matcher already has a scope field
	words     []string   // word list (for word matchers)
	isWord    bool       // is a word-type matcher
}

func extractMatcherInfo(m *yaml.Node) matcherInfo {
	info := matcherInfo{node: m}
	if m == nil || m.Kind != yaml.MappingNode {
		return info
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		key := m.Content[i].Value
		val := m.Content[i+1]
		switch key {
		case "type":
			if val.Value == "word" {
				info.isWord = true
			}
		case "part":
			if val.Value == "body" || val.Value == "" {
				info.hasBody = true
			}
			if val.Value == "header" {
				info.hasHeader = true
			}
		case "scope":
			info.hasScope = true
		case "words":
			if val.Kind == yaml.SequenceNode {
				for _, item := range val.Content {
					if item.Value != "" {
						info.words = append(info.words, item.Value)
					}
				}
			}
		}
	}
	return info
}

// injectScope adds scope: final-only to a matcher mapping node.
// Inserted at the end of the mapping to minimize disruption.
func injectScope(m *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	keyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: "scope",
		Tag:   "!!str",
	}
	valNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: "final-only",
		Tag:   "!!str",
	}
	m.Content = append(m.Content, keyNode, valNode)
}

// processTemplate parses, analyzes, and optionally modifies a single template file.
// Returns (modified, error).
func processTemplate(path string, dryRun bool) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return false, fmt.Errorf("yaml parse: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return false, nil
	}
	tmpl := root.Content[0]
	if tmpl.Kind != yaml.MappingNode {
		return false, nil
	}

	// Find "http:" key in the template
	var httpNode *yaml.Node
	for i := 0; i+1 < len(tmpl.Content); i += 2 {
		if tmpl.Content[i].Value == "http" {
			httpNode = tmpl.Content[i+1]
			break
		}
	}
	if httpNode == nil || httpNode.Kind != yaml.SequenceNode {
		return false, nil // not an HTTP template
	}

	modified := false
	// Iterate over HTTP request blocks
	for _, reqNode := range httpNode.Content {
		if reqNode.Kind != yaml.MappingNode {
			continue
		}
		// Find "matchers:" in this request
		for i := 0; i+1 < len(reqNode.Content); i += 2 {
			if reqNode.Content[i].Value != "matchers" {
				continue
			}
			matchersNode := reqNode.Content[i+1]
			if matchersNode.Kind != yaml.SequenceNode {
				continue
			}
			// Examine each matcher
			for _, mNode := range matchersNode.Content {
				if mNode.Kind != yaml.MappingNode {
					continue
				}
				info := extractMatcherInfo(mNode)
				// Tag word matchers targeting body or header that don't already have scope
				if !info.isWord || info.hasScope || (!info.hasBody && !info.hasHeader) {
					continue
				}
				if scopeDecision(info.words) {
					if !dryRun {
						injectScope(mNode)
					}
					modified = true
				}
			}
		}
	}

	if modified && !dryRun {
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(&root); err != nil {
			return false, fmt.Errorf("yaml encode: %w", err)
		}
		enc.Close()
		if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
			return false, fmt.Errorf("write: %w", err)
		}
	}

	return modified, nil
}

func main() {
	var (
		templatesDir string
		dryRun       bool
		verbose      bool
	)
	flag.StringVar(&templatesDir, "t", "", "Path to nuclei templates directory")
	flag.BoolVar(&dryRun, "dry-run", false, "Report changes without writing files")
	flag.BoolVar(&verbose, "v", false, "Verbose: list every modified template")
	flag.Parse()

	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	fmt.Print(banner)

	if templatesDir == "" {
		gologger.Fatal().Msg("-t <templates-dir> is required")
	}

	st := stats{}
	err := filepath.Walk(templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			st.errorCount++
			return nil
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		// Only process templates in redirect-prone directories
		if !isRedirectProne(path, templatesDir) {
			return nil
		}
		st.totalTemplates++
		modified, err := processTemplate(path, dryRun)
		if err != nil {
			st.errorCount++
			if verbose {
				gologger.Warning().Msgf("error %s: %v", path, err)
			}
			return nil
		}
		if modified {
			st.modifiedCount++
			if verbose {
				verb := "would modify"
				if !dryRun {
					verb = "modified"
				}
				gologger.Info().Msgf("%s: %s", verb, path)
			}
		}
		return nil
	})
	if err != nil {
		gologger.Fatal().Msgf("walk error: %v", err)
	}

	verb := "modified"
	if dryRun {
		verb = "would modify"
	}
	gologger.Info().Msgf("done: scanned=%d %s=%d errors=%d",
		st.totalTemplates, verb, st.modifiedCount, st.errorCount)
}
