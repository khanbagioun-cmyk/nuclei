package fuzzorch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TemplateGenerator generates nuclei fuzzing templates from fuzz targets
type TemplateGenerator struct {
	library    *PayloadLibrary
	outputDir  string
}

// NewTemplateGenerator creates a new template generator
func NewTemplateGenerator(library *PayloadLibrary, outputDir string) *TemplateGenerator {
	if outputDir == "" {
		outputDir = filepath.Join(os.Getenv("HOME"), ".config", "nuclei-dev", "fuzz-templates")
	}
	os.MkdirAll(outputDir, 0755)
	return &TemplateGenerator{
		library:   library,
		outputDir: outputDir,
	}
}

// GenerateTemplates creates nuclei fuzzing YAML templates for the given targets and vuln types.
// Returns the list of generated template file paths.
func (g *TemplateGenerator) GenerateTemplates(targets []FuzzTarget, vulnTypes []string) ([]string, error) {
	var templatePaths []string

	for _, target := range targets {
		for _, vt := range vulnTypes {
			ps := g.library.GetPayloads(vt)
			if ps == nil || len(ps.Payloads) == 0 {
				continue
			}
			for _, param := range target.Params {
				tmplPath := g.generateSingleTemplate(target, param, ps)
				if tmplPath != "" {
					templatePaths = append(templatePaths, tmplPath)
				}
			}
		}
	}

	return templatePaths, nil
}

// generateSingleTemplate creates a single nuclei fuzzing template
func (g *TemplateGenerator) generateSingleTemplate(target FuzzTarget, param Param, ps *FuzzPayloadSet) string {
	templateID := fmt.Sprintf("fuzz-%s-%s-%s", ps.VulnType, param.Name, strings.ReplaceAll(target.URL, "://", "_"))
	templateID = sanitizeFilename(templateID)
	// nuclei template IDs must be lowercase and contain only alphanumeric, hyphens
	templateID = strings.ToLower(templateID)
	templateID = strings.ReplaceAll(templateID, "/", "-")
	templateID = strings.ReplaceAll(templateID, ":", "-")
	templateID = strings.ReplaceAll(templateID, "?", "-")
	templateID = strings.ReplaceAll(templateID, "&", "-")
	templateID = strings.ReplaceAll(templateID, "=", "-")
	if len(templateID) > 80 {
		templateID = templateID[:80]
	}

	var yaml strings.Builder

	// Build the payloads section
	payloadsYaml := buildPayloadsYaml(ps.Payloads)

	// Build the fuzzing rule based on param position
	fuzzPart := param.Position
	if fuzzPart == "" {
		fuzzPart = "query"
	}

	// Determine matchers based on vuln type
	matchers := buildMatchers(ps.VulnType)

	yaml.WriteString(fmt.Sprintf(`id: %s
info:
  name: "Fuzz %s on %s parameter"
  author: fuzzorch
  severity: high
  tags: fuzzorch,%s
  description: "Auto-generated fuzzing template for %s parameter (%s)"
http:
  - method: %s
    path:
      - "{{BaseURL}}"
    fuzzing:
      - part: %s
        type: replace
        mode: single
        keys:
          - "%s"
        fuzz:
%s
    matchers-condition: and
    matchers:
%s
`,
		templateID,
		ps.VulnType, param.Name,
		ps.VulnType,
		param.Name, ps.VulnType,
		target.Method,
		fuzzPart,
		param.Name,
		payloadsYaml,
		matchers,
	))

	// Write the template file
	filePath := filepath.Join(g.outputDir, templateID+".yaml")
	if err := os.WriteFile(filePath, []byte(yaml.String()), 0644); err != nil {
		return ""
	}
	return filePath
}

// buildPathWithURL constructs the path for the template, including the base URL
func buildPathWithURL(baseURL string, param Param) string {
	// For query params, the URL already contains the endpoint
	// nuclei will replace the param value with the fuzz payload
	return baseURL
}

// buildPayloadsYaml builds the YAML list of payloads with proper indentation
func buildPayloadsYaml(payloads []string) string {
	var b strings.Builder
	for _, p := range payloads {
		// Escape special YAML characters
		escaped := yamlEscape(p)
		fmt.Fprintf(&b, "          - %s\n", escaped)
	}
	return b.String()
}

// buildMatchers creates matcher YAML for a given vuln type
func buildMatchers(vulnType string) string {
	var b strings.Builder
	indent := "      "

	switch strings.ToLower(vulnType) {
	case "sqli", "sqli-mysql":
		fmt.Fprintf(&b, "%s- type: word\n", indent)
		fmt.Fprintf(&b, "%s  part: body\n", indent)
		fmt.Fprintf(&b, "%s  words:\n", indent)
		fmt.Fprintf(&b, "%s    - \"SQL syntax\"\n", indent)
		fmt.Fprintf(&b, "%s    - \"mysql_fetch\"\n", indent)
		fmt.Fprintf(&b, "%s    - \"ORA-\"\n", indent)
		fmt.Fprintf(&b, "%s    - \"Microsoft OLE DB\"\n", indent)
		fmt.Fprintf(&b, "%s    - \"PostgreSQL\"\n", indent)
		fmt.Fprintf(&b, "%s  condition: or\n", indent)
	case "xss":
		fmt.Fprintf(&b, "%s- type: word\n", indent)
		fmt.Fprintf(&b, "%s  part: body\n", indent)
		fmt.Fprintf(&b, "%s  words:\n", indent)
		fmt.Fprintf(&b, "%s    - \"<script>alert(1)</script>\"\n", indent)
		fmt.Fprintf(&b, "%s    - \"onerror=alert(1)\"\n", indent)
		fmt.Fprintf(&b, "%s    - \"onload=alert(1)\"\n", indent)
		fmt.Fprintf(&b, "%s  condition: or\n", indent)
	case "ssrf":
		// SSRF typically requires OOB callback — use status + time as proxy
		fmt.Fprintf(&b, "%s- type: status\n", indent)
		fmt.Fprintf(&b, "%s  status:\n", indent)
		fmt.Fprintf(&b, "%s    - 200\n", indent)
	case "lfi":
		fmt.Fprintf(&b, "%s- type: word\n", indent)
		fmt.Fprintf(&b, "%s  part: body\n", indent)
		fmt.Fprintf(&b, "%s  words:\n", indent)
		fmt.Fprintf(&b, "%s    - \"root:x:0:0\"\n", indent)
		fmt.Fprintf(&b, "%s    - \"[extensions]\"\n", indent)
		fmt.Fprintf(&b, "%s    - \"[fonts]\"\n", indent)
		fmt.Fprintf(&b, "%s  condition: or\n", indent)
	case "rce":
		fmt.Fprintf(&b, "%s- type: word\n", indent)
		fmt.Fprintf(&b, "%s  part: body\n", indent)
		fmt.Fprintf(&b, "%s  words:\n", indent)
		fmt.Fprintf(&b, "%s    - \"uid=\"\n", indent)
		fmt.Fprintf(&b, "%s    - \"www-data\"\n", indent)
		fmt.Fprintf(&b, "%s    - \"root\"\n", indent)
		fmt.Fprintf(&b, "%s  condition: or\n", indent)
	case "redirect":
		fmt.Fprintf(&b, "%s- type: word\n", indent)
		fmt.Fprintf(&b, "%s  part: header\n", indent)
		fmt.Fprintf(&b, "%s  words:\n", indent)
		fmt.Fprintf(&b, "%s    - \"Location: https://evil.com\"\n", indent)
		fmt.Fprintf(&b, "%s    - \"Location: //evil.com\"\n", indent)
		fmt.Fprintf(&b, "%s  condition: or\n", indent)
	case "xxe":
		fmt.Fprintf(&b, "%s- type: word\n", indent)
		fmt.Fprintf(&b, "%s  part: body\n", indent)
		fmt.Fprintf(&b, "%s  words:\n", indent)
		fmt.Fprintf(&b, "%s    - \"root:x:0:0\"\n", indent)
		fmt.Fprintf(&b, "%s  condition: or\n", indent)
	default:
		fmt.Fprintf(&b, "%s- type: status\n", indent)
		fmt.Fprintf(&b, "%s  status:\n", indent)
		fmt.Fprintf(&b, "%s    - 200\n", indent)
	}

	return b.String()
}

// yamlEscape escapes a string for safe YAML usage
func yamlEscape(s string) string {
	// If the string contains special characters, quote it
	if strings.ContainsAny(s, ":{}[]&*#?|<>=!%@`\"'\\\n") {
		// Use double quotes and escape backslashes and quotes
		s = strings.ReplaceAll(s, "\\", "\\\\")
		s = strings.ReplaceAll(s, "\"", "\\\"")
		s = strings.ReplaceAll(s, "\n", "\\n")
		return "\"" + s + "\""
	}
	return s
}

// sanitizeFilename removes characters unsafe for filenames and template IDs
func sanitizeFilename(s string) string {
	replacer := strings.NewReplacer(
		" ", "-",
		"://", "-",
		":", "-",
		"?", "-",
		"&", "-",
		"=", "-",
		"/", "-",
		".", "-",
		"_", "-",
	)
	s = replacer.Replace(s)
	// Collapse consecutive dashes
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	// Trim leading/trailing dashes
	s = strings.Trim(s, "-")
	return s
}

// Orchestrator coordinates the full fuzzing workflow
type Orchestrator struct {
	library   *PayloadLibrary
	generator *TemplateGenerator
	nucleiBin string
	timeout   time.Duration
}

// NewOrchestrator creates a new fuzzing orchestrator
func NewOrchestrator(nucleiBin string, outputDir string, timeout time.Duration) *Orchestrator {
	lib := NewPayloadLibrary()
	if nucleiBin == "" {
		nucleiBin = "nuclei-dev"
	}
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	return &Orchestrator{
		library:   lib,
		generator: NewTemplateGenerator(lib, outputDir),
		nucleiBin: nucleiBin,
		timeout:   timeout,
	}
}

// GetLibrary returns the payload library
func (o *Orchestrator) GetLibrary() *PayloadLibrary {
	return o.library
}

// GetGenerator returns the template generator
func (o *Orchestrator) GetGenerator() *TemplateGenerator {
	return o.generator
}
