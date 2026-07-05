package jsextract

import (
	"fmt"
	"regexp"
	"strings"
)

// Endpoint represents an extracted API endpoint from JavaScript.
type Endpoint struct {
	Path       string
	Method     string
	Source     string // JS file URL or "inline"
	Params     []string
	HasSecrets bool
}

// Secret represents an extracted secret from JavaScript.
type Secret struct {
	Type   string // e.g., "api_key", "token", "aws_key"
	Value  string
	Source string
}

// ExtractionResult holds all extracted data from JS analysis.
type ExtractionResult struct {
	Endpoints []Endpoint
	Secrets   []Secret
	Params    []string // unique parameters across all endpoints
}

// Extractor parses JavaScript content for hidden endpoints, parameters, and secrets.
type Extractor struct {
	endpointPatterns []*regexp.Regexp
	secretPatterns   map[string]*regexp.Regexp
	paramPatterns    []*regexp.Regexp
}

// New creates a JS extractor with default patterns.
func New() *Extractor {
	return &Extractor{
		endpointPatterns: compileEndpointPatterns(),
		secretPatterns:   compileSecretPatterns(),
		paramPatterns:    compileParamPatterns(),
	}
}

// Extract parses JS content and returns endpoints, secrets, and parameters.
// baseURL is the URL of the JS file (or "inline" for embedded scripts).
func (e *Extractor) Extract(content, baseURL string) ExtractionResult {
	result := ExtractionResult{}

	// Extract endpoints
	seenPaths := make(map[string]bool)
	for _, pat := range e.endpointPatterns {
		matches := pat.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			// Determine which group is the path and which is the method
			// depends on the pattern. We use a heuristic: the longest
			// capture group that starts with / is the path.
			path := ""
			method := "GET"
			for i := 1; i < len(m); i++ {
				g := m[i]
				if strings.HasPrefix(g, "/") {
					path = g
				} else if len(g) <= 6 && g == strings.ToUpper(g) {
					method = g
				} else if strings.EqualFold(g, "get") || strings.EqualFold(g, "post") ||
					strings.EqualFold(g, "put") || strings.EqualFold(g, "delete") ||
					strings.EqualFold(g, "patch") {
					method = strings.ToUpper(g)
				}
			}
			if path == "" {
				continue
			}
			path = cleanPath(path)
			if path == "" || !isValidPath(path) {
				continue
			}
			if seenPaths[path] {
				continue
			}
			seenPaths[path] = true
			result.Endpoints = append(result.Endpoints, Endpoint{
				Path:   path,
				Method: method,
				Source: baseURL,
			})
		}
	}

	// Extract secrets
	for secretType, pat := range e.secretPatterns {
		matches := pat.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			value := strings.TrimSpace(m[1])
			if value == "" || len(value) < 8 {
				continue
			}
			result.Secrets = append(result.Secrets, Secret{
				Type:   secretType,
				Value:  value,
				Source: baseURL,
			})
			// Mark endpoints from this file as having secrets
			for i := range result.Endpoints {
				result.Endpoints[i].HasSecrets = true
			}
		}
	}

	// Extract parameters
	seenParams := make(map[string]bool)
	for _, pat := range e.paramPatterns {
		matches := pat.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			param := strings.TrimSpace(m[1])
			if param == "" || len(param) < 2 {
				continue
			}
			// Skip common false positives
			lower := strings.ToLower(param)
			if isFalseParam(lower) {
				continue
			}
			if !seenParams[param] {
				seenParams[param] = true
				result.Params = append(result.Params, param)
			}
		}
	}

	return result
}

// cleanPath normalizes an extracted path.
func cleanPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"'`)
	// Ensure starts with /
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// isValidPath checks if a path looks like a real API endpoint.
func isValidPath(p string) bool {
	// Too short
	if len(p) < 3 {
		return false
	}
	// Skip obvious false positives
	lower := strings.ToLower(p)
	bad := []string{".css", ".png", ".jpg", ".svg", ".woff", ".ico", ".gif"}
	for _, b := range bad {
		if strings.HasSuffix(lower, b) {
			return false
		}
	}
	// Must contain at least one path segment
	if !strings.Contains(p[1:], "/") && len(p) < 10 {
		// Short single-segment paths are often false positives
		return false
	}
	return true
}

// isFalseParam returns true for common false-positive parameter names.
func isFalseParam(p string) bool {
	bad := map[string]bool{
		"type": true, "name": true, "value": true, "data": true,
		"true": true, "false": true, "null": true, "undefined": true,
		"function": true, "return": true, "var": true, "let": true,
		"const": true, "class": true, "this": true, "self": true,
		"window": true, "document": true, "console": true,
	}
	return bad[p]
}

// compileEndpointPatterns returns regex patterns for extracting API endpoints from JS.
func compileEndpointPatterns() []*regexp.Regexp {
	patterns := []string{
		// fetch("/api/...") or fetch('/api/...', {method: "POST"})
		`fetch\(["']([^"']+)["'].*?(?:method:\s*["']([A-Z]+)["'])?`,
		// axios.get("/api/...") etc.
		`axios\.(get|post|put|delete|patch)\(["']([^"']+)["']`,
		// $.ajax({url: "/api/..."})
		`\$\.(?:ajax|get|post)\(["']([^"']+)["']`,
		// XMLHttpRequest.open("GET", "/api/...")
		`\.open\(["']([A-Z]+)["'],\s*["']([^"']+)["']`,
		// url: "/api/..."
		`url:\s*["']([^"']+)["']`,
		// href="/api/..."
		`href=["']([^"']+)["']`,
		// window.location = "/api/..."
		`location(?:\.href)?\s*=\s*["']([^"']+)["']`,
	}
	var compiled []*regexp.Regexp
	for _, p := range patterns {
		if r, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, r)
		}
	}
	return compiled
}

// compileSecretPatterns returns regex patterns for extracting secrets from JS.
func compileSecretPatterns() map[string]*regexp.Regexp {
	patterns := map[string]string{
		"api_key":        `(?i)api[_-]?key["'\s:=]+["']([a-zA-Z0-9_\-]{16,})["']`,
		"auth_token":     `(?i)(?:auth|bearer|access[_-]?token)["'\s:=]+["']([a-zA-Z0-9_\-.]{16,})["']`,
		"aws_access_key": `(AKIA[A-Z0-9]{16})`,
		"aws_secret":     `(?i)aws[_-]?secret[_-]?access[_-]?key["'\s:=]+["']([a-zA-Z0-9/+=]{40})["']`,
		"private_key":    `(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)`,
		"jwt":            `(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})`,
		"slack_token":    `xox[baprs]-[a-zA-Z0-9-]{10,}`,
		"google_api":     `AIza[0-9A-Za-z\-_]{35}`,
		"stripe_key":     `sk_(?:live|test)_[a-zA-Z0-9]{24,}`,
		"github_token":   `gh[pousr]_[A-Za-z0-9]{36}`,
	}
	compiled := make(map[string]*regexp.Regexp)
	for name, p := range patterns {
		if r, err := regexp.Compile(p); err == nil {
			compiled[name] = r
		}
	}
	return compiled
}

// compileParamPatterns returns regex patterns for extracting parameter names from JS.
func compileParamPatterns() []*regexp.Regexp {
	patterns := []string{
		// {param: value}
		`["']([a-z_][a-z0-9_]{2,})["']\s*:`,
		// unquoted object key: {param: value}
		`\{([a-z_][a-z0-9_]{2,})\s*:`,
		// .param=value or param=value in URL query strings
		`[?&]([a-z_][a-z0-9_]{2,})=`,
	}
	var compiled []*regexp.Regexp
	for _, p := range patterns {
		if r, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, r)
		}
	}
	return compiled
}

// Summary returns a human-readable extraction summary.
func (r ExtractionResult) Summary() string {
	return fmt.Sprintf("JS extraction: %d endpoints, %d secrets, %d params",
		len(r.Endpoints), len(r.Secrets), len(r.Params))
}
