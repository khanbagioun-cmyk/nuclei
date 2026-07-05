package matchers

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/contextmatch"
)

// ExtractContext narrows the corpus to only the content matching the given
// structural context (JSONPath, CSS selector, or regex). This allows word/regex
// matchers to focus on a specific section of the response, eliminating false
// positives from matches appearing in unrelated sections.
//
// The contextType parameter determines how the pattern is interpreted:
//   - "jsonpath": treats pattern as a JSONPath (e.g. "$.user.role")
//   - "html": treats pattern as a CSS selector (e.g. "div.error")
//   - "regex": treats pattern as a Go regex; returns captured group 1 if present
//   - "" (auto): infers type from pattern syntax
//
// If extraction fails, returns the original corpus unchanged (fail-open).
func ExtractContext(corpus, pattern, contextType string) string {
	if pattern == "" {
		return corpus
	}

	cm := &contextmatch.ContextMatcher{
		Pattern: pattern,
	}

	// Determine context type
	switch strings.ToLower(contextType) {
	case "jsonpath":
		cm.Type = contextmatch.ContextJSONPath
	case "html":
		cm.Type = contextmatch.ContextHTMLSelector
	case "regex":
		cm.Type = contextmatch.ContextRegex
	case "":
		cm.Type = inferContextType(pattern)
	default:
		cm.Type = contextmatch.ParseContextType(contextType)
	}

	extracted, ok := cm.Extract(corpus)
	if !ok || extracted == "" {
		return corpus
	}
	return extracted
}

// inferContextType guesses the context type from the pattern syntax.
//   - patterns starting with "$" → JSONPath
//   - patterns starting with "#" or "." or containing tag names → HTML selector
//   - everything else → regex
func inferContextType(pattern string) contextmatch.ContextType {
	if strings.HasPrefix(pattern, "$") {
		return contextmatch.ContextJSONPath
	}
	// Simple heuristic: if it looks like a CSS selector (starts with tag, ., #)
	if strings.HasPrefix(pattern, "#") || strings.HasPrefix(pattern, ".") {
		return contextmatch.ContextHTMLSelector
	}
	// Check if it's a plain tag name (lowercase letters only)
	isPlainTag := true
	for _, r := range pattern {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			isPlainTag = false
			break
		}
	}
	if isPlainTag && len(pattern) > 0 {
		return contextmatch.ContextHTMLSelector
	}
	return contextmatch.ContextRegex
}
