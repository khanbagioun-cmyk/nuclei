package contextmatch

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// ContextMatcher matches content within a specific structural context
// (JSON path, HTML DOM path, or regex context) rather than anywhere in the response.
// This eliminates false positives where a word appears in an unrelated section.
type ContextMatcher struct {
	Type    ContextType
	Pattern string // JSONPath, CSS selector, or regex
	Word    string // word to match within the context
	Part    string // "body", "header", or "all"
	Negate  bool
}

// ContextType defines the matching context.
type ContextType int

const (
	ContextJSONPath ContextType = iota
	ContextHTMLSelector
	ContextRegex
)

// Match checks if the word exists within the specified context in the response.
func (cm *ContextMatcher) Match(responseBody, responseHeader string) bool {
	var content string
	switch strings.ToLower(cm.Part) {
	case "header":
		content = responseHeader
	case "all":
		content = responseHeader + "\n" + responseBody
	default:
		content = responseBody
	}

	switch cm.Type {
	case ContextJSONPath:
		return cm.matchJSONPath(content)
	case ContextHTMLSelector:
		return cm.matchHTMLSelector(content)
	case ContextRegex:
		return cm.matchRegexContext(content)
	}
	return false
}

// matchJSONPath checks if the word exists at the given JSON path.
// Supports dot notation: $.user.name, $.data[0].id
func (cm *ContextMatcher) matchJSONPath(content string) bool {
	var data interface{}
	if err := json.Unmarshal([]byte(content), &data); err != nil {
		return false
	}

	value := getJSONPath(data, cm.Pattern)
	if value == nil {
		return cm.Negate // negation: not found = match
	}

	strVal := fmt.Sprintf("%v", value)
	matched := strings.Contains(strings.ToLower(strVal), strings.ToLower(cm.Word))
	if cm.Negate {
		return !matched
	}
	return matched
}

// matchHTMLSelector checks if the word exists within elements matching the CSS selector.
// Uses a simplified selector parser (tag, .class, #id).
func (cm *ContextMatcher) matchHTMLSelector(content string) bool {
	doc, err := html.Parse(strings.NewReader(content))
	if err != nil {
		return false
	}

	matched := false
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && matchesSelector(n, cm.Pattern) {
			text := getTextContent(n)
			if strings.Contains(strings.ToLower(text), strings.ToLower(cm.Word)) {
				matched = true
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	if cm.Negate {
		return !matched
	}
	return matched
}

// matchRegexContext checks if the word exists within text matched by the regex.
func (cm *ContextMatcher) matchRegexContext(content string) bool {
	pat, err := regexp.Compile(cm.Pattern)
	if err != nil {
		return false
	}

	matches := pat.FindAllString(content, -1)
	matched := false
	for _, m := range matches {
		if strings.Contains(strings.ToLower(m), strings.ToLower(cm.Word)) {
			matched = true
			break
		}
	}

	if cm.Negate {
		return !matched
	}
	return matched
}

// getJSONPath navigates a JSON object using dot notation with array index support.
func getJSONPath(data interface{}, path string) interface{} {
	// Strip leading $.
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, "$")

	if path == "" {
		return data
	}

	parts := splitJSONPath(path)
	current := data

	for _, part := range parts {
		// Check for array index: field[0]
		arrayMatch := regexp.MustCompile(`^([^\[]+)\[(\d+)\]$`).FindStringSubmatch(part)
		if len(arrayMatch) == 3 {
			fieldName := arrayMatch[1]
			index := arrayMatch[2]

			obj, ok := current.(map[string]interface{})
			if !ok {
				return nil
			}
			arr, ok := obj[fieldName].([]interface{})
			if !ok {
				return nil
			}
			var idx int
			fmt.Sscanf(index, "%d", &idx)
			if idx < 0 || idx >= len(arr) {
				return nil
			}
			current = arr[idx]
			continue
		}

		// Direct array index: [0]
		if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
			arr, ok := current.([]interface{})
			if !ok {
				return nil
			}
			var idx int
			fmt.Sscanf(strings.Trim(part, "[]"), "%d", &idx)
			if idx < 0 || idx >= len(arr) {
				return nil
			}
			current = arr[idx]
			continue
		}

		// Regular field
		obj, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = obj[part]
	}

	return current
}

// splitJSONPath splits a JSON path into parts, handling dots and array indices.
func splitJSONPath(path string) []string {
	var parts []string
	current := ""
	inBracket := false

	for _, c := range path {
		switch c {
		case '.':
			if inBracket {
				current += string(c)
			} else if current != "" {
				parts = append(parts, current)
				current = ""
			}
		case '[':
			inBracket = true
			current += string(c)
		case ']':
			current += string(c)
			inBracket = false
		default:
			if c == '$' && current == "" {
				// skip leading $
				continue
			}
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// matchesSelector checks if an HTML node matches a simplified CSS selector.
// Supports: tag, .class, #id, tag.class, tag#id
func matchesSelector(n *html.Node, selector string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return false
	}

	// Parse selector into tag, class, id
	var selTag, selClass, selID string
	if strings.Contains(selector, ".") {
		parts := strings.SplitN(selector, ".", 2)
		selTag = parts[0]
		selClass = parts[1]
	} else if strings.Contains(selector, "#") {
		parts := strings.SplitN(selector, "#", 2)
		selTag = parts[0]
		selID = parts[1]
	} else {
		selTag = selector
	}

	// Check tag
	if selTag != "" && selTag != "*" && n.Data != selTag {
		return false
	}

	// Check class and id
	for _, attr := range n.Attr {
		if attr.Key == "class" && selClass != "" {
			classes := strings.Fields(attr.Val)
			for _, c := range classes {
				if c == selClass {
					return true
				}
			}
		}
		if attr.Key == "id" && selID != "" && attr.Val == selID {
			return true
		}
	}

	// If only tag was specified
	if selClass == "" && selID == "" && selTag != "" {
		return true
	}
	return false
}

// getTextContent extracts all text content from an HTML node and its children.
func getTextContent(n *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			sb.WriteString(node.Data)
			sb.WriteString(" ")
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return sb.String()
}

// Extract returns the sub-corpus text at the given context path/pattern.
// Unlike Match, it does not check for a specific word — it returns the
// full text content at the context location, which can then be passed
// to word/regex matchers for scoped matching.
//
// Returns (extractedText, true) if the context resolved to content,
// ("", false) if the context could not be resolved.
func (cm *ContextMatcher) Extract(content string) (string, bool) {
	switch cm.Type {
	case ContextJSONPath:
		return cm.extractJSONPath(content)
	case ContextHTMLSelector:
		return cm.extractHTMLSelector(content)
	case ContextRegex:
		return cm.extractRegexContext(content)
	}
	return content, false
}

// extractJSONPath returns the string value at the given JSON path.
func (cm *ContextMatcher) extractJSONPath(content string) (string, bool) {
	var data interface{}
	if err := json.Unmarshal([]byte(content), &data); err != nil {
		return "", false
	}
	value := getJSONPath(data, cm.Pattern)
	if value == nil {
		return "", false
	}
	return fmt.Sprintf("%v", value), true
}

// extractHTMLSelector returns concatenated text content of all elements
// matching the CSS selector.
func (cm *ContextMatcher) extractHTMLSelector(content string) (string, bool) {
	doc, err := html.Parse(strings.NewReader(content))
	if err != nil {
		return "", false
	}
	var sb strings.Builder
	found := false
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && matchesSelector(n, cm.Pattern) {
			sb.WriteString(getTextContent(n))
			sb.WriteString(" ")
			found = true
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return sb.String(), found
}

// extractRegexContext returns the text matched by the regex.
// If the regex has a capture group, returns group 1; otherwise returns full match.
func (cm *ContextMatcher) extractRegexContext(content string) (string, bool) {
	pat, err := regexp.Compile(cm.Pattern)
	if err != nil {
		return "", false
	}
	matches := pat.FindAllString(content, -1)
	if len(matches) == 0 {
		return "", false
	}
	return strings.Join(matches, " "), true
}

// ParseContextType converts a string to ContextType.
func ParseContextType(s string) ContextType {
	switch strings.ToLower(s) {
	case "jsonpath", "json":
		return ContextJSONPath
	case "html", "selector", "css":
		return ContextHTMLSelector
	case "regex", "rx":
		return ContextRegex
	default:
		return ContextRegex
	}
}
