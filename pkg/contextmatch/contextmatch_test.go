package contextmatch

import (
	"strings"
	"testing"
)

func TestMatchJSONPath(t *testing.T) {
	json := `{"user":{"name":"admin","role":"superuser"},"data":[{"id":1,"title":"secret"}]}`

	tests := []struct {
		name     string
		pattern  string
		word     string
		expected bool
	}{
		{"match user.name", "$.user.name", "admin", true},
		{"no match user.name", "$.user.name", "root", false},
		{"match user.role", "$.user.role", "superuser", true},
		{"match array[0].title", "$.data[0].title", "secret", true},
		{"no match array[0].id", "$.data[0].id", "secret", false},
		{"missing path", "$.nonexistent", "admin", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := ContextMatcher{
				Type:    ContextJSONPath,
				Pattern: tt.pattern,
				Word:    tt.word,
				Part:    "body",
			}
			if got := cm.Match(json, ""); got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMatchJSONPath_Negate(t *testing.T) {
	json := `{"user":{"name":"admin"}}`
	cm := ContextMatcher{
		Type:    ContextJSONPath,
		Pattern: "$.user.name",
		Word:    "root",
		Negate:  true,
		Part:    "body",
	}
	if !cm.Match(json, "") {
		t.Error("expected negation to match (word not found)")
	}
}

func TestMatchHTMLSelector(t *testing.T) {
	html := `<html><body>
		<div class="error">Access Denied</div>
		<div class="message">Welcome admin</div>
		<span id="status">success</span>
	</body></html>`

	tests := []struct {
		name     string
		selector string
		word     string
		expected bool
	}{
		{"match div.error", "div.error", "denied", true},
		{"no match div.error", "div.error", "welcome", false},
		{"match div.message", "div.message", "admin", true},
		{"match span#status", "span#status", "success", true},
		{"no match span#status", "span#status", "error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := ContextMatcher{
				Type:    ContextHTMLSelector,
				Pattern: tt.selector,
				Word:    tt.word,
				Part:    "body",
			}
			if got := cm.Match(html, ""); got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMatchRegexContext(t *testing.T) {
	content := `<div>Error: database connection failed</div><div>Status: OK</div>`

	cm := ContextMatcher{
		Type:    ContextRegex,
		Pattern: `Error:.*?</div>`,
		Word:    "database",
		Part:    "body",
	}
	if !cm.Match(content, "") {
		t.Error("expected regex context match")
	}

	// Word not in regex-matched text
	cm.Word = "Status"
	if cm.Match(content, "") {
		t.Error("expected no match (word outside regex context)")
	}
}

func TestMatchHeader(t *testing.T) {
	cm := ContextMatcher{
		Type:    ContextRegex,
		Pattern: `X-Powered-By:.*`,
		Word:    "express",
		Part:    "header",
	}
	header := "HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\nContent-Type: text/html\r\n"
	if !cm.Match("", header) {
		t.Error("expected header match")
	}
}

func TestMatchNonJSON(t *testing.T) {
	cm := ContextMatcher{
		Type:    ContextJSONPath,
		Pattern: "$.user.name",
		Word:    "admin",
		Part:    "body",
	}
	if cm.Match("not json at all", "") {
		t.Error("expected no match on non-JSON content")
	}
}

func TestParseContextType(t *testing.T) {
	tests := []struct {
		input    string
		expected ContextType
	}{
		{"jsonpath", ContextJSONPath},
		{"json", ContextJSONPath},
		{"html", ContextHTMLSelector},
		{"css", ContextHTMLSelector},
		{"regex", ContextRegex},
		{"rx", ContextRegex},
		{"unknown", ContextRegex},
	}
	for _, tt := range tests {
		if got := ParseContextType(tt.input); got != tt.expected {
			t.Errorf("ParseContextType(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestSplitJSONPath(t *testing.T) {
	tests := []struct {
		path     string
		expected []string
	}{
		{"user.name", []string{"user", "name"}},
		{"data[0].title", []string{"data[0]", "title"}},
		{"$.user.name", []string{"user", "name"}},
	}
	for _, tt := range tests {
		got := splitJSONPath(tt.path)
		if len(got) != len(tt.expected) {
			t.Errorf("splitJSONPath(%q) = %v, want %v", tt.path, got, tt.expected)
			continue
		}
		for i := range got {
			if !strings.EqualFold(got[i], tt.expected[i]) {
				t.Errorf("splitJSONPath(%q)[%d] = %q, want %q", tt.path, i, got[i], tt.expected[i])
			}
		}
	}
}
