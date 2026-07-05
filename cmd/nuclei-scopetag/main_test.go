package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestScopeDecision(t *testing.T) {
	tests := []struct {
		name     string
		words    []string
		expected bool
	}{
		{"high-risk word", []string{"admin", "cisco", "config"}, true},
		{"high-risk word alone", []string{"login"}, true},
		{"generic word small list", []string{"server", "config"}, true},
		{"generic word large list not flagged", []string{"server", "config", "foo", "bar"}, false},
		{"CVE-specific words", []string{"DB_NAME", "DB_PASSWORD", "DB_HOST"}, false},
		{"empty list", []string{}, false},
		{"case insensitive", []string{"LOGIN"}, true},
		{"mixed case high-risk", []string{"Welcome", "admin"}, true},
		{"generic large list skipped", []string{"home", "default", "test", "example"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scopeDecision(tt.words)
			if got != tt.expected {
				t.Errorf("scopeDecision(%v) = %v, want %v", tt.words, got, tt.expected)
			}
		})
	}
}

func TestIsRedirectProne(t *testing.T) {
	root := "/templates"
	tests := []struct {
		path     string
		expected bool
	}{
		{"/templates/http/cves/2020/CVE-2020-1234.yaml", true},
		{"/templates/http/vulnerabilities/apache/foo.yaml", true},
		{"/templates/http/misconfiguration/foo.yaml", true},
		{"/templates/http/exposures/foo.yaml", true},
		{"/templates/http/default-logins/foo.yaml", true},
		{"/templates/http/token-spray/foo.yaml", false},
		{"/templates/http/osint/foo.yaml", false},
		{"/templates/http/detections/foo.yaml", false},
		{"/templates/http/technologies/foo.yaml", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isRedirectProne(tt.path, root)
			if got != tt.expected {
				t.Errorf("isRedirectProne(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestProcessTemplate_DryRun(t *testing.T) {
	// Template with body word matcher containing "admin" (high-risk)
	tmpl := []byte(`id: test-1

info:
  name: Test
  author: test
  severity: high

http:
  - method: GET
    path:
      - '{{BaseURL}}/admin'
    matchers:
      - type: word
        part: body
        words:
          - "admin"
          - "panel"
        condition: and
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, tmpl, 0644); err != nil {
		t.Fatal(err)
	}

	modified, err := processTemplate(path, true)
	if err != nil {
		t.Fatalf("processTemplate error: %v", err)
	}
	if !modified {
		t.Error("expected template to be flagged for modification")
	}

	// Verify file was NOT modified (dry-run)
	data, _ := os.ReadFile(path)
	if string(data) != string(tmpl) {
		t.Error("dry-run should not modify file")
	}
}

func TestProcessTemplate_Write(t *testing.T) {
	tmpl := []byte(`id: test-2

info:
  name: Test
  author: test
  severity: high

http:
  - method: GET
    path:
      - '{{BaseURL}}/login'
    matchers:
      - type: word
        part: body
        words:
          - "login"
        condition: and
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, tmpl, 0644); err != nil {
		t.Fatal(err)
	}

	modified, err := processTemplate(path, false)
	if err != nil {
		t.Fatalf("processTemplate error: %v", err)
	}
	if !modified {
		t.Fatal("expected template to be modified")
	}

	// Verify file was modified and scope added
	data, _ := os.ReadFile(path)
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatalf("modified file failed to parse: %v", err)
	}
	if !containsScope(data) {
		t.Error("modified file does not contain scope: final-only")
	}
}

func TestProcessTemplate_SkipExistingScope(t *testing.T) {
	tmpl := []byte(`id: test-3

info:
  name: Test
  author: test
  severity: high

http:
  - method: GET
    path:
      - '{{BaseURL}}/admin'
    matchers:
      - type: word
        part: body
        words:
          - "admin"
        scope: final-only
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, tmpl, 0644); err != nil {
		t.Fatal(err)
	}

	modified, err := processTemplate(path, false)
	if err != nil {
		t.Fatalf("processTemplate error: %v", err)
	}
	if modified {
		t.Error("template with existing scope should not be modified")
	}
}

func TestProcessTemplate_SkipNonBody(t *testing.T) {
	tmpl := []byte(`id: test-4

info:
  name: Test
  author: test
  severity: high

http:
  - method: GET
    path:
      - '{{BaseURL}}/admin'
    matchers:
      - type: word
        part: header
        words:
          - "admin"
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, tmpl, 0644); err != nil {
		t.Fatal(err)
	}

	modified, err := processTemplate(path, false)
	if err != nil {
		t.Fatalf("processTemplate error: %v", err)
	}
	if !modified {
		t.Error("header-part matcher with generic word should be flagged")
	}
}

func TestProcessTemplate_SkipNonHTTP(t *testing.T) {
	tmpl := []byte(`id: test-5

info:
  name: Test
  author: test
  severity: high

dns:
  - name: '{{FQDN}}'
    type: A
    matchers:
      - type: word
        words:
          - "admin"
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, tmpl, 0644); err != nil {
		t.Fatal(err)
	}

	modified, err := processTemplate(path, false)
	if err != nil {
		t.Fatalf("processTemplate error: %v", err)
	}
	if modified {
		t.Error("DNS template should not be modified")
	}
}

// containsScope checks if the YAML data contains "scope: final-only".
func containsScope(data []byte) bool {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return false
	}
	return walkForScope(&root)
}

func walkForScope(n *yaml.Node) bool {
	if n == nil {
		return false
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "scope" && n.Content[i+1].Value == "final-only" {
				return true
			}
			if walkForScope(n.Content[i+1]) {
				return true
			}
		}
	}
	if n.Kind == yaml.SequenceNode || n.Kind == yaml.DocumentNode {
		for _, c := range n.Content {
			if walkForScope(c) {
				return true
			}
		}
	}
	return false
}
