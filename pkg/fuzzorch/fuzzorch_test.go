package fuzzorch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPayloadLibrary_Defaults(t *testing.T) {
	lib := NewPayloadLibrary()
	if lib.GetPayloads("sqli") == nil {
		t.Error("expected sqli payloads")
	}
	if lib.GetPayloads("xss") == nil {
		t.Error("expected xss payloads")
	}
	if lib.GetPayloads("ssrf") == nil {
		t.Error("expected ssrf payloads")
	}
	if lib.GetPayloads("lfi") == nil {
		t.Error("expected lfi payloads")
	}
	if lib.GetPayloads("rce") == nil {
		t.Error("expected rce payloads")
	}
	if lib.GetPayloads("redirect") == nil {
		t.Error("expected redirect payloads")
	}
	if lib.GetPayloads("xxe") == nil {
		t.Error("expected xxe payloads")
	}
}

func TestPayloadLibrary_GetNonexistent(t *testing.T) {
	lib := NewPayloadLibrary()
	if lib.GetPayloads("nonexistent") != nil {
		t.Error("expected nil for nonexistent vuln type")
	}
}

func TestPayloadLibrary_AddCustom(t *testing.T) {
	lib := NewPayloadLibrary()
	lib.AddPayloadSet(&FuzzPayloadSet{
		Name:     "Custom",
		VulnType: "custom-vuln",
		Payloads: []string{"payload1", "payload2"},
	})
	ps := lib.GetPayloads("custom-vuln")
	if ps == nil {
		t.Fatal("expected custom payloads")
	}
	if len(ps.Payloads) != 2 {
		t.Errorf("expected 2 payloads, got %d", len(ps.Payloads))
	}
}

func TestPayloadLibrary_SelectPayloadTypes_Default(t *testing.T) {
	lib := NewPayloadLibrary()
	selected := lib.SelectPayloadTypes([]string{})
	if !contains(selected, "sqli") {
		t.Error("expected sqli in default selection")
	}
	if !contains(selected, "xss") {
		t.Error("expected xss in default selection")
	}
	if !contains(selected, "lfi") {
		t.Error("expected lfi in default selection")
	}
}

func TestPayloadLibrary_SelectPayloadTypes_PHP(t *testing.T) {
	lib := NewPayloadLibrary()
	selected := lib.SelectPayloadTypes([]string{"PHP", "MySQL"})
	if !contains(selected, "sqli-mysql") {
		t.Error("expected sqli-mysql for PHP+MySQL")
	}
}

func TestPayloadLibrary_SelectPayloadTypes_Java(t *testing.T) {
	lib := NewPayloadLibrary()
	selected := lib.SelectPayloadTypes([]string{"Java", "Spring"})
	if !contains(selected, "ssrf") {
		t.Error("expected ssrf for Java/Spring")
	}
	if !contains(selected, "rce") {
		t.Error("expected rce for Java/Spring")
	}
}

func TestPayloadLibrary_SelectPayloadTypes_Node(t *testing.T) {
	lib := NewPayloadLibrary()
	selected := lib.SelectPayloadTypes([]string{"Node.js", "Express"})
	if !contains(selected, "ssrf") {
		t.Error("expected ssrf for Node.js")
	}
}

func TestTargetFromURL_WithParams(t *testing.T) {
	target := TargetFromURL("http://example.com/search?q=test&page=1")
	if target.URL != "http://example.com/search?q=test&page=1" {
		t.Errorf("unexpected URL: %s", target.URL)
	}
	if len(target.Params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(target.Params))
	}
	if target.Params[0].Name != "q" {
		t.Errorf("expected first param 'q', got '%s'", target.Params[0].Name)
	}
	if target.Params[1].Name != "page" {
		t.Errorf("expected second param 'page', got '%s'", target.Params[1].Name)
	}
}

func TestTargetFromURL_NoParams(t *testing.T) {
	target := TargetFromURL("http://example.com/")
	if len(target.Params) != 1 {
		t.Fatalf("expected 1 default param, got %d", len(target.Params))
	}
	if target.Params[0].Name != "q" {
		t.Errorf("expected default param 'q', got '%s'", target.Params[0].Name)
	}
}

func TestTargetsFromForms(t *testing.T) {
	forms := []FormInfo{
		{
			Action: "http://example.com/login",
			Method: "POST",
			Inputs: []FormField{
				{Name: "username", Type: "text"},
				{Name: "password", Type: "password"},
			},
		},
		{
			Action: "http://example.com/search",
			Method: "GET",
			Inputs: []FormField{
				{Name: "q", Type: "text"},
			},
		},
	}

	targets := TargetsFromForms("http://example.com", forms)
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if targets[0].Method != "POST" {
		t.Errorf("expected POST, got %s", targets[0].Method)
	}
	if len(targets[0].Params) != 2 {
		t.Errorf("expected 2 params, got %d", len(targets[0].Params))
	}
	if targets[0].Params[0].Name != "username" {
		t.Errorf("expected 'username', got '%s'", targets[0].Params[0].Name)
	}
}

func TestTemplateGenerator_GenerateTemplates(t *testing.T) {
	tmpDir := t.TempDir()
	lib := NewPayloadLibrary()
	gen := NewTemplateGenerator(lib, tmpDir)

	targets := []FuzzTarget{
		{
			URL:    "http://example.com/search?q=test",
			Method: "GET",
			Params: []Param{
				{Name: "q", Position: "query", Type: "string", Value: "test"},
			},
		},
	}

	vulnTypes := []string{"sqli", "xss"}
	paths, err := gen.GenerateTemplates(targets, vulnTypes)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(paths))
	}

	// Verify template files exist and have content
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		content := string(data)
		if !strings.Contains(content, "id: fuzz-") {
			t.Errorf("expected template ID starting with 'fuzz-':\n%s", content)
		}
		if !strings.Contains(content, "fuzzing:") {
			t.Errorf("expected fuzzing block:\n%s", content)
		}
		if !strings.Contains(content, "matchers:") {
			t.Errorf("expected matchers block:\n%s", content)
		}
	}
}

func TestTemplateGenerator_SqliMatchers(t *testing.T) {
	tmpDir := t.TempDir()
	lib := NewPayloadLibrary()
	gen := NewTemplateGenerator(lib, tmpDir)

	targets := []FuzzTarget{
		{
			URL:    "http://example.com/?id=1",
			Method: "GET",
			Params: []Param{
				{Name: "id", Position: "query"},
			},
		},
	}

	paths, _ := gen.GenerateTemplates(targets, []string{"sqli"})
	if len(paths) == 0 {
		t.Fatal("expected at least 1 template")
	}

	data, _ := os.ReadFile(paths[0])
	if !strings.Contains(string(data), "SQL syntax") {
		t.Error("expected SQL syntax matcher")
	}
}

func TestTemplateGenerator_XssMatchers(t *testing.T) {
	tmpDir := t.TempDir()
	lib := NewPayloadLibrary()
	gen := NewTemplateGenerator(lib, tmpDir)

	targets := []FuzzTarget{
		{
			URL:    "http://example.com/?q=test",
			Method: "GET",
			Params: []Param{{Name: "q", Position: "query"}},
		},
	}

	paths, _ := gen.GenerateTemplates(targets, []string{"xss"})
	if len(paths) == 0 {
		t.Fatal("expected at least 1 template")
	}

	data, _ := os.ReadFile(paths[0])
	if !strings.Contains(string(data), "<script>alert(1)</script>") {
		t.Error("expected XSS matcher")
	}
}

func TestTemplateGenerator_LfiMatchers(t *testing.T) {
	tmpDir := t.TempDir()
	lib := NewPayloadLibrary()
	gen := NewTemplateGenerator(lib, tmpDir)

	targets := []FuzzTarget{
		{
			URL:    "http://example.com/?file=test",
			Method: "GET",
			Params: []Param{{Name: "file", Position: "query"}},
		},
	}

	paths, _ := gen.GenerateTemplates(targets, []string{"lfi"})
	if len(paths) == 0 {
		t.Fatal("expected at least 1 template")
	}

	data, _ := os.ReadFile(paths[0])
	if !strings.Contains(string(data), "root:x:0:0") {
		t.Error("expected /etc/passwd matcher")
	}
}

func TestTemplateGenerator_MultipleParams(t *testing.T) {
	tmpDir := t.TempDir()
	lib := NewPayloadLibrary()
	gen := NewTemplateGenerator(lib, tmpDir)

	targets := []FuzzTarget{
		{
			URL:    "http://example.com/search?q=test&page=1",
			Method: "GET",
			Params: []Param{
				{Name: "q", Position: "query"},
				{Name: "page", Position: "query"},
			},
		},
	}

	paths, _ := gen.GenerateTemplates(targets, []string{"sqli"})
	// 2 params * 1 vuln type = 2 templates
	if len(paths) != 2 {
		t.Fatalf("expected 2 templates (2 params * 1 vuln type), got %d", len(paths))
	}
}

func TestTemplateGenerator_NoMatchingPayloads(t *testing.T) {
	tmpDir := t.TempDir()
	lib := NewPayloadLibrary()
	gen := NewTemplateGenerator(lib, tmpDir)

	targets := []FuzzTarget{
		{
			URL:    "http://example.com/?q=test",
			Method: "GET",
			Params: []Param{{Name: "q"}},
		},
	}

	// "nonexistent" has no payloads
	paths, _ := gen.GenerateTemplates(targets, []string{"nonexistent"})
	if len(paths) != 0 {
		t.Errorf("expected 0 templates, got %d", len(paths))
	}
}

func TestFuzzStats(t *testing.T) {
	stats := NewFuzzStats()
	stats.TotalTargets = 5
	stats.TotalParams = 10
	stats.TotalRequests = 100
	stats.AddFinding("sqli")
	stats.AddFinding("sqli")
	stats.AddFinding("xss")
	stats.Duration = "5s"

	if stats.Findings != 3 {
		t.Errorf("expected 3 findings, got %d", stats.Findings)
	}
	if stats.ByVulnType["sqli"] != 2 {
		t.Errorf("expected 2 sqli, got %d", stats.ByVulnType["sqli"])
	}
	if stats.ByVulnType["xss"] != 1 {
		t.Errorf("expected 1 xss, got %d", stats.ByVulnType["xss"])
	}

	s := stats.String()
	if !strings.Contains(s, "Findings: 3") {
		t.Errorf("expected 'Findings: 3' in stats string: %s", s)
	}
}

func TestExtractVulnType(t *testing.T) {
	tests := []struct {
		templateID string
		expected   string
	}{
		{"fuzz-sqli-q-http---example-com", "sqli"},
		{"fuzz-xss-q-http---example-com", "xss"},
		{"fuzz-lfi-file-http---example-com", "lfi"},
		{"fuzz-sqli-mysql-id-http---example-com", "sqli"},
		{"not-a-fuzz-template", "unknown"},
	}

	for _, tt := range tests {
		got := extractVulnType(tt.templateID)
		if got != tt.expected {
			t.Errorf("extractVulnType(%s) = %s, expected %s", tt.templateID, got, tt.expected)
		}
	}
}

func TestParseFuzzFindings(t *testing.T) {
	jsonl := `{"template-id":"fuzz-sqli-q-http---example-com","host":"example.com","url":"http://example.com/?q=test","type":"http","severity":"high","matcher-name":"SQL syntax"}
{"template-id":"fuzz-xss-q-http---example-com","host":"example.com","url":"http://example.com/?q=test","type":"http","severity":"high","matcher-name":"<script>alert(1)</script>"}
`
	findings := parseFuzzFindings([]byte(jsonl))
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].VulnType != "sqli" {
		t.Errorf("expected sqli, got %s", findings[0].VulnType)
	}
	if findings[1].VulnType != "xss" {
		t.Errorf("expected xss, got %s", findings[1].VulnType)
	}
}

func TestParseFuzzFindings_Empty(t *testing.T) {
	findings := parseFuzzFindings([]byte(""))
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseFuzzFindings_InvalidJSON(t *testing.T) {
	jsonl := `{invalid json}
{"template-id":"fuzz-sqli-q","host":"example.com","url":"http://example.com"}
`
	findings := parseFuzzFindings([]byte(jsonl))
	if len(findings) != 1 {
		t.Fatalf("expected 1 valid finding, got %d", len(findings))
	}
}

func TestYamlEscape(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"simple", "simple"},
		{`has "quotes"`, `"has \"quotes\""`},
		{"has: colon", `"has: colon"`},
	}
	for _, tt := range tests {
		got := yamlEscape(tt.input)
		if !strings.Contains(got, tt.contains) {
			t.Errorf("yamlEscape(%s): expected to contain %s, got %s", tt.input, tt.contains, got)
		}
	}
}

func TestOrchestrator_New(t *testing.T) {
	tmpDir := t.TempDir()
	orch := NewOrchestrator("nuclei-dev", tmpDir, 5*time.Minute)
	if orch.nucleiBin != "nuclei-dev" {
		t.Errorf("expected nuclei-dev, got %s", orch.nucleiBin)
	}
	if orch.library == nil {
		t.Error("expected non-nil library")
	}
	if orch.generator == nil {
		t.Error("expected non-nil generator")
	}
}

func TestOrchestrator_GenerateOnly(t *testing.T) {
	tmpDir := t.TempDir()
	orch := NewOrchestrator("nuclei-dev", tmpDir, 5*time.Minute)

	targets := []FuzzTarget{
		TargetFromURL("http://example.com/?q=test&id=1"),
	}

	vulnTypes := orch.library.SelectPayloadTypes([]string{"PHP", "MySQL"})
	paths, err := orch.generator.GenerateTemplates(targets, vulnTypes)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("expected generated templates")
	}

	// Verify all files exist
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("template file does not exist: %s", p)
		}
	}

	// Check output directory contains templates
	entries, _ := os.ReadDir(tmpDir)
	yamlCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".yaml" {
			yamlCount++
		}
	}
	if yamlCount != len(paths) {
		t.Errorf("expected %d yaml files, got %d", len(paths), yamlCount)
	}
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
