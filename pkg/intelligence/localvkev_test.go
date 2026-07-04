package intelligence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractCVEFromTemplate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no CVE-YYYY-NNNN in tags",
			input:    "tags: cve,cve2024,php,cgi,rce,kev,vkev,vuln",
			expected: "",
		},
		{
			name:     "CVE in ID field",
			input:    "id: CVE-2023-7091",
			expected: "CVE-2023-7091",
		},
		{
			name:     "CVE in description",
			input:    "description: Exploit for CVE-2024-4577 in PHP-CGI",
			expected: "CVE-2024-4577",
		},
		{
			name:     "no CVE present",
			input:    "tags: tech,nginx,discovery",
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCVEFromTemplate(tt.input)
			if got != tt.expected {
				t.Errorf("extractCVEFromTemplate() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExtractTags(t *testing.T) {
	content := `id: test-template
info:
  name: Test
  tags: cve,cve2024,php,rce,vkev,vuln
  severity: high
`
	tags := extractTags(content)
	if len(tags) != 6 {
		t.Fatalf("expected 6 tags, got %d: %v", len(tags), tags)
	}
	if tags[0] != "cve" {
		t.Errorf("expected first tag 'cve', got '%s'", tags[0])
	}
	if tags[4] != "vkev" {
		t.Errorf("expected 5th tag 'vkev', got '%s'", tags[4])
	}
}

func TestExtractField(t *testing.T) {
	content := `id: test
info:
  name: Test Template
  severity: critical
  description: A test
`
	if got := extractField(content, "severity"); got != "critical" {
		t.Errorf("expected severity 'critical', got '%s'", got)
	}
}

func TestLocalVKEVIndex_BuildAndQuery(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test templates with vkev tag
	templates := map[string]string{
		"http/cves/2024/CVE-2024-4577.yaml": `id: CVE-2024-4577
info:
  name: PHP-CGI RCE
  tags: cve,cve2024,php,cgi,rce,kev,vkev,vuln
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
`,
		"http/cves/2023/CVE-2023-7091.yaml": `id: CVE-2023-7091
info:
  name: Zimbra LFI
  tags: cve2013,cve,packetstorm,zimbra,lfi,edb,synacor,vkev,vuln
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
`,
		"http/technologies/tech-detect.yaml": `id: tech-detect
info:
  name: Tech Detect
  tags: tech,discovery
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`,
	}

	for path, content := range templates {
		fullPath := filepath.Join(tmpDir, path)
		os.MkdirAll(filepath.Dir(fullPath), 0755)
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Build index
	idx, err := BuildLocalVKEVIndex(tmpDir)
	if err != nil {
		t.Fatalf("BuildLocalVKEVIndex: %v", err)
	}

	if idx.Count() != 2 {
		t.Errorf("expected 2 VKEV CVEs, got %d", idx.Count())
	}

	// Query specific CVE
	if !idx.IsVulnCheckKEV("CVE-2024-4577") {
		t.Error("expected CVE-2024-4577 to be in VKEV index")
	}
	if !idx.IsVulnCheckKEV("cve-2023-7091") {
		t.Error("expected case-insensitive lookup for CVE-2023-7091")
	}
	if idx.IsVulnCheckKEV("CVE-9999-9999") {
		t.Error("CVE-9999-9999 should NOT be in VKEV index")
	}

	// Get entry
	entry, found := idx.GetEntry("CVE-2024-4577")
	if !found {
		t.Fatal("expected to find entry for CVE-2024-4577")
	}
	if len(entry.TemplatePaths) != 1 {
		t.Errorf("expected 1 template path, got %d", len(entry.TemplatePaths))
	}
	if entry.Severity != "critical" {
		t.Errorf("expected severity 'critical', got '%s'", entry.Severity)
	}

	// Verify tech-detect (non-vkev) was NOT indexed
	ids := idx.GetCVEIDs()
	if len(ids) != 2 {
		t.Errorf("expected 2 CVE IDs, got %d", len(ids))
	}
}

func TestLocalVKEVIndex_SaveLoad(t *testing.T) {
	tmpDir := t.TempDir()

	idx := NewLocalVKEVIndex()
	idx.CVEs["CVE-2024-4577"] = &LocalVKEVEntry{
		CVEID:         "CVE-2024-4577",
		TemplatePaths: []string{"/path/to/template.yaml"},
		Tags:          []string{"vkev", "cve"},
		Severity:      "critical",
	}
	idx.CVEs["CVE-2023-7091"] = &LocalVKEVEntry{
		CVEID:         "CVE-2023-7091",
		TemplatePaths: []string{"/path/to/other.yaml"},
		Tags:          []string{"vkev", "cve"},
		Severity:      "high",
	}

	savePath := filepath.Join(tmpDir, "vkev-index.json")
	if err := idx.Save(savePath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadLocalVKEVIndex(savePath)
	if err != nil {
		t.Fatalf("LoadLocalVKEVIndex: %v", err)
	}

	if loaded.Count() != 2 {
		t.Errorf("expected 2 CVEs after load, got %d", loaded.Count())
	}
	if !loaded.IsVulnCheckKEV("CVE-2024-4577") {
		t.Error("CVE-2024-4577 should be in loaded index")
	}

	entry, _ := loaded.GetEntry("CVE-2024-4577")
	if entry.Severity != "critical" {
		t.Errorf("expected severity 'critical', got '%s'", entry.Severity)
	}
}

func TestLocalVKEVIndex_MergeWithAPI(t *testing.T) {
	idx := NewLocalVKEVIndex()
	idx.CVEs["CVE-2024-4577"] = &LocalVKEVEntry{
		CVEID: "CVE-2024-4577",
		Tags:  []string{"vkev"},
	}

	// Simulate API catalog with 1 existing + 1 new CVE
	catalog := &VulnCheckKEVCatalog{
		Data: []VulnCheckKEVEntry{
			{
				CVE:          []string{"CVE-2024-4577"}, // already in index
				Product:      "PHP",
				VendorProject: "PHP Group",
			},
			{
				CVE:          []string{"CVE-2024-9999"}, // new
				Product:      "Apache",
				VendorProject: "Apache",
			},
		},
	}

	added := idx.MergeWithAPI(catalog)
	if added != 1 {
		t.Errorf("expected 1 new entry added, got %d", added)
	}
	if idx.Count() != 2 {
		t.Errorf("expected 2 total CVEs after merge, got %d", idx.Count())
	}
	if !idx.IsVulnCheckKEV("CVE-2024-9999") {
		t.Error("CVE-2024-9999 should be in index after merge")
	}
}

func TestBuildLocalVKEVIndex_RealTemplates(t *testing.T) {
	templatesDir := os.ExpandEnv("$HOME/.local/nuclei-templates-dev")
	if _, err := os.Stat(templatesDir); err != nil {
		t.Skipf("templates dir not found: %s", templatesDir)
	}

	idx, err := BuildLocalVKEVIndex(templatesDir)
	if err != nil {
		t.Fatalf("BuildLocalVKEVIndex: %v", err)
	}

	if idx.Count() == 0 {
		t.Fatal("expected non-zero VKEV CVE count from real templates")
	}

	t.Logf("Local VKEV index: %d unique CVEs from vkev-tagged templates", idx.Count())

	// Verify a few known VKEV CVEs
	knownVKEV := []string{"CVE-2024-4577"}
	for _, cve := range knownVKEV {
		if !idx.IsVulnCheckKEV(cve) {
			t.Errorf("expected %s to be in VKEV index", cve)
		}
	}
}
