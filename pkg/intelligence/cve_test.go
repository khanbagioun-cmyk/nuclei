package intelligence

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestFetchSingleCVE(t *testing.T) {
	cve, err := FetchSingleCVE("CVE-2024-0012", "")
	if err != nil {
		t.Skipf("NVD API unavailable: %v", err)
	}
	if cve.ID != "CVE-2024-0012" {
		t.Errorf("expected CVE-2024-0012, got %s", cve.ID)
	}
	if cve.GetSeverity() != "critical" {
		t.Errorf("expected critical, got %s", cve.GetSeverity())
	}
	desc := cve.GetEnglishDescription()
	if !strings.Contains(strings.ToLower(desc), "authentication bypass") {
		t.Error("description should mention authentication bypass")
	}
	vendor, product := cve.GetVendorProduct()
	if vendor == "" || product == "" {
		t.Error("vendor and product should be extracted")
	}
	t.Logf("CVE-2024-0012: vendor=%s product=%s severity=%s score=%.1f",
		vendor, product, cve.GetSeverity(), cve.GetCVSSScore())
}

func TestSynthesizer_WordpressCVE(t *testing.T) {
	cve := &NVDCVE{
		ID: "CVE-2024-9999",
		Descriptions: []NVDDescription{
			{Lang: "en", Value: "A SQL injection vulnerability in WordPress plugin FooBar version 2.0 allows remote attackers to execute arbitrary SQL commands via the id parameter."},
		},
		Affected: []NVDAffected{
			{AffectedData: []NVDAffectedData{
				{Vendor: "WordPress", Product: "FooBar", CPEs: []string{"cpe:2.3:a:wordpress:foobar:2.0:*:*:*:*:*:*:*"}},
			}},
		},
		Metrics: NVDMetrics{
			CVSSv31: []CVSSv31{
				{CVSSData: CVSSData31{BaseScore: 9.8, BaseSeverity: "CRITICAL", VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			},
		},
		Weaknesses: []NVDWeakness{
			{Description: []NVDDescription{{Lang: "en", Value: "CWE-89"}}},
		},
		References: []NVDReference{
			{URL: "https://example.com/advisory"},
			{URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-9999"},
		},
	}

	synth := NewSynthesizer()
	tmpl, err := synth.Synthesize(cve)
	if err != nil {
		t.Fatalf("synthesize failed: %v", err)
	}

	if tmpl.CVEID != "CVE-2024-9999" {
		t.Errorf("expected CVE-2024-9999, got %s", tmpl.CVEID)
	}
	if tmpl.Severity != "critical" {
		t.Errorf("expected critical, got %s", tmpl.Severity)
	}
	if tmpl.CWE != "CWE-89" {
		t.Errorf("expected CWE-89, got %s", tmpl.CWE)
	}
	if len(tmpl.HTTPRequests) == 0 {
		t.Error("should have at least one HTTP request")
	}
	if len(tmpl.Matchers) == 0 {
		t.Error("should have at least one matcher")
	}
	if tmpl.Confidence < 0.3 {
		t.Error("confidence should be > 0.3")
	}
	t.Logf("template: %d requests, %d matchers, confidence=%.2f, tags=%v",
		len(tmpl.HTTPRequests), len(tmpl.Matchers), tmpl.Confidence, tmpl.Tags)
}

func TestSynthesizer_PathExtraction(t *testing.T) {
	cve := &NVDCVE{
		ID: "CVE-2024-5555",
		Descriptions: []NVDDescription{
			{Lang: "en", Value: "A path traversal vulnerability in FooCMS allows access to /etc/passwd via /admin/upload.php?file=../../../etc/passwd"},
		},
		Metrics: NVDMetrics{
			CVSSv31: []CVSSv31{
				{CVSSData: CVSSData31{BaseScore: 7.5, BaseSeverity: "HIGH", VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
			},
		},
	}

	synth := NewSynthesizer()
	tmpl, err := synth.Synthesize(cve)
	if err != nil {
		t.Fatalf("synthesize failed: %v", err)
	}

	if len(tmpl.HTTPRequests) == 0 {
		t.Error("should have HTTP requests from extracted paths")
	}
	found := false
	for _, req := range tmpl.HTTPRequests {
		if strings.Contains(req.Path, "upload.php") {
			found = true
			break
		}
	}
	if !found {
		t.Error("should have extracted upload.php path from description")
	}
}

func TestClassifyVulnType(t *testing.T) {
	tests := []struct {
		desc     string
		expected string
	}{
		{"A SQL injection vulnerability in the id parameter", "SQL Injection"},
		{"Cross-site scripting (XSS) in search results", "XSS"},
		{"Remote code execution via deserialization", "Remote Code Execution"},
		{"Authentication bypass in login endpoint", "Authentication Bypass"},
		{"Path traversal allows reading /etc/passwd", "Path Traversal"},
		{"SSRF vulnerability in webhook handler", "SSRF"},
		{"Information disclosure in API response", "Information Disclosure"},
		{"Privilege escalation via IDOR", "Privilege Escalation"},
		{"CSRF in password change form", "CSRF"},
		{"Unrestricted file upload allows webshell", "File Upload"},
		{"Java deserialization leading to RCE", "Remote Code Execution"},
		{"OS command injection in ping utility", "Command Injection"},
		{"XXE in XML parser", "XXE"},
		{"SSTI in template engine", "SSTI"},
		{"Open redirect in return URL", "Open Redirect"},
		{"Some unknown vulnerability type", "Vulnerability"},
	}

	for _, tt := range tests {
		got := classifyVulnType(tt.desc)
		if got != tt.expected {
			t.Errorf("classifyVulnType(%q) = %q, want %q", tt.desc, got, tt.expected)
		}
	}
}

func TestExtractPathsFromDesc(t *testing.T) {
	desc := "Vulnerability in /admin/login.php and /api/v2/users.json allows bypass"
	paths := extractPathsFromDesc(desc)
	if len(paths) < 2 {
		t.Errorf("expected at least 2 paths, got %d: %v", len(paths), paths)
	}
}

func TestExtractProductFromDesc(t *testing.T) {
	tests := []struct {
		desc     string
		expected string
	}{
		{"A vulnerability in WordPress software version 6.0", "WordPress"},
		{"Apache Tomcat version 9.0 has a bug", "Tomcat"},
		{"Drupal CMS module vulnerable to XSS", "Drupal"},
		{"some generic description", ""},
	}

	for _, tt := range tests {
		got := extractProductFromDesc(tt.desc)
		if got != tt.expected && tt.expected != "" {
			t.Errorf("extractProductFromDesc(%q) = %q, want %q", tt.desc, got, tt.expected)
		}
	}
}

func TestTemplateWriter_RenderYAML(t *testing.T) {
	tmpl := &SynthesizedTemplate{
		CVEID:       "CVE-2024-TEST",
		Name:        "Test Product - SQL Injection",
		Author:      "nuclei-cvesync",
		Severity:    "critical",
		Description: "A SQL injection vulnerability in Test Product",
		References:  []string{"https://example.com/ref1", "https://example.com/ref2"},
		CVSSMetrics: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:   9.8,
		CWE:         "CWE-89",
		Vendor:      "TestCorp",
		Product:     "TestProduct",
		Tags:        []string{"cve", "cve2024", "testproduct", "vuln"},
		HTTPRequests: []HTTPRequestSpec{
			{Method: "GET", Path: "/admin/login.php"},
		},
		Matchers: []MatcherSpec{
			{Type: "status", Status: []int{200}, Condition: "and"},
			{Type: "word", Part: "body", Words: []string{"SQL syntax"}, Condition: "or"},
		},
		Confidence:       0.85,
		GenerationMethod: "heuristic",
	}

	writer := NewTemplateWriter(t.TempDir())
	yaml := writer.RenderYAML(tmpl)

	if !strings.Contains(yaml, "id: CVE-2024-TEST") {
		t.Error("YAML should contain template ID")
	}
	if !strings.Contains(yaml, "severity: critical") {
		t.Error("YAML should contain severity")
	}
	if !strings.Contains(yaml, "cvss-score: 9.8") {
		t.Error("YAML should contain CVSS score")
	}
	if !strings.Contains(yaml, "cwe-id: CWE-89") {
		t.Error("YAML should contain CWE")
	}
	if !strings.Contains(yaml, "GET /admin/login.php") {
		t.Error("YAML should contain HTTP request path")
	}
	if !strings.Contains(yaml, "type: status") {
		t.Error("YAML should contain status matcher")
	}
	if !strings.Contains(yaml, "type: word") {
		t.Error("YAML should contain word matcher")
	}
	if !strings.Contains(yaml, "tags: cve,cve2024") {
		t.Error("YAML should contain tags")
	}
}

func TestTemplateWriter_WriteFile(t *testing.T) {
	tmpl := &SynthesizedTemplate{
		CVEID:       "CVE-2024-1234",
		Name:        "Test - Vulnerability",
		Author:      "nuclei-cvesync",
		Severity:    "high",
		Description: "Test vulnerability",
		Tags:        []string{"cve", "cve2024"},
		HTTPRequests: []HTTPRequestSpec{
			{Method: "GET", Path: "/"},
		},
		Matchers: []MatcherSpec{
			{Type: "status", Status: []int{200}, Condition: "and"},
		},
		Confidence: 0.5,
	}

	writer := NewTemplateWriter(t.TempDir())
	path, err := writer.Write(tmpl)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if !strings.Contains(path, "http/cves/2024/CVE-2024-1234.yaml") {
		t.Errorf("unexpected path: %s", path)
	}

	yaml, err := readFileContent(path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !strings.Contains(yaml, "id: CVE-2024-1234") {
		t.Error("file should contain template ID")
	}
}

func TestSynthesizer_AssessConfidence(t *testing.T) {
	synth := NewSynthesizer()

	tmpl := &SynthesizedTemplate{
		CVEID:      "CVE-2024-0001",
		Product:    "wordpress",
		CVSSScore:  9.8,
		Tags:       []string{"cve", "kev"},
		References: []string{"ref1", "ref2", "ref3"},
		HTTPRequests: []HTTPRequestSpec{{Path: "/wp-login.php"}},
		Matchers:   []MatcherSpec{{Type: "status", Status: []int{200}}},
	}
	confidence := synth.assessConfidence(tmpl)
	if confidence < 0.7 {
		t.Errorf("expected confidence > 0.7 for well-specified CVE, got %.2f", confidence)
	}

	tmpl2 := &SynthesizedTemplate{
		CVEID: "CVE-2024-0002",
		Tags:  []string{"cve"},
	}
	confidence2 := synth.assessConfidence(tmpl2)
	if confidence2 > 0.5 {
		t.Errorf("expected confidence < 0.5 for sparse CVE, got %.2f", confidence2)
	}
}

func TestNVDCVE_GetVendorProduct(t *testing.T) {
	cve := &NVDCVE{
		Affected: []NVDAffected{
			{AffectedData: []NVDAffectedData{
				{Vendor: "Apache", Product: "Tomcat"},
			}},
		},
	}
	vendor, product := cve.GetVendorProduct()
	if vendor != "Apache" || product != "Tomcat" {
		t.Errorf("expected Apache/Tomcat, got %s/%s", vendor, product)
	}
}

func TestNVDCVE_IsCISAKEV(t *testing.T) {
	cve := &NVDCVE{CISAExploitAdd: "2024-01-15"}
	if !cve.IsCISAKEV() {
		t.Error("should be CISA KEV")
	}

	cve2 := &NVDCVE{}
	if cve2.IsCISAKEV() {
		t.Error("should not be CISA KEV")
	}
}

func TestSynthesizer_KnownProductDetection(t *testing.T) {
	cve := &NVDCVE{
		ID: "CVE-2024-7777",
		Descriptions: []NVDDescription{
			{Lang: "en", Value: "Remote code execution in Apache Tomcat allows unauthenticated attackers to execute arbitrary code"},
		},
		Affected: []NVDAffected{
			{AffectedData: []NVDAffectedData{{Vendor: "Apache", Product: "Tomcat", CPEs: []string{"cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*"}}}},
		},
		Metrics: NVDMetrics{
			CVSSv31: []CVSSv31{
				{CVSSData: CVSSData31{BaseScore: 9.8, BaseSeverity: "CRITICAL", VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			},
		},
		Weaknesses: []NVDWeakness{
			{Description: []NVDDescription{{Lang: "en", Value: "CWE-94"}}},
		},
	}

	synth := NewSynthesizer()
	tmpl, err := synth.Synthesize(cve)
	if err != nil {
		t.Fatalf("synthesize failed: %v", err)
	}

	if tmpl.Product == "" {
		t.Error("product should be extracted")
	}
	if len(tmpl.HTTPRequests) == 0 {
		t.Error("should have HTTP requests for known product")
	}
	t.Logf("Tomcat CVE: %d HTTP requests, %d matchers, confidence=%.2f, tags=%v",
		len(tmpl.HTTPRequests), len(tmpl.Matchers), tmpl.Confidence, tmpl.Tags)
}

func TestFetchCVEsRecent(t *testing.T) {
	cfg := CVEFeedConfig{
		ResultsPerPage: 5,
		HTTPTimeout:    30 * time.Second,
		PubStartDate:   "2024-11-01T00:00:00.000",
		PubEndDate:     "2024-11-02T00:00:00.000",
	}

	cves, err := FetchCVEs(cfg)
	if err != nil {
		t.Skipf("NVD API unavailable: %v", err)
	}
	if len(cves) == 0 {
		t.Skip("no CVEs returned (API may be rate-limited)")
	}
	t.Logf("fetched %d CVEs", len(cves))
}

func readFileContent(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
