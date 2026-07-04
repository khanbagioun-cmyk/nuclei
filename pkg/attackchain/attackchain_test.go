package attackchain

import (
	"strings"
	"testing"
)

func TestSeverityValue(t *testing.T) {
	tests := []struct {
		sev    string
		expect int
	}{
		{"info", 1}, {"low", 2}, {"medium", 3}, {"high", 4}, {"critical", 5},
		{"INFO", 1}, {"Critical", 5}, {"unknown", 0},
	}
	for _, tt := range tests {
		got := SeverityValue(tt.sev)
		if got != tt.expect {
			t.Errorf("SeverityValue(%q) = %d, want %d", tt.sev, got, tt.expect)
		}
	}
}

func TestMaxSeverity(t *testing.T) {
	if MaxSeverity("low", "high") != "high" {
		t.Error("expected high")
	}
	if MaxSeverity("critical", "medium") != "critical" {
		t.Error("expected critical")
	}
}

func TestFinding_HasTag(t *testing.T) {
	f := &Finding{Tags: []string{"sqli", "cve"}}
	if !f.HasTag("sqli") {
		t.Error("expected sqli tag")
	}
	if f.HasTag("xss") {
		t.Error("did not expect xss tag")
	}
}

func TestFinding_VulnTypeOr(t *testing.T) {
	f := &Finding{VulnType: "sqli"}
	if f.VulnTypeOr() != "sqli" {
		t.Error("expected sqli")
	}
	f2 := &Finding{Tags: []string{"xss"}}
	if f2.VulnTypeOr() != "xss" {
		t.Error("expected xss from tags")
	}
}

func TestInferVulnType(t *testing.T) {
	tests := []struct {
		tags    []string
		tmplID  string
		matcher string
		expect  string
	}{
		{[]string{"sqli"}, "", "", "sqli"},
		{[]string{"cross-site-scripting"}, "", "", "xss"},
		{[]string{}, "cve-2024-1234-rce", "", "rce"},
		{[]string{}, "", "ssrf-detected", "ssrf"},
		{[]string{"wordpress"}, "", "", "wordpress"},
		{[]string{}, "", "", "unknown"},
	}
	for _, tt := range tests {
		got := inferVulnType(tt.tags, tt.tmplID, tt.matcher)
		if got != tt.expect {
			t.Errorf("inferVulnType(%v, %q, %q) = %q, want %q", tt.tags, tt.tmplID, tt.matcher, got, tt.expect)
		}
	}
}

func TestParseJSONL(t *testing.T) {
	jsonl := `{"template-id":"tech-detect","info":{"name":"Tech Detect","severity":"info","tags":["tech","fingerprint"]},"type":"http","host":"example.com","matched-at":"http://example.com/","matcher-name":"apache"}
{"template-id":"CVE-2024-1234","info":{"name":"RCE in Apache","severity":"critical","tags":["cve","rce","apache"]},"type":"http","host":"example.com","matched-at":"http://example.com/admin","matcher-name":"rce"}
{"template-id":"exposure-backup","info":{"name":"Backup File","severity":"high","tags":["exposure","backup"]},"type":"http","host":"example.com","matched-at":"http://example.com/backup.zip","matcher-name":"backup-file"}`

	findings, err := ParseJSONL(strings.NewReader(jsonl))
	if err != nil {
		t.Fatalf("ParseJSONL error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// Check first finding
	if findings[0].TemplateID != "tech-detect" {
		t.Errorf("expected template-id tech-detect, got %s", findings[0].TemplateID)
	}
	if findings[0].VulnType != "fingerprint" {
		t.Errorf("expected vuln type fingerprint, got %s", findings[0].VulnType)
	}
	if findings[0].Host != "example.com" {
		t.Errorf("expected host example.com, got %s", findings[0].Host)
	}

	// Check second finding
	if findings[1].Severity != "critical" {
		t.Errorf("expected severity critical, got %s", findings[1].Severity)
	}
	if findings[1].VulnType != "rce" {
		t.Errorf("expected vuln type rce, got %s", findings[1].VulnType)
	}
}

func TestParseJSONL_EmptyInput(t *testing.T) {
	findings, err := ParseJSONL(strings.NewReader(""))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseJSONL_InvalidLines(t *testing.T) {
	jsonl := `{"template-id":"valid","info":{"severity":"info","tags":["xss"]},"host":"example.com"}
invalid json line
{"template-id":"valid2","info":{"severity":"high","tags":["sqli"]},"host":"example.com"}`
	findings, err := ParseJSONL(strings.NewReader(jsonl))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (skip invalid), got %d", len(findings))
	}
}

func TestAttackGraph_AddFinding(t *testing.T) {
	g := NewAttackGraph(nil)

	f1 := &Finding{
		TemplateID: "tech-detect",
		Host:       "example.com",
		Severity:   "info",
		Tags:       []string{"fingerprint"},
		VulnType:   "fingerprint",
	}
	f2 := &Finding{
		TemplateID: "CVE-2024-1234",
		Host:       "example.com",
		Severity:   "critical",
		Tags:       []string{"cve", "rce"},
		VulnType:   "rce",
	}

	g.AddFinding(f1)
	g.AddFinding(f2)

	if g.NodeCount() != 2 {
		t.Errorf("expected 2 nodes, got %d", g.NodeCount())
	}
	// fingerprint → cve/rce should create an edge (version-to-cve rule)
	if g.EdgeCount() == 0 {
		t.Error("expected at least 1 edge")
	}
}

func TestAttackGraph_SameHostFilter(t *testing.T) {
	g := NewAttackGraph(nil)

	f1 := &Finding{
		TemplateID: "tech-detect",
		Host:       "example.com",
		Severity:   "info",
		Tags:       []string{"fingerprint"},
		VulnType:   "fingerprint",
	}
	f2 := &Finding{
		TemplateID: "CVE-2024-1234",
		Host:       "other.com",
		Severity:   "critical",
		Tags:       []string{"cve", "rce"},
		VulnType:   "rce",
	}

	g.AddFinding(f1)
	g.AddFinding(f2)

	// version-to-cve rule requires same host
	if g.EdgeCount() != 0 {
		t.Errorf("expected 0 edges (different hosts), got %d", g.EdgeCount())
	}
}

func TestAttackGraph_MultipleFindings(t *testing.T) {
	g := NewAttackGraph(nil)

	findings := []*Finding{
		{TemplateID: "exposure-config", Host: "h.com", Severity: "medium", Tags: []string{"exposure", "config"}, VulnType: "exposure"},
		{TemplateID: "default-login", Host: "h.com", Severity: "high", Tags: []string{"default-login"}, VulnType: "default-login"},
		{TemplateID: "admin-panel", Host: "h.com", Severity: "info", Tags: []string{"panel", "admin"}, VulnType: "panel"},
	}
	g.AddFindings(findings)

	if g.NodeCount() != 3 {
		t.Errorf("expected 3 nodes, got %d", g.NodeCount())
	}
	// Should have edges: exposure→default-login (misconfig-to-access),
	//   default-login→panel (default-login-to-auth-access)
	if g.EdgeCount() < 2 {
		t.Errorf("expected at least 2 edges, got %d", g.EdgeCount())
	}
}

func TestChainFinder_FindAll(t *testing.T) {
	g := NewAttackGraph(nil)

	findings := []*Finding{
		{TemplateID: "exposure-config", Host: "h.com", Severity: "medium", Tags: []string{"exposure", "config"}, VulnType: "exposure"},
		{TemplateID: "default-login", Host: "h.com", Severity: "high", Tags: []string{"default-login"}, VulnType: "default-login"},
		{TemplateID: "admin-panel", Host: "h.com", Severity: "info", Tags: []string{"panel", "admin"}, VulnType: "panel"},
		{TemplateID: "CVE-2024-9999", Host: "h.com", Severity: "critical", Tags: []string{"cve", "rce"}, VulnType: "rce"},
	}
	g.AddFindings(findings)

	cf := NewChainFinder(g, 5, 0.0)
	chains := cf.FindAll()

	if len(chains) == 0 {
		t.Fatal("expected at least 1 chain")
	}

	// Check that the highest-scoring chain has critical severity
	top := chains[0]
	if top.FinalSeverity != "critical" {
		t.Errorf("expected top chain final severity critical, got %s", top.FinalSeverity)
	}
}

func TestChainFinder_MaxDepth(t *testing.T) {
	g := NewAttackGraph(nil)

	// Create a linear chain: exposure → default-login → panel → cve → rce
	findings := []*Finding{
		{TemplateID: "f1", Host: "h.com", Severity: "medium", Tags: []string{"exposure"}, VulnType: "exposure"},
		{TemplateID: "f2", Host: "h.com", Severity: "high", Tags: []string{"default-login"}, VulnType: "default-login"},
		{TemplateID: "f3", Host: "h.com", Severity: "info", Tags: []string{"panel"}, VulnType: "panel"},
		{TemplateID: "f4", Host: "h.com", Severity: "high", Tags: []string{"cve"}, VulnType: "cve"},
		{TemplateID: "f5", Host: "h.com", Severity: "critical", Tags: []string{"rce"}, VulnType: "rce"},
	}
	g.AddFindings(findings)

	// With maxDepth=2, chains should have at most 2 steps
	cf := NewChainFinder(g, 2, 0.0)
	chains := cf.FindAll()

	for _, c := range chains {
		if len(c.Steps) > 2 {
			t.Errorf("chain has %d steps, expected <= 2", len(c.Steps))
		}
	}
}

func TestChainFinder_CycleDetection(t *testing.T) {
	g := NewAttackGraph(nil)

	// Create findings that could form cycles
	f1 := &Finding{TemplateID: "f1", Host: "h.com", Severity: "medium", Tags: []string{"exposure"}, VulnType: "exposure"}
	f2 := &Finding{TemplateID: "f2", Host: "h.com", Severity: "high", Tags: []string{"default-login"}, VulnType: "default-login"}
	f3 := &Finding{TemplateID: "f3", Host: "h.com", Severity: "info", Tags: []string{"panel"}, VulnType: "panel"}

	g.AddFindings([]*Finding{f1, f2, f3})

	cf := NewChainFinder(g, 10, 0.0)
	chains := cf.FindAll()

	// Check no chain visits the same node twice
	for _, c := range chains {
		seen := make(map[string]bool)
		for _, f := range c.Findings {
			if seen[f.ID] {
				t.Errorf("chain visits node %s twice", f.ID)
			}
			seen[f.ID] = true
		}
	}
}

func TestChainFinder_MinConfidence(t *testing.T) {
	g := NewAttackGraph(nil)

	findings := []*Finding{
		{TemplateID: "f1", Host: "h.com", Severity: "medium", Tags: []string{"exposure"}, VulnType: "exposure"},
		{TemplateID: "f2", Host: "h.com", Severity: "high", Tags: []string{"default-login"}, VulnType: "default-login"},
	}
	g.AddFindings(findings)

	// minConf=1.0 should filter out edges with confidence < 1.0
	cf := NewChainFinder(g, 5, 1.0)
	chains := cf.FindAll()

	for _, c := range chains {
		if c.Confidence < 1.0 {
			t.Errorf("chain confidence %f < 1.0 min", c.Confidence)
		}
	}
}

func TestSummarize(t *testing.T) {
	// Build real chains with real findings
	f1 := &Finding{ID: "a", Severity: "critical"}
	f2 := &Finding{ID: "b", Severity: "critical"}
	f3 := &Finding{ID: "c", Severity: "high"}
	f4 := &Finding{ID: "d", Severity: "high"}
	f5 := &Finding{ID: "e", Severity: "medium"}
	f6 := &Finding{ID: "f", Severity: "medium"}

	chains := []*AttackChain{
		{FinalSeverity: "critical", RiskScore: 90, Steps: []*ChainEdge{{}, {}, {}}, Findings: []*Finding{f1, f2}},
		{FinalSeverity: "high", RiskScore: 70, Steps: []*ChainEdge{{}, {}}, Findings: []*Finding{f3, f4}},
		{FinalSeverity: "medium", RiskScore: 50, Steps: []*ChainEdge{{}}, Findings: []*Finding{f5, f6}},
	}

	s := Summarize(chains)
	if s.TotalChains != 3 {
		t.Errorf("expected 3 total chains, got %d", s.TotalChains)
	}
	if s.CriticalChains != 1 {
		t.Errorf("expected 1 critical chain, got %d", s.CriticalChains)
	}
	if s.HighChains != 1 {
		t.Errorf("expected 1 high chain, got %d", s.HighChains)
	}
	if s.MaxChainLength != 3 {
		t.Errorf("expected max length 3, got %d", s.MaxChainLength)
	}
	if s.UniqueFindings != 6 {
		t.Errorf("expected 6 unique findings, got %d", s.UniqueFindings)
	}
}

func TestChainsBySeverity(t *testing.T) {
	chains := []*AttackChain{
		{FinalSeverity: "critical"},
		{FinalSeverity: "high"},
		{FinalSeverity: "critical"},
		{FinalSeverity: "low"},
	}
	grouped := ChainsBySeverity(chains)
	if len(grouped["critical"]) != 2 {
		t.Errorf("expected 2 critical, got %d", len(grouped["critical"]))
	}
	if len(grouped["high"]) != 1 {
		t.Errorf("expected 1 high, got %d", len(grouped["high"]))
	}
}

func TestAnalyzer_LoadFindings(t *testing.T) {
	jsonl := `{"template-id":"tech-detect","info":{"name":"Tech","severity":"info","tags":["fingerprint"]},"host":"example.com","matched-at":"http://example.com/","matcher-name":"apache"}
{"template-id":"CVE-2024-1234","info":{"name":"RCE","severity":"critical","tags":["cve","rce"]},"host":"example.com","matched-at":"http://example.com/admin","matcher-name":"rce"}`

	a := NewAnalyzer(DefaultAnalyzerConfig())
	count, err := a.LoadFindings(strings.NewReader(jsonl))
	if err != nil {
		t.Fatalf("LoadFindings error: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 findings, got %d", count)
	}

	chains := a.Analyze()
	if len(chains) == 0 {
		t.Fatal("expected at least 1 chain")
	}
}

func TestAnalyzer_GenerateReport(t *testing.T) {
	jsonl := `{"template-id":"exposure","info":{"name":"Exposure","severity":"medium","tags":["exposure","config"]},"host":"h.com","matched-at":"http://h.com/","matcher-name":"config"}
{"template-id":"default-login","info":{"name":"Default Login","severity":"high","tags":["default-login"]},"host":"h.com","matched-at":"http://h.com/login","matcher-name":"default"}
{"template-id":"admin-panel","info":{"name":"Admin Panel","severity":"info","tags":["panel","admin"]},"host":"h.com","matched-at":"http://h.com/admin","matcher-name":"panel"}`

	a := NewAnalyzer(DefaultAnalyzerConfig())
	a.LoadFindings(strings.NewReader(jsonl))
	chains := a.Analyze()

	report := a.GenerateReport(chains)
	if report.Summary.TotalChains == 0 {
		t.Error("expected chains in report")
	}
	if report.GraphStats.Nodes != 3 {
		t.Errorf("expected 3 graph nodes, got %d", report.GraphStats.Nodes)
	}
	if len(report.Findings) != 3 {
		t.Errorf("expected 3 findings in report, got %d", len(report.Findings))
	}
}

func TestVulnMatches(t *testing.T) {
	f := &Finding{VulnType: "sqli", Tags: []string{"sqli", "cve"}}
	if !vulnMatches(f, []string{"sqli"}) {
		t.Error("expected match on vuln type")
	}
	if !vulnMatches(f, []string{"cve"}) {
		t.Error("expected match on tag")
	}
	if vulnMatches(f, []string{"xss"}) {
		t.Error("did not expect match on xss")
	}
}

func TestVulnMatches_TemplateID(t *testing.T) {
	f := &Finding{VulnType: "unknown", Tags: []string{}, TemplateID: "CVE-2024-sqli-1234"}
	if !vulnMatches(f, []string{"sqli"}) {
		t.Error("expected match on template ID")
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		url    string
		expect string
	}{
		{"http://example.com/path", "example.com"},
		{"https://sub.example.com:8080/page", "sub.example.com:8080"},
		{"http://localhost:8080", "localhost:8080"},
		{"example.com/path", "example.com"},
	}
	for _, tt := range tests {
		got := extractHost(tt.url)
		if got != tt.expect {
			t.Errorf("extractHost(%q) = %q, want %q", tt.url, got, tt.expect)
		}
	}
}

func TestAttackGraph_GetNode(t *testing.T) {
	g := NewAttackGraph(nil)
	f := &Finding{TemplateID: "test", Host: "h.com", VulnType: "xss", Tags: []string{"xss"}}
	g.AddFinding(f)
	if g.GetNode(f.ID) == nil {
		t.Error("expected to find node")
	}
	if g.GetNode("nonexistent") != nil {
		t.Error("did not expect to find nonexistent node")
	}
}

func TestAttackGraph_OutgoingEdges(t *testing.T) {
	g := NewAttackGraph(nil)
	f1 := &Finding{TemplateID: "exposure", Host: "h.com", Severity: "medium", Tags: []string{"exposure"}, VulnType: "exposure"}
	f2 := &Finding{TemplateID: "default-login", Host: "h.com", Severity: "high", Tags: []string{"default-login"}, VulnType: "default-login"}
	g.AddFindings([]*Finding{f1, f2})

	edges := g.OutgoingEdges(f1.ID)
	if len(edges) == 0 {
		t.Error("expected outgoing edges from exposure")
	}
}

func TestTopChains(t *testing.T) {
	chains := []*AttackChain{
		{Score: 20, FinalSeverity: "critical"},
		{Score: 15, FinalSeverity: "high"},
		{Score: 10, FinalSeverity: "high"},
	}
	top := TopChains(chains, 2)
	if len(top) != 2 {
		t.Fatalf("expected 2 chains, got %d", len(top))
	}
	if top[0].Score != 20 {
		t.Errorf("expected top score 20, got %f", top[0].Score)
	}
}

func TestDefaultChainRules(t *testing.T) {
	if len(DefaultChainRules) == 0 {
		t.Fatal("expected default chain rules")
	}
	// Verify a few key rules exist
	names := make(map[string]bool)
	for _, r := range DefaultChainRules {
		names[r.Name] = true
	}
	expected := []string{
		"info-leak-to-cred-access",
		"ssrf-to-metadata",
		"lfi-to-rce",
		"sqli-to-exfil",
		"xss-to-session-hijack",
		"version-to-cve",
		"cve-to-rce",
		"misconfig-to-access",
	}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("missing chain rule: %s", name)
		}
	}
}

func TestAnalyzer_CustomRules(t *testing.T) {
	customRule := ChainRule{
		Name: "custom-test",
		FromVuln: []string{"custom-a"},
		ToVuln: []string{"custom-b"},
		Relation: "enables",
		Confidence: 0.9,
		Reason: "test rule",
		RequiresSameHost: true,
	}
	config := AnalyzerConfig{
		MaxDepth: 3,
		CustomRules: []ChainRule{customRule},
	}
	a := NewAnalyzer(config)

	findings := []*Finding{
		{TemplateID: "f1", Host: "h.com", Severity: "low", Tags: []string{"custom-a"}, VulnType: "custom-a"},
		{TemplateID: "f2", Host: "h.com", Severity: "high", Tags: []string{"custom-b"}, VulnType: "custom-b"},
	}
	a.LoadFindingsDirect(findings)
	chains := a.Analyze()

	if len(chains) == 0 {
		t.Fatal("expected chains with custom rules")
	}
}

func TestSeverityBoost(t *testing.T) {
	g := NewAttackGraph(nil)
	// exposure (medium) → default-login (high) → panel (info)
	// default-login-to-auth-access has SeverityBoost: "critical"
	findings := []*Finding{
		{TemplateID: "exposure", Host: "h.com", Severity: "medium", Tags: []string{"exposure"}, VulnType: "exposure"},
		{TemplateID: "default-login", Host: "h.com", Severity: "high", Tags: []string{"default-login"}, VulnType: "default-login"},
		{TemplateID: "panel", Host: "h.com", Severity: "info", Tags: []string{"panel"}, VulnType: "panel"},
	}
	g.AddFindings(findings)

	cf := NewChainFinder(g, 5, 0.0)
	chains := cf.FindAll()

	found := false
	for _, c := range chains {
		if c.FinalSeverity == "critical" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one chain with critical severity due to boost")
	}
}

func TestAttackChain_Description(t *testing.T) {
	g := NewAttackGraph(nil)
	findings := []*Finding{
		{TemplateID: "f1", Host: "h.com", Severity: "medium", Tags: []string{"exposure"}, VulnType: "exposure"},
		{TemplateID: "f2", Host: "h.com", Severity: "high", Tags: []string{"default-login"}, VulnType: "default-login"},
	}
	g.AddFindings(findings)

	cf := NewChainFinder(g, 5, 0.0)
	chains := cf.FindAll()

	if len(chains) == 0 {
		t.Fatal("expected chains")
	}
	if chains[0].Description == "" {
		t.Error("expected non-empty description")
	}
	if !strings.Contains(chains[0].Description, "→") {
		t.Error("expected arrow in description")
	}
}
