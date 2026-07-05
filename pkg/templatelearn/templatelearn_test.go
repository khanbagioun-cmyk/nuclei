package templatelearn

import (
	"fmt"
	"strings"
	"testing"
)

func TestSignatureFromFinding(t *testing.T) {
	sig1 := SignatureFromFinding("CVE-2024-1234", "example.com", "rce")
	sig2 := SignatureFromFinding("CVE-2024-1234", "example.com", "rce")
	sig3 := SignatureFromFinding("CVE-2024-1234", "other.com", "rce")

	if sig1.Hash != sig2.Hash {
		t.Error("expected same signature for same input")
	}
	if sig1.Hash == sig3.Hash {
		t.Error("expected different signature for different host")
	}
	if sig1.Hash == "" {
		t.Error("expected non-empty hash")
	}
}

func TestFeedbackStore_MarkFeedback(t *testing.T) {
	store := NewFeedbackStore("", 3)
	fb := store.MarkFeedback("CVE-2024-1234", "example.com", "rce", "rce",
		FeedbackFalsePositive, "test environment", "")

	if fb == nil {
		t.Fatal("expected feedback")
	}
	if fb.Type != FeedbackFalsePositive {
		t.Error("expected FP type")
	}
	if fb.Count != 1 {
		t.Errorf("expected count 1, got %d", fb.Count)
	}
}

func TestFeedbackStore_FeedbackIncrement(t *testing.T) {
	store := NewFeedbackStore("", 3)

	// Mark the same template as FP from 3 distinct hosts (new behavior)
	hosts := []string{"example.com", "test.example.com", "prod.example.com"}
	for _, h := range hosts {
		store.MarkFeedback("CVE-2024-1234", h, "rce", "rce",
			FeedbackFalsePositive, "test environment", "")
	}

	// Get feedback from any of the host signatures
	fb := store.GetFeedback(SignatureFromFinding("CVE-2024-1234", "example.com", "rce").Hash)
	if fb == nil {
		t.Fatal("expected feedback")
	}
	if fb.Count != 1 {
		t.Errorf("expected count 1 per signature, got %d", fb.Count)
	}
	if !fb.AutoSuppressed {
		t.Error("expected auto-suppressed after 3 FP marks from distinct hosts")
	}
}

func TestFeedbackStore_ShouldSuppress(t *testing.T) {
	store := NewFeedbackStoreWithDistinctHosts("", 1, 1) // threshold=1 for immediate suppression

	store.MarkFeedback("CVE-2024-1234", "example.com", "rce", "rce",
		FeedbackFalsePositive, "test env", "")

	// Should suppress on any host (host-agnostic rule)
	suppressed, reason := store.ShouldSuppress("CVE-2024-1234", "other-host.com", "rce", "rce")
	if !suppressed {
		t.Error("expected suppression")
	}
	if reason == "" {
		t.Error("expected reason")
	}
}

func TestFeedbackStore_ShouldNotSuppress(t *testing.T) {
	store := NewFeedbackStore("", 5)

	store.MarkFeedback("CVE-2024-1234", "example.com", "rce", "rce",
		FeedbackFalsePositive, "test env", "")

	suppressed, _ := store.ShouldSuppress("CVE-2024-1234", "example.com", "rce", "rce")
	if suppressed {
		t.Error("expected no suppression (below threshold)")
	}
}

func TestFeedbackStore_ManualSuppression(t *testing.T) {
	store := NewFeedbackStore("", 5)

	rule := &SuppressionRule{
		TemplateID:  "bad-template",
		Host:        "",
		MatcherName: "",
		Reason:      "Manual suppression: always FP",
	}
	store.AddSuppressionRule(rule)

	suppressed, reason := store.ShouldSuppress("bad-template", "any-host.com", "any-matcher", "")
	if !suppressed {
		t.Error("expected manual suppression")
	}
	if !strings.Contains(reason, "Manual") {
		t.Errorf("expected manual reason, got %s", reason)
	}
}

func TestFeedbackStore_RemoveSuppression(t *testing.T) {
	store := NewFeedbackStore("", 5)

	rule := &SuppressionRule{
		TemplateID: "temp-template",
		Reason:     "test",
	}
	store.AddSuppressionRule(rule)

	ruleID := rule.ID
	if !store.RemoveSuppression(ruleID) {
		t.Error("expected removal to succeed")
	}
	if store.RemoveSuppression(ruleID) {
		t.Error("expected second removal to fail")
	}
}

func TestFeedbackStore_Stats(t *testing.T) {
	store := NewFeedbackStore("", 3)

	store.MarkFeedback("t1", "h1.com", "m1", "sqli", FeedbackFalsePositive, "", "")
	store.MarkFeedback("t2", "h2.com", "m2", "xss", FeedbackTruePositive, "", "")
	store.MarkFeedback("t3", "h3.com", "m3", "rce", FeedbackFalseNegative, "", "")

	// Mark t1 as FP from 2 more distinct hosts to trigger auto-suppress (total 3 distinct)
	store.MarkFeedback("t1", "h4.com", "m1", "sqli", FeedbackFalsePositive, "", "")
	store.MarkFeedback("t1", "h5.com", "m1", "sqli", FeedbackFalsePositive, "", "")

	stats := store.Stats()
	if stats.TotalFeedback != 5 {
		t.Errorf("expected 5 feedback, got %d", stats.TotalFeedback)
	}
	if stats.FalsePositives != 3 {
		t.Errorf("expected 3 FP, got %d", stats.FalsePositives)
	}
	if stats.TruePositives != 1 {
		t.Errorf("expected 1 TP, got %d", stats.TruePositives)
	}
	if stats.FalseNegatives != 1 {
		t.Errorf("expected 1 FN, got %d", stats.FalseNegatives)
	}
	if stats.AutoSuppressed != 3 {
		t.Errorf("expected 3 auto-suppressed (all entries for t1), got %d", stats.AutoSuppressed)
	}
}

func TestFilterJSONL(t *testing.T) {
	store := NewFeedbackStore("", 1)

	// Add a suppression rule for a specific template
	store.AddSuppressionRule(&SuppressionRule{
		TemplateID:  "fp-template",
		Host:        "example.com",
		MatcherName: "fp-matcher",
		Reason:      "known FP",
	})

	jsonl := `{"template-id":"fp-template","info":{"name":"FP","severity":"high","tags":["xss"]},"host":"example.com","matched-at":"http://example.com/","matcher-name":"fp-matcher"}
{"template-id":"real-vuln","info":{"name":"Real","severity":"critical","tags":["cve","rce"]},"host":"example.com","matched-at":"http://example.com/admin","matcher-name":"rce"}`

	var output strings.Builder
	total, suppressed, err := FilterJSONL(store, strings.NewReader(jsonl), &output)
	if err != nil {
		t.Fatalf("FilterJSONL error: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 total, got %d", total)
	}
	if suppressed != 1 {
		t.Errorf("expected 1 suppressed, got %d", suppressed)
	}
	if strings.Contains(output.String(), "fp-template") {
		t.Error("expected FP template to be filtered out")
	}
	if !strings.Contains(output.String(), "real-vuln") {
		t.Error("expected real vuln to pass through")
	}
}

func TestFilterResultJSONL(t *testing.T) {
	store := NewFeedbackStore("", 1)
	store.AddSuppressionRule(&SuppressionRule{
		TemplateID: "fp-template",
		Reason:     "test",
	})

	jsonl := `{"template-id":"fp-template","info":{"name":"FP","severity":"high","tags":["xss"]},"host":"h.com","matched-at":"http://h.com/","matcher-name":"m1"}
{"template-id":"ok-template","info":{"name":"OK","severity":"info","tags":["tech"]},"host":"h.com","matched-at":"http://h.com/","matcher-name":"m2"}`

	results, err := FilterResultJSONL(store, strings.NewReader(jsonl))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if !results[0].Suppressed {
		t.Error("expected first finding to be suppressed")
	}
	if results[1].Suppressed {
		t.Error("expected second finding to pass")
	}
}

func TestInferVulnTypeFromTags(t *testing.T) {
	tests := []struct {
		tags    []string
		tmplID  string
		matcher string
		expect  string
	}{
		{[]string{"sqli"}, "", "", "sqli"},
		{[]string{"cve", "rce"}, "", "", "rce"},
		{[]string{}, "cve-2024-xss-123", "", "xss"},
		{[]string{"tech", "fingerprint"}, "", "", "tech"},
		{[]string{}, "", "", "unknown"},
	}
	for _, tt := range tests {
		got := inferVulnTypeFromTags(tt.tags, tt.tmplID, tt.matcher)
		if got != tt.expect {
			t.Errorf("inferVulnTypeFromTags(%v, %q, %q) = %q, want %q", tt.tags, tt.tmplID, tt.matcher, got, tt.expect)
		}
	}
}

func TestFNDetector_CheckFalseNegatives(t *testing.T) {
	store := NewFeedbackStore("", 5)

	// Mark a TP on host A
	store.MarkFeedback("CVE-2024-1234", "host-a.com", "rce", "rce",
		FeedbackTruePositive, "confirmed RCE", "")

	detector := NewFNDetector(store)

	// Scan host B (which should have had the same vuln but didn't trigger)
	scannedHosts := []string{"host-a.com", "host-b.com"}
	actualFindings := []*NucleiJSONLFinding{
		{TemplateID: "CVE-2024-1234", Host: "host-a.com", MatcherName: "rce"},
	}

	results := detector.CheckFalseNegatives(scannedHosts, actualFindings)
	if len(results) == 0 {
		t.Fatal("expected at least 1 FN result")
	}
	found := false
	for _, r := range results {
		if r.Host == "host-b.com" && r.TemplateID == "CVE-2024-1234" {
			found = true
		}
	}
	if !found {
		t.Error("expected FN for host-b.com")
	}
}

func TestGenerateReport(t *testing.T) {
	store := NewFeedbackStore("", 3)

	store.MarkFeedback("t1", "h1.com", "m1", "sqli", FeedbackFalsePositive, "fp1", "")
	store.MarkFeedback("t1", "h2.com", "m1", "sqli", FeedbackFalsePositive, "fp2", "")
	store.MarkFeedback("t2", "h1.com", "m2", "xss", FeedbackTruePositive, "tp1", "")

	report := store.GenerateReport()
	if report.Stats.TotalFeedback != 3 {
		t.Errorf("expected 3 feedback entries, got %d", report.Stats.TotalFeedback)
	}
	if len(report.TopFPTemplates) == 0 {
		t.Fatal("expected top FP templates")
	}
	if report.TopFPTemplates[0].TemplateID != "t1" {
		t.Errorf("expected t1 as top FP, got %s", report.TopFPTemplates[0].TemplateID)
	}
	if report.TopFPTemplates[0].FPCount != 2 {
		t.Errorf("expected 2 FP count, got %d", report.TopFPTemplates[0].FPCount)
	}
}

func TestPersistence(t *testing.T) {
	tmpPath := t.TempDir() + "/feedback.json"

	// Create and populate store
	store1 := NewFeedbackStore(tmpPath, 3)
	store1.MarkFeedback("t1", "h1.com", "m1", "sqli", FeedbackFalsePositive, "test", "")
	store1.MarkFeedback("t2", "h2.com", "m2", "xss", FeedbackTruePositive, "confirmed", "")
	store1.AddSuppressionRule(&SuppressionRule{
		TemplateID: "t3",
		Reason:     "manual",
	})

	if err := store1.Save(); err != nil {
		t.Fatalf("save error: %v", err)
	}

	// Load into new store
	store2 := NewFeedbackStore(tmpPath, 3)
	if err := store2.Load(); err != nil {
		t.Fatalf("load error: %v", err)
	}

	// Verify feedback loaded
	fb := store2.GetFeedback(SignatureFromFinding("t1", "h1.com", "m1").Hash)
	if fb == nil {
		t.Fatal("expected feedback to be loaded")
	}
	if fb.Reason != "test" {
		t.Errorf("expected reason 'test', got %s", fb.Reason)
	}

	// Verify suppression loaded
	suppressed, _ := store2.ShouldSuppress("t3", "any", "any", "")
	if !suppressed {
		t.Error("expected suppression rule to be loaded")
	}
}

func TestPersistence_EmptyFile(t *testing.T) {
	tmpPath := t.TempDir() + "/nonexistent.json"
	store := NewFeedbackStore(tmpPath, 3)
	if err := store.Load(); err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if store.Stats().TotalFeedback != 0 {
		t.Error("expected empty store")
	}
}

func TestSuppressionRule_WildcardMatching(t *testing.T) {
	store := NewFeedbackStore("", 5)

	// Rule with empty Host = all hosts
	store.AddSuppressionRule(&SuppressionRule{
		TemplateID: "wildcard-template",
		Host:       "", // any host
		Reason:     "always FP",
	})

	// Should suppress on any host
	suppressed, _ := store.ShouldSuppress("wildcard-template", "host-a.com", "", "")
	if !suppressed {
		t.Error("expected suppression on host-a")
	}
	suppressed, _ = store.ShouldSuppress("wildcard-template", "host-b.com", "", "")
	if !suppressed {
		t.Error("expected suppression on host-b")
	}
	// Should not suppress different template
	suppressed, _ = store.ShouldSuppress("other-template", "host-a.com", "", "")
	if suppressed {
		t.Error("expected no suppression for different template")
	}
}

func TestSuppressionRule_VulnTypeMatching(t *testing.T) {
	store := NewFeedbackStore("", 5)

	store.AddSuppressionRule(&SuppressionRule{
		VulnType: "sqli",
		Reason:   "suppress all sqli",
	})

	suppressed, _ := store.ShouldSuppress("any-template", "any-host", "", "sqli")
	if !suppressed {
		t.Error("expected suppression for sqli")
	}
	suppressed, _ = store.ShouldSuppress("any-template", "any-host", "", "xss")
	if suppressed {
		t.Error("expected no suppression for xss")
	}
}

func TestFilterJSONL_LargeStream(t *testing.T) {
	store := NewFeedbackStore("", 1)
	store.AddSuppressionRule(&SuppressionRule{
		TemplateID: "fp-template",
		Reason:     "known FP",
	})

	// Generate 5000 lines: odd lines are FP-template (suppressed), even are real
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		if i%2 == 0 {
			sb.WriteString(`{"template-id":"fp-template","info":{"name":"FP","severity":"high","tags":["xss"]},"host":"example.com","matched-at":"http://example.com/","matcher-name":"m"}`)
		} else {
			sb.WriteString(fmt.Sprintf(`{"template-id":"real-%d","info":{"name":"Real","severity":"info","tags":["tech"]},"host":"example.com","matched-at":"http://example.com/%d","matcher-name":"m"}`, i, i))
		}
		sb.WriteByte('\n')
	}

	var output strings.Builder
	total, suppressed, err := FilterJSONL(store, strings.NewReader(sb.String()), &output)
	if err != nil {
		t.Fatalf("FilterJSONL error: %v", err)
	}
	if total != 5000 {
		t.Errorf("expected 5000 total, got %d", total)
	}
	if suppressed != 2500 {
		t.Errorf("expected 2500 suppressed, got %d", suppressed)
	}
	// Output should only contain real-* templates
	outputLines := strings.Count(output.String(), "\n")
	if outputLines != 2500 {
		t.Errorf("expected 2500 output lines, got %d", outputLines)
	}
	if strings.Contains(output.String(), "fp-template") {
		t.Error("expected no fp-template in output")
	}
}

func TestFilterJSONLWithBuffer_ZeroBuffer(t *testing.T) {
	store := NewFeedbackStore("", 1)
	store.AddSuppressionRule(&SuppressionRule{
		TemplateID: "fp",
		Reason:     "test",
	})

	jsonl := `{"template-id":"fp","info":{"name":"FP","severity":"high","tags":[]},"host":"h.com","matched-at":"http://h.com/","matcher-name":"m"}
{"template-id":"ok","info":{"name":"OK","severity":"info","tags":[]},"host":"h.com","matched-at":"http://h.com/","matcher-name":"m"}`

	var output strings.Builder
	total, suppressed, err := FilterJSONLWithBuffer(store, strings.NewReader(jsonl), &output, 0)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 total, got %d", total)
	}
	if suppressed != 1 {
		t.Errorf("expected 1 suppressed, got %d", suppressed)
	}
	if strings.Contains(output.String(), "fp") && !strings.Contains(output.String(), "ok") {
		t.Error("expected ok to pass, fp to be suppressed")
	}
}

func TestTechStackIndex_SharesTechStack(t *testing.T) {
	findings := []*NucleiJSONLFinding{
		{TemplateID: "tech-detect", Host: "a.com", MatcherName: "nginx", Info: struct {
			Name     string   `json:"name"`
			Severity string   `json:"severity"`
			Tags     []string `json:"tags"`
		}{Tags: []string{"tech"}}},
		{TemplateID: "tech-detect", Host: "b.com", MatcherName: "nginx", Info: struct {
			Name     string   `json:"name"`
			Severity string   `json:"severity"`
			Tags     []string `json:"tags"`
		}{Tags: []string{"tech"}}},
		{TemplateID: "tech-detect", Host: "c.com", MatcherName: "apache", Info: struct {
			Name     string   `json:"name"`
			Severity string   `json:"severity"`
			Tags     []string `json:"tags"`
		}{Tags: []string{"tech"}}},
	}
	idx := NewTechStackIndex(findings)

	if !idx.SharesTechStack("a.com", "b.com") {
		t.Error("expected a.com and b.com to share nginx stack")
	}
	if idx.SharesTechStack("a.com", "c.com") {
		t.Error("expected a.com (nginx) and c.com (apache) to NOT share stack")
	}
	// Unknown host = conservative true
	if !idx.SharesTechStack("a.com", "unknown.com") {
		t.Error("expected unknown host to be conservative true")
	}
}

func TestComputeFNConfidence(t *testing.T) {
	fb := &Feedback{
		TemplateID: "CVE-2024-1234",
		VulnType:   "rce",
	}

	// High confidence: same stack, multiple TPs, CVE, critical vuln
	conf := ComputeFNConfidence(fb, 5, true)
	if conf < 0.8 {
		t.Errorf("expected high confidence (>0.8), got %.2f", conf)
	}
	if conf > 1.0 {
		t.Errorf("expected confidence <=1.0, got %.2f", conf)
	}

	// Lower confidence: different stack, single TP, non-CVE
	fb2 := &Feedback{
		TemplateID: "custom-xss",
		VulnType:   "xss",
	}
	conf2 := ComputeFNConfidence(fb2, 1, false)
	if conf2 >= conf {
		t.Errorf("expected lower confidence for different stack + non-CVE: %.2f vs %.2f", conf2, conf)
	}
	if conf2 < 0.1 {
		t.Errorf("expected minimum confidence >0.1, got %.2f", conf2)
	}
}

func TestFNDetector_DifferentStackSkipped(t *testing.T) {
	store := NewFeedbackStore("", 5)

	// Mark TP on host-a (nginx)
	store.MarkFeedback("CVE-2024-1234", "host-a.com", "rce", "rce",
		FeedbackTruePositive, "confirmed RCE", "")

	detector := NewFNDetector(store)

	// host-b is apache (different stack), host-c is nginx (same stack)
	scannedHosts := []string{"host-a.com", "host-b.com", "host-c.com"}
	actualFindings := []*NucleiJSONLFinding{
		{TemplateID: "CVE-2024-1234", Host: "host-a.com", MatcherName: "rce"},
		{TemplateID: "tech-detect", Host: "host-a.com", MatcherName: "nginx",
			Info: struct {
				Name     string   `json:"name"`
				Severity string   `json:"severity"`
				Tags     []string `json:"tags"`
			}{Tags: []string{"tech"}}},
		{TemplateID: "tech-detect", Host: "host-b.com", MatcherName: "apache",
			Info: struct {
				Name     string   `json:"name"`
				Severity string   `json:"severity"`
				Tags     []string `json:"tags"`
			}{Tags: []string{"tech"}}},
		{TemplateID: "tech-detect", Host: "host-c.com", MatcherName: "nginx",
			Info: struct {
				Name     string   `json:"name"`
				Severity string   `json:"severity"`
				Tags     []string `json:"tags"`
			}{Tags: []string{"tech"}}},
	}

	results := detector.CheckFalseNegatives(scannedHosts, actualFindings)

	// Should have FN for host-c (same stack) but confidence should be > host-b (different stack)
	var hostBConf, hostCConf float64
	for _, r := range results {
		if r.Host == "host-b.com" {
			hostBConf = r.Confidence
		}
		if r.Host == "host-c.com" {
			hostCConf = r.Confidence
		}
	}
	if hostCConf <= hostBConf {
		t.Errorf("expected host-c (same stack) confidence > host-b (diff stack): %.2f vs %.2f", hostCConf, hostBConf)
	}
}
