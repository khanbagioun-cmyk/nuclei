package intelligence

import (
	"os"
	"testing"
	"time"
)

func TestCISAKEVEntry_GetPriority(t *testing.T) {
	tests := []struct {
		name     string
		entry    CISAKEVEntry
		expected KEVPriority
	}{
		{
			name:     "normal entry",
			entry:    CISAKEVEntry{CVEID: "CVE-2024-0001", KnownToBeRansomwareCampaignUse: false},
			expected: KEVPriorityNormal,
		},
		{
			name:     "ransomware entry",
			entry:    CISAKEVEntry{CVEID: "CVE-2024-0002", KnownToBeRansomwareCampaignUse: true},
			expected: KEVPriorityRansomware,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entry.GetPriority(); got != tt.expected {
				t.Errorf("GetPriority() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCISAKEVCatalog_GetKEVByCVE(t *testing.T) {
	catalog := &CISAKEVCatalog{
		Vulnerabilities: []CISAKEVEntry{
			{CVEID: "CVE-2024-0001", VendorProject: "Microsoft", Product: "Windows"},
			{CVEID: "CVE-2024-0002", VendorProject: "Apache", Product: "Log4j"},
		},
	}

	entry, found := catalog.GetKEVByCVE("CVE-2024-0001")
	if !found {
		t.Fatal("expected to find CVE-2024-0001")
	}
	if entry.Product != "Windows" {
		t.Errorf("expected product 'Windows', got '%s'", entry.Product)
	}

	_, found = catalog.GetKEVByCVE("CVE-9999-9999")
	if found {
		t.Fatal("should not find non-existent CVE")
	}

	entry, found = catalog.GetKEVByCVE("cve-2024-0002")
	if !found {
		t.Fatal("expected case-insensitive match")
	}
	if entry.Product != "Log4j" {
		t.Errorf("expected product 'Log4j', got '%s'", entry.Product)
	}
}

func TestCISAKEVCatalog_GetKEVCVEIDs(t *testing.T) {
	catalog := &CISAKEVCatalog{
		Vulnerabilities: []CISAKEVEntry{
			{CVEID: "CVE-2024-0001"},
			{CVEID: "CVE-2024-0002"},
			{CVEID: "CVE-2024-0003"},
		},
		Count: 3,
	}

	ids := catalog.GetKEVCVEIDs()
	if len(ids) != 3 {
		t.Fatalf("expected 3 IDs, got %d", len(ids))
	}
	if ids[0] != "CVE-2024-0001" {
		t.Errorf("expected first ID 'CVE-2024-0001', got '%s'", ids[0])
	}
}

func TestCISAKEVCatalog_GetRecentKEV(t *testing.T) {
	catalog := &CISAKEVCatalog{
		Vulnerabilities: []CISAKEVEntry{
			{CVEID: "CVE-2024-0001", DateAdded: "2024-01-01"},
			{CVEID: "CVE-2024-0002", DateAdded: "2024-06-01"},
			{CVEID: "CVE-2024-0003", DateAdded: "2024-12-01"},
		},
	}

	since, _ := time.Parse("2006-01-02", "2024-05-01")
	recent := catalog.GetRecentKEV(since)

	if len(recent) != 2 {
		t.Fatalf("expected 2 recent entries since 2024-05-01, got %d", len(recent))
	}
	if recent[0].CVEID != "CVE-2024-0002" {
		t.Errorf("expected first recent entry 'CVE-2024-0002', got '%s'", recent[0].CVEID)
	}
}

func TestFetchCISAKEV(t *testing.T) {
	catalog, err := FetchCISAKEV()
	if err != nil {
		t.Skipf("CISA KEV feed unavailable: %v", err)
	}

	if catalog.Count == 0 {
		t.Fatal("expected non-zero KEV count")
	}

	t.Logf("KEV catalog version: %s, count: %d", catalog.CatalogVersion, catalog.Count)

	if len(catalog.Vulnerabilities) != catalog.Count {
		t.Errorf("vulnerabilities length %d != count %d",
			len(catalog.Vulnerabilities), catalog.Count)
	}

	for _, v := range catalog.Vulnerabilities[:3] {
		if v.CVEID == "" {
			t.Error("found KEV entry with empty CVE ID")
		}
		t.Logf("  %s: %s (%s)", v.CVEID, v.VulnerabilityName, v.DateAdded)
	}
}

func TestThreatWatchState_LoadSave(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"

	// Load non-existent state
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState (new): %v", err)
	}
	if state.ProcessedCVEs == nil {
		t.Fatal("expected non-nil ProcessedCVEs map")
	}

	// Add some state
	state.MarkProcessed("CVE-2024-0001")
	state.MarkProcessed("CVE-2024-0002")
	state.GeneratedCount = 2
	state.KEVCount = 1

	// Save
	if err := state.Save(statePath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state file not created: %v", err)
	}

	// Reload
	state2, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState (reload): %v", err)
	}

	if !state2.IsProcessed("CVE-2024-0001") {
		t.Error("CVE-2024-0001 should be marked as processed")
	}
	if !state2.IsProcessed("CVE-2024-0002") {
		t.Error("CVE-2024-0002 should be marked as processed")
	}
	if state2.IsProcessed("CVE-2024-9999") {
		t.Error("CVE-2024-9999 should NOT be marked as processed")
	}
	if state2.GeneratedCount != 2 {
		t.Errorf("expected GeneratedCount=2, got %d", state2.GeneratedCount)
	}
	if state2.KEVCount != 1 {
		t.Errorf("expected KEVCount=1, got %d", state2.KEVCount)
	}
}

func TestThreatWatchState_Concurrent(t *testing.T) {
	state := &ThreatWatchState{
		ProcessedCVEs: make(map[string]bool),
	}

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			cveID := "CVE-2024-" + string(rune('0'+idx))
			state.MarkProcessed(cveID)
			_ = state.IsProcessed(cveID)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if len(state.ProcessedCVEs) < 10 {
		t.Errorf("expected at least 10 processed, got %d", len(state.ProcessedCVEs))
	}
}

func TestThreatWatchConfig_Defaults(t *testing.T) {
	cfg := DefaultThreatWatchConfig()

	if cfg.PollInterval != 15*time.Minute {
		t.Errorf("expected 15m poll interval, got %v", cfg.PollInterval)
	}
	if cfg.MinCVSSScore != 7.0 {
		t.Errorf("expected min CVSS 7.0, got %f", cfg.MinCVSSScore)
	}
	if cfg.TemplateOutputDir == "" {
		t.Error("expected non-empty template output dir")
	}
	if cfg.StateFile == "" {
		t.Error("expected non-empty state file")
	}
	if cfg.MaxPerPoll != 50 {
		t.Errorf("expected max per poll 50, got %d", cfg.MaxPerPoll)
	}
}

func TestThreatWatch_PollOnce(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := DefaultThreatWatchConfig()
	cfg.TemplateOutputDir = tmpDir + "/templates"
	cfg.StateFile = tmpDir + "/state.json"
	cfg.NVDAPIKey = ""
	cfg.MinCVSSScore = 0.0
	cfg.MinConfidence = 0.0
	cfg.MaxPerPoll = 3

	tw, err := NewThreatWatch(cfg)
	if err != nil {
		t.Fatalf("NewThreatWatch: %v", err)
	}

	events, err := tw.PollOnce()
	if err != nil {
		t.Skipf("NVD API unavailable: %v", err)
	}

	t.Logf("PollOnce returned %d events", len(events))

	for _, event := range events {
		t.Logf("  %s: source=%s score=%.1f kev=%v path=%s err=%s",
			event.CVEID, event.Source, event.CVSSScore, event.IsKEV,
			event.TemplatePath, event.Error)

		if event.Error == "" && event.TemplatePath != "" {
			if _, err := os.Stat(event.TemplatePath); err != nil {
				t.Errorf("template file not found: %s: %v", event.TemplatePath, err)
			}
		}
	}

	stats := tw.GetStats()
	t.Logf("stats: generated=%v skipped=%v kev=%v vulncheck_kev=%v processed=%v",
		stats["generated_count"], stats["skipped_count"],
		stats["kev_count"], stats["vulncheck_kev_count"], stats["processed_count"])
}
