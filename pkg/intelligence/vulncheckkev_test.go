package intelligence

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestVulnCheckKEVEntry_IsRansomware(t *testing.T) {
	tests := []struct {
		name     string
		entry    VulnCheckKEVEntry
		expected bool
	}{
		{
			name:     "known ransomware",
			entry:    VulnCheckKEVEntry{KnownRansomwareCampaignUse: "Known"},
			expected: true,
		},
		{
			name:     "not ransomware",
			entry:    VulnCheckKEVEntry{KnownRansomwareCampaignUse: "Unknown"},
			expected: false,
		},
		{
			name:     "empty",
			entry:    VulnCheckKEVEntry{},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entry.IsRansomware(); got != tt.expected {
				t.Errorf("IsRansomware() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestVulnCheckKEVEntry_HasExploitCode(t *testing.T) {
	entryWithExploit := VulnCheckKEVEntry{
		VulnCheckXDB: []XDBEntry{
			{XDBID: "abc123", CloneSSHURL: "git@github.com:test/exploit.git"},
		},
	}
	entryWithoutExploit := VulnCheckKEVEntry{}

	if !entryWithExploit.HasExploitCode() {
		t.Error("expected HasExploitCode() = true for entry with XDB refs")
	}
	if entryWithoutExploit.HasExploitCode() {
		t.Error("expected HasExploitCode() = false for entry without XDB refs")
	}
}

func TestVulnCheckKEVEntry_IsInCISAKEV(t *testing.T) {
	now := time.Now()

	entryInCISA := VulnCheckKEVEntry{CISADateAdded: &now}
	entryNotInCISA := VulnCheckKEVEntry{}

	if !entryInCISA.IsInCISAKEV() {
		t.Error("expected IsInCISAKEV() = true when CISADateAdded is set")
	}
	if entryNotInCISA.IsInCISAKEV() {
		t.Error("expected IsInCISAKEV() = false when CISADateAdded is nil")
	}
}

func TestVulnCheckKEVEntry_VulnCheckOnly(t *testing.T) {
	now := time.Now()

	entryVCOnly := VulnCheckKEVEntry{}
	entryAlsoCISA := VulnCheckKEVEntry{CISADateAdded: &now}

	if !entryVCOnly.VulnCheckOnly() {
		t.Error("expected VulnCheckOnly() = true when not in CISA KEV")
	}
	if entryAlsoCISA.VulnCheckOnly() {
		t.Error("expected VulnCheckOnly() = false when also in CISA KEV")
	}
}

func TestVulnCheckKEVEntry_GetPriority(t *testing.T) {
	tests := []struct {
		name     string
		entry    VulnCheckKEVEntry
		expected VulnCheckKEVPriority
	}{
		{
			name:     "normal - no exploit, no ransomware",
			entry:    VulnCheckKEVEntry{},
			expected: VulnCheckKEVPriorityNormal,
		},
		{
			name: "exploit code only",
			entry: VulnCheckKEVEntry{
				VulnCheckXDB: []XDBEntry{{XDBID: "abc"}},
			},
			expected: VulnCheckKEVPriorityExploit,
		},
		{
			name:     "ransomware only",
			entry:    VulnCheckKEVEntry{KnownRansomwareCampaignUse: "Known"},
			expected: VulnCheckKEVPriorityRansomware,
		},
		{
			name: "ransomware + exploit = critical",
			entry: VulnCheckKEVEntry{
				KnownRansomwareCampaignUse: "Known",
				VulnCheckXDB:               []XDBEntry{{XDBID: "abc"}},
			},
			expected: VulnCheckKEVPriorityCritical,
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

func TestVulnCheckKEVCatalog_GetVulnCheckKEVByCVE(t *testing.T) {
	catalog := &VulnCheckKEVCatalog{
		Data: []VulnCheckKEVEntry{
			{CVE: []string{"CVE-2024-4577"}, Product: "PHP", VendorProject: "PHP Group"},
			{CVE: []string{"CVE-2024-0001", "CVE-2024-0002"}, Product: "Windows"},
		},
	}

	entry, found := catalog.GetVulnCheckKEVByCVE("CVE-2024-4577")
	if !found {
		t.Fatal("expected to find CVE-2024-4577")
	}
	if entry.Product != "PHP" {
		t.Errorf("expected product 'PHP', got '%s'", entry.Product)
	}

	entry, found = catalog.GetVulnCheckKEVByCVE("CVE-2024-0002")
	if !found {
		t.Fatal("expected to find CVE-2024-0002 (second CVE in multi-CVE entry)")
	}
	if entry.Product != "Windows" {
		t.Errorf("expected product 'Windows', got '%s'", entry.Product)
	}

	_, found = catalog.GetVulnCheckKEVByCVE("CVE-9999-9999")
	if found {
		t.Fatal("should not find non-existent CVE")
	}

	entry, found = catalog.GetVulnCheckKEVByCVE("cve-2024-4577")
	if !found {
		t.Fatal("expected case-insensitive match")
	}
	if entry.Product != "PHP" {
		t.Errorf("expected product 'PHP', got '%s'", entry.Product)
	}
}

func TestVulnCheckKEVCatalog_GetVulnCheckKEVCVEIDs(t *testing.T) {
	catalog := &VulnCheckKEVCatalog{
		Data: []VulnCheckKEVEntry{
			{CVE: []string{"CVE-2024-0001"}},
			{CVE: []string{"CVE-2024-0002", "CVE-2024-0003"}},
			{CVE: []string{"CVE-2024-0001"}}, // duplicate
		},
	}

	ids := catalog.GetVulnCheckKEVCVEIDs()
	if len(ids) != 3 {
		t.Fatalf("expected 3 unique IDs, got %d", len(ids))
	}
}

func TestVulnCheckKEVCatalog_GetRecentVulnCheckKEV(t *testing.T) {
	t1, _ := time.Parse(time.RFC3339, "2024-06-01T00:00:00Z")
	t2, _ := time.Parse(time.RFC3339, "2024-09-01T00:00:00Z")
	t3, _ := time.Parse(time.RFC3339, "2024-12-01T00:00:00Z")

	catalog := &VulnCheckKEVCatalog{
		Data: []VulnCheckKEVEntry{
			{CVE: []string{"CVE-2024-0001"}, DateAdded: t1},
			{CVE: []string{"CVE-2024-0002"}, DateAdded: t2},
			{CVE: []string{"CVE-2024-0003"}, DateAdded: t3},
			{CVE: []string{"CVE-2024-0004"}, DateAdded: time.Time{}}, // zero time, should be skipped
		},
	}

	since, _ := time.Parse(time.RFC3339, "2024-08-01T00:00:00Z")
	recent := catalog.GetRecentVulnCheckKEV(since)

	if len(recent) != 2 {
		t.Fatalf("expected 2 recent entries since 2024-08-01, got %d", len(recent))
	}
	if recent[0].CVE[0] != "CVE-2024-0002" {
		t.Errorf("expected first recent entry 'CVE-2024-0002', got '%s'", recent[0].CVE[0])
	}
}

func TestVulnCheckKEVJSONParsing(t *testing.T) {
	jsonData := `{
		"data": [
			{
				"vendorProject": "PHP Group",
				"product": "PHP",
				"shortDescription": "PHP-CGI OS Command Injection",
				"vulnerabilityName": "PHP-CGI OS Command Injection Vulnerability",
				"required_action": "Apply mitigations",
				"knownRansomwareCampaignUse": "Known",
				"cve": ["CVE-2024-4577"],
				"cwes": ["CWE-78"],
				"vulncheck_xdb": [
					{
						"xdb_id": "024996c990cc",
						"xdb_url": "https://vulncheck.com/xdb/024996c990cc",
						"date_added": "2025-02-14T19:38:10Z",
						"exploit_type": "initial-access",
						"clone_ssh_url": "git@github.com:test/exploit.git"
					}
				],
				"vulncheck_reported_exploitation": [
					{
						"url": "https://example.com/report",
						"date_added": "2024-06-07T00:00:00Z"
					}
				],
				"reported_exploited_by_vulncheck_canaries": true,
				"dueDate": "2024-07-03T00:00:00Z",
				"cisa_date_added": "2024-06-12T00:00:00Z",
				"date_added": "2024-06-07T00:00:00Z"
			},
			{
				"vendorProject": "Apache",
				"product": "Log4j",
				"shortDescription": "Remote code execution",
				"vulnerabilityName": "Log4Shell",
				"required_action": "Update immediately",
				"knownRansomwareCampaignUse": "Unknown",
				"cve": ["CVE-2021-44228"],
				"vulncheck_xdb": [],
				"vulncheck_reported_exploitation": [],
				"date_added": "2021-12-10T00:00:00Z"
			}
		]
	}`

	var catalog VulnCheckKEVCatalog
	if err := json.Unmarshal([]byte(jsonData), &catalog); err != nil {
		t.Fatalf("failed to parse VulnCheck KEV JSON: %v", err)
	}

	if len(catalog.Data) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(catalog.Data))
	}

	// Verify first entry (PHP CVE with ransomware + exploit)
	php := catalog.Data[0]
	if php.Product != "PHP" {
		t.Errorf("expected product 'PHP', got '%s'", php.Product)
	}
	if !php.IsRansomware() {
		t.Error("expected PHP entry to be ransomware")
	}
	if !php.HasExploitCode() {
		t.Error("expected PHP entry to have exploit code")
	}
	if !php.IsInCISAKEV() {
		t.Error("expected PHP entry to be in CISA KEV")
	}
	if php.GetPriority() != VulnCheckKEVPriorityCritical {
		t.Errorf("expected priority Critical, got %v", php.GetPriority())
	}

	// Verify second entry (Log4j without ransomware or exploit code in XDB)
	log4j := catalog.Data[1]
	if log4j.Product != "Log4j" {
		t.Errorf("expected product 'Log4j', got '%s'", log4j.Product)
	}
	if log4j.IsRansomware() {
		t.Error("expected Log4j entry to NOT be ransomware")
	}
	if log4j.HasExploitCode() {
		t.Error("expected Log4j entry to NOT have exploit code (empty XDB)")
	}
	if log4j.IsInCISAKEV() {
		t.Error("expected Log4j entry to NOT be in CISA KEV")
	}
	if log4j.GetPriority() != VulnCheckKEVPriorityNormal {
		t.Errorf("expected priority Normal, got %v", log4j.GetPriority())
	}
}

func TestFetchVulnCheckKEV_NoToken(t *testing.T) {
	// Save and clear token
	oldToken := os.Getenv("VULNCHECK_API_TOKEN")
	os.Unsetenv("VULNCHECK_API_TOKEN")
	defer func() {
		if oldToken != "" {
			os.Setenv("VULNCHECK_API_TOKEN", oldToken)
		}
	}()

	_, err := FetchVulnCheckKEV()
	if err == nil {
		t.Fatal("expected error when VULNCHECK_API_TOKEN is not set")
	}
}

func TestThreatWatchState_VulnCheckKEVCount(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"

	state := &ThreatWatchState{
		ProcessedCVEs:     make(map[string]bool),
		VulnCheckKEVCount: 5,
	}

	if err := state.Save(statePath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	state2, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	if state2.VulnCheckKEVCount != 5 {
		t.Errorf("expected VulnCheckKEVCount=5, got %d", state2.VulnCheckKEVCount)
	}
}
