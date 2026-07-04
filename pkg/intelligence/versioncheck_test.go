package intelligence

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/versionutil"
)

func TestParseVersion_Simple(t *testing.T) {
	tests := []struct {
		input    string
		epoch    int
		segments []int
	}{
		{"1.2.3", 0, []int{1, 2, 3}},
		{"10.0", 0, []int{10, 0}},
		{"5", 0, []int{5}},
		{"1.2.3.4.5", 0, []int{1, 2, 3, 4, 5}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			pv, err := versionutil.Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.input, err)
			}
			if pv.Epoch != tt.epoch {
				t.Errorf("epoch: got %d, want %d", pv.Epoch, tt.epoch)
			}
			if len(pv.Segments) != len(tt.segments) {
				t.Fatalf("segments: got %v, want %v", pv.Segments, tt.segments)
			}
			for i, seg := range tt.segments {
				if pv.Segments[i] != seg {
					t.Errorf("segment %d: got %d, want %d", i, pv.Segments[i], seg)
				}
			}
		})
	}
}

func TestParseVersion_Distro(t *testing.T) {
	tests := []struct {
		input        string
		expectDistro bool
	}{
		{"1.2.3-1.el9", true},
		{"1.2.3-1ubuntu4", true},
		{"1.2.3+deb11", true},
		{"1:2.0-1.el8", true},
		{"1.2.3", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			pv, err := versionutil.Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.input, err)
			}
			if tt.expectDistro && pv.Distro == "" {
				t.Errorf("expected distro suffix, got empty")
			}
			if !tt.expectDistro && pv.Distro != "" {
				t.Errorf("expected no distro suffix, got '%s'", pv.Distro)
			}
		})
	}
}

func TestParseVersion_Epoch(t *testing.T) {
	pv, err := versionutil.Parse("1:2.4.41-4ubuntu3.18")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pv.Epoch != 1 {
		t.Errorf("epoch: got %d, want 1", pv.Epoch)
	}
	if len(pv.Segments) < 3 {
		t.Errorf("expected at least 3 segments, got %d", len(pv.Segments))
	}
	if pv.Segments[0] != 2 {
		t.Errorf("first segment: got %d, want 2", pv.Segments[0])
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b     string
		expected int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.3", "1.2.4", -1},
		{"1.2.4", "1.2.3", 1},
		{"1.2", "1.2.0", 0},
		{"1.2", "1.2.1", -1},
		{"1.10.0", "1.9.0", 1},
		{"1:2.0", "2.0", 1},
		{"2.0", "1:2.0", -1},
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc1", 1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			a, _ := versionutil.Parse(tt.a)
			b, _ := versionutil.Parse(tt.b)
			got := versionutil.Compare(a, b)
			if got != tt.expected {
				t.Errorf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestVersionChecker_InRange(t *testing.T) {
	vc := NewVersionChecker()

	tests := []struct {
		detected string
		from     string
		to       string
		expected bool
	}{
		{"1.0.0", "1.0.0", "2.0.0", true},
		{"1.5.0", "1.0.0", "2.0.0", true},
		{"2.0.0", "1.0.0", "2.0.0", false},
		{"0.9.0", "1.0.0", "2.0.0", false},
		{"1.2.3", "1.0", "1.3", true},
		{"1.3.0", "1.0", "1.3", false},
		{"5.5.15", "5.0", "5.5.16", true},
		{"5.5.16", "5.0", "5.5.16", false},
	}

	for _, tt := range tests {
		t.Run(tt.detected, func(t *testing.T) {
			result := vc.CheckVersion(tt.detected, []VersionRange{{From: tt.from, To: tt.to}}, "TEST")
			if result.Vulnerable != tt.expected {
				t.Errorf("CheckVersion(%q, %q-%q) = vulnerable=%v, want %v. Reason: %s",
					tt.detected, tt.from, tt.to, result.Vulnerable, tt.expected, result.Reason)
			}
		})
	}
}

func TestVersionChecker_CheckVersion(t *testing.T) {
	vc := NewVersionChecker()

	// Vulnerable version
	result := vc.CheckVersion("1.2.3", []VersionRange{
		{From: "1.0.0", To: "1.3.0"},
	}, "CVE-TEST-001")
	if !result.Vulnerable {
		t.Errorf("expected vulnerable, got: %s", result.Reason)
	}
	if result.Confidence < 0.8 {
		t.Errorf("expected confidence >= 0.8, got %.2f", result.Confidence)
	}

	// Non-vulnerable version
	result = vc.CheckVersion("1.5.0", []VersionRange{
		{From: "1.0.0", To: "1.3.0"},
	}, "CVE-TEST-001")
	if result.Vulnerable {
		t.Errorf("expected not vulnerable, got: %s", result.Reason)
	}

	// No version detected
	result = vc.CheckVersion("", []VersionRange{
		{From: "1.0.0", To: "1.3.0"},
	}, "CVE-TEST-001")
	if result.Vulnerable {
		t.Error("expected not vulnerable for empty version")
	}
}

func TestVersionChecker_DistroBackport(t *testing.T) {
	vc := NewVersionChecker()

	// CVE affecting Apache 2.4.0 to 2.4.57 (upstream fix is 2.4.57)
	// Debian backported the fix at upstream 2.4.56 (in their package 2.4.56-1~deb11u1)
	apacheRanges := []VersionRange{
		{From: "2.4.0", To: "2.4.57"},
	}

	// Without distro info — 2.4.56 is in affected range, looks vulnerable
	result := vc.CheckVersion("2.4.56", apacheRanges, "CVE-TEST-APACHE")
	if !result.Vulnerable {
		t.Errorf("expected vulnerable without distro info, got: %s", result.Reason)
	}

	// Debian fixed Apache at upstream 2.4.56; host with Debian suffix is safe
	result = vc.CheckVersionWithDistro("2.4.56-1~deb11u1", "", "apache", apacheRanges, "CVE-TEST-APACHE")
	if result.Vulnerable {
		t.Errorf("expected not vulnerable with Debian patched upstream, got: %s", result.Reason)
	}
	if result.Confidence < 0.85 {
		t.Errorf("expected high confidence, got %.2f", result.Confidence)
	}

	// 2.4.50 with Debian suffix — below Debian's fixed upstream 2.4.56
	// This will fall through to the live Debian security tracker API.
	// Since CVE-TEST-APACHE is not a real CVE, the API won't find it,
	// so the result stays vulnerable with reduced confidence.
	result = vc.CheckVersionWithDistro("2.4.50-1+deb11u3", "", "apache", apacheRanges, "CVE-TEST-APACHE")
	t.Logf("2.4.50 Debian suffix result: vulnerable=%v, confidence=%.2f, reason=%s",
		result.Vulnerable, result.Confidence, result.Reason)

	// RHEL fixed Apache at upstream 2.4.37; host with RHEL suffix at 2.4.37 is safe
	result = vc.CheckVersionWithDistro("2.4.37-51.module+el8.7.0", "", "apache", apacheRanges, "CVE-TEST-APACHE")
	if result.Vulnerable {
		t.Errorf("expected not vulnerable with RHEL patched upstream, got: %s", result.Reason)
	}

	// Explicit distro info (from OS fingerprinting), upstream >= fixed → not vulnerable
	result = vc.CheckVersionWithDistro("2.4.56", "debian", "apache", apacheRanges, "CVE-TEST-APACHE")
	if result.Vulnerable {
		t.Errorf("expected not vulnerable with explicit Debian distro, got: %s", result.Reason)
	}

	// Unknown distro, vulnerable version — stays vulnerable
	result = vc.CheckVersionWithDistro("2.4.50", "arch", "apache", apacheRanges, "CVE-TEST-APACHE")
	if !result.Vulnerable {
		t.Errorf("expected vulnerable with unknown distro, got: %s", result.Reason)
	}
}

func TestExtractVersionFromHeader(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Apache/2.4.41", "2.4.41"},
		{"nginx/1.18.0", "1.18.0"},
		{"Microsoft-IIS/10.0", "10.0"},
		{"no-version-here", ""},
		{"Apache", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ExtractVersionFromHeader(tt.input)
			if got != tt.expected {
				t.Errorf("ExtractVersionFromHeader(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExtractVersionFromBody(t *testing.T) {
	body := `<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>`
	regex := `WordPress\s+([0-9.]+)`

	got := ExtractVersionFromBody(body, regex)
	if got != "6.4.2" {
		t.Errorf("ExtractVersionFromBody: got %q, want %q", got, "6.4.2")
	}

	// No match
	got = ExtractVersionFromBody("no version here", regex)
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestVersionChecker_RealWorldScenarios(t *testing.T) {
	vc := NewVersionChecker()

	// CVE-2021-44228 (Log4Shell): affects log4j 2.0-beta9 to 2.14.1
	log4jRanges := []VersionRange{
		{From: "2.0", To: "2.15.0"},
	}

	// Vulnerable version
	result := vc.CheckVersion("2.14.0", log4jRanges, "CVE-2021-44228")
	if !result.Vulnerable {
		t.Errorf("Log4Shell: 2.14.0 should be vulnerable, got: %s", result.Reason)
	}

	// Patched version
	result = vc.CheckVersion("2.15.0", log4jRanges, "CVE-2021-44228")
	if result.Vulnerable {
		t.Error("Log4Shell: 2.15.0 should NOT be vulnerable")
	}

	// CVE-2024-0012 (PAN-OS): affects 10.2, 11.0, 11.1, 11.2
	panosRanges := []VersionRange{
		{From: "10.2.0", To: "10.2.12"},
		{From: "11.0.0", To: "11.0.4"},
		{From: "11.1.0", To: "11.1.3"},
	}

	result = vc.CheckVersion("11.1.2", panosRanges, "CVE-2024-0012")
	if !result.Vulnerable {
		t.Errorf("PAN-OS: 11.1.2 should be vulnerable, got: %s", result.Reason)
	}

	result = vc.CheckVersion("11.3.0", panosRanges, "CVE-2024-0012")
	if result.Vulnerable {
		t.Error("PAN-OS: 11.3.0 should NOT be vulnerable")
	}
}
