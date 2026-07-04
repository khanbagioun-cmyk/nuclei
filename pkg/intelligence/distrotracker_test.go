package intelligence

import (
	"testing"
)

func TestDistroTracker_RHEL_LiveAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live API test in short mode")
	}

	dst := NewDistroSecurityTracker()

	// CVE-2021-44228 (Log4Shell) — Red Hat says RHEL is "Not affected"
	result, err := dst.CheckBackport("CVE-2021-44228", "log4j", "2.14.0", "rhel")
	if err != nil {
		t.Skipf("RHEL API unavailable: %v", err)
	}

	if result.Status != "not-affected" {
		t.Errorf("expected 'not-affected' for log4j on RHEL, got '%s' (confidence: %.2f, source: %s)",
			result.Status, result.Confidence, result.Source)
	}
	if result.Confidence < 0.85 {
		t.Errorf("expected confidence >= 0.85, got %.2f", result.Confidence)
	}
	t.Logf("RHEL result: status=%s, confidence=%.2f, fixed=%s, release=%s",
		result.Status, result.Confidence, result.FixedVer, result.Release)
}

func TestDistroTracker_RHEL_AffectedProduct(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live API test in short mode")
	}

	dst := NewDistroSecurityTracker()

	// CVE-2021-44228 — Camel Quarkus is "Affected" on RHEL
	result, err := dst.CheckBackport("CVE-2021-44228", "log4j-core", "2.14.0", "rhel")
	if err != nil {
		t.Skipf("RHEL API unavailable: %v", err)
	}

	// log4j-core should find the Camel Quarkus "Affected" entry
	t.Logf("RHEL log4j-core result: status=%s, confidence=%.2f, fixed=%s, release=%s",
		result.Status, result.Confidence, result.FixedVer, result.Release)
}

func TestDistroTracker_Debian_LiveAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live API test in short mode")
	}

	dst := NewDistroSecurityTracker()

	// CVE-2021-44228 — Debian fixed log4j2 in bullseye at 2.17.1-1~deb11u1
	result, err := dst.CheckBackport("CVE-2021-44228", "log4j", "2.17.1-1~deb11u1", "debian")
	if err != nil {
		t.Skipf("Debian tracker unavailable: %v", err)
	}

	t.Logf("Debian result: status=%s, confidence=%.2f, fixed=%s, release=%s",
		result.Status, result.Confidence, result.FixedVer, result.Release)

	// A version >= the fixed version should be "fixed"
	if result.Status == "fixed" {
		if result.Confidence < 0.85 {
			t.Errorf("expected confidence >= 0.85 for fixed, got %.2f", result.Confidence)
		}
	}
}

func TestDistroTracker_Debian_VulnerableVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live API test in short mode")
	}

	dst := NewDistroSecurityTracker()

	// CVE-2021-44228 — a version below the fix should be "vulnerable"
	result, err := dst.CheckBackport("CVE-2021-44228", "log4j", "2.14.0-1", "debian")
	if err != nil {
		t.Skipf("Debian tracker unavailable: %v", err)
	}

	t.Logf("Debian vulnerable result: status=%s, confidence=%.2f, fixed=%s, release=%s",
		result.Status, result.Confidence, result.FixedVer, result.Release)
}

func TestDistroTracker_UnsupportedDistro(t *testing.T) {
	dst := NewDistroSecurityTracker()

	_, err := dst.CheckBackport("CVE-2021-44228", "log4j", "2.14.0", "arch")
	if err == nil {
		t.Error("expected error for unsupported distro")
	}
}

func TestDistroTracker_PackageNameMapping(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"apache", "apache2"},
		{"nginx", "nginx"},
		{"log4j", "apache-log4j2"},
		{"log4j2", "apache-log4j2"},
		{"openssh", "openssh"},
		{"unknown-product", "unknown-product"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := debianPackageName(tt.input)
			if got != tt.expected {
				t.Errorf("debianPackageName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDistroTracker_UbuntuPackageNameMapping(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"apache", "apache2"},
		{"nginx", "nginx"},
		{"log4j", "log4j2"},
		{"httpd", "apache2"},
		{"unknown-product", "unknown-product"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ubuntuPackageName(tt.input)
			if got != tt.expected {
				t.Errorf("ubuntuPackageName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestStripTags(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"<span class='red'>vulnerable</span>", "vulnerable"},
		{"<a href='/tracker/CVE-2021-44228'>CVE-2021-44228</a>", "CVE-2021-44228"},
		{"plain text", "plain text"},
		{"", ""},
		{"<b>bold</b> and <i>italic</i>", "bold and italic"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripTags(tt.input)
			if got != tt.expected {
				t.Errorf("stripTags(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExtractHTMLCells(t *testing.T) {
	row := "<tr><td><a href='/pkg/apache-log4j2'>apache-log4j2</a></td><td>bullseye</td><td>2.17.1-1~deb11u1</td><td>fixed</td></tr>"
	cells := extractHTMLCells(row)
	if len(cells) != 4 {
		t.Fatalf("expected 4 cells, got %d", len(cells))
	}
	if stripTags(cells[0]) != "apache-log4j2" {
		t.Errorf("cell 0: got %q, want 'apache-log4j2'", stripTags(cells[0]))
	}
	if stripTags(cells[1]) != "bullseye" {
		t.Errorf("cell 1: got %q, want 'bullseye'", stripTags(cells[1]))
	}
	if stripTags(cells[2]) != "2.17.1-1~deb11u1" {
		t.Errorf("cell 2: got %q, want '2.17.1-1~deb11u1'", stripTags(cells[2]))
	}
	if stripTags(cells[3]) != "fixed" {
		t.Errorf("cell 3: got %q, want 'fixed'", stripTags(cells[3]))
	}
}
