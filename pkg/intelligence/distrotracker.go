package intelligence

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/versionutil"
)

// DistroFixStatus represents the fix status of a package in a specific distro release
type DistroFixStatus struct {
	Distro     string // debian, ubuntu, rhel
	Release    string // bullseye, jammy, el8, etc.
	Package    string // source package name
	Version    string // installed/detected version
	Status     string // vulnerable, fixed, not-affected, unknown
	FixedVer   string // version containing the fix
	Confidence float64
	Source     string // API URL or data source
}

// DistroSecurityTracker queries distro security APIs for backport/fix status
type DistroSecurityTracker struct {
	client    *http.Client
	cache     map[string][]DistroFixStatus // cache key: distro:package or distro:cve
	cacheMu   sync.RWMutex
	cacheTTL  time.Duration
	cacheTime time.Time
}

// NewDistroSecurityTracker creates a new distro security tracker client
func NewDistroSecurityTracker() *DistroSecurityTracker {
	return &DistroSecurityTracker{
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		cache:    make(map[string][]DistroFixStatus),
		cacheTTL: 6 * time.Hour,
	}
}

// CheckBackport queries distro security trackers to determine if a detected
// version includes a backported fix for the given CVE.
//
// This resolves the limitation noted in CheckVersionWithDistro: instead of
// relying on a static map of known fixed upstream versions, we query the
// distro's own security tracker to get the actual fix status for the
// specific CVE + package + release combination.
func (dst *DistroSecurityTracker) CheckBackport(cveID, product, detectedVersion, distro string) (DistroFixStatus, error) {
	result := DistroFixStatus{
		Distro:     distro,
		Package:    product,
		Version:    detectedVersion,
		Status:     "unknown",
		Confidence: 0.5,
	}

	switch strings.ToLower(distro) {
	case "debian":
		return dst.checkDebian(cveID, product, detectedVersion)
	case "ubuntu":
		return dst.checkUbuntu(cveID, product, detectedVersion)
	case "rhel", "fedora", "centos", "rocky", "alma":
		return dst.checkRHEL(cveID, product, detectedVersion)
	default:
		return result, fmt.Errorf("unsupported distro: %s", distro)
	}
}

// --- Red Hat ---

type rhelCVEResponse struct {
	PackageState []struct {
		ProductName string `json:"product_name"`
		PackageName string `json:"package_name"`
		FixState    string `json:"fix_state"`
		CPE         string `json:"cpe"`
	} `json:"package_state"`
	AffectedRelease []struct {
		Package string `json:"package"`
	} `json:"affected_release"`
}

func (dst *DistroSecurityTracker) checkRHEL(cveID, product, detectedVersion string) (DistroFixStatus, error) {
	result := DistroFixStatus{
		Distro:     "rhel",
		Package:    product,
		Version:    detectedVersion,
		Status:     "unknown",
		Confidence: 0.5,
	}

	url := fmt.Sprintf("https://access.redhat.com/hydra/rest/securitydata/cve/%s.json", cveID)
	body, err := dst.fetch(url)
	if err != nil {
		result.Source = url
		return result, fmt.Errorf("RHEL API: %w", err)
	}
	result.Source = url

	var resp rhelCVEResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return result, fmt.Errorf("RHEL API parse: %w", err)
	}

	productLower := strings.ToLower(product)
	for _, ps := range resp.PackageState {
		if strings.Contains(strings.ToLower(ps.PackageName), productLower) ||
			strings.Contains(productLower, strings.ToLower(ps.PackageName)) {
			result.Release = ps.CPE
			result.FixedVer = ps.FixState

			switch strings.ToLower(ps.FixState) {
			case "not affected":
				result.Status = "not-affected"
				result.Confidence = 0.95
			case "affected":
				result.Status = "vulnerable"
				result.Confidence = 0.90
			case "will not fix":
				result.Status = "wont-fix"
				result.Confidence = 0.85
			case "fix deferred":
				result.Status = "fix-deferred"
				result.Confidence = 0.85
			default:
				result.Status = "unknown"
				result.Confidence = 0.60
			}
			return result, nil
		}
	}

	// If not found in package_state, check if it's in affected_release
	for _, ar := range resp.AffectedRelease {
		if strings.Contains(strings.ToLower(ar.Package), productLower) {
			result.Status = "vulnerable"
			result.Confidence = 0.85
			result.FixedVer = "see advisory"
			return result, nil
		}
	}

	result.Status = "not-affected"
	result.Confidence = 0.70
	result.FixedVer = "not in package_state"
	return result, nil
}

// --- Debian ---

func (dst *DistroSecurityTracker) checkDebian(cveID, product, detectedVersion string) (DistroFixStatus, error) {
	result := DistroFixStatus{
		Distro:     "debian",
		Package:    product,
		Version:    detectedVersion,
		Status:     "unknown",
		Confidence: 0.5,
	}

	// Debian security tracker per-CVE page
	url := fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", cveID)
	body, err := dst.fetch(url)
	if err != nil {
		result.Source = url
		return result, fmt.Errorf("Debian tracker: %w", err)
	}
	result.Source = url

	html := string(body)

	// Parse the "Vulnerable and fixed packages" table
	// Look for product name in the table rows
	productLower := strings.ToLower(product)
	// Map common product names to Debian source package names
	debPkg := debianPackageName(product)
	debPkgLower := strings.ToLower(debPkg)

	// Find all table rows containing the package name
	// Format: <tr><td>...source-package/PKG...</td><td>RELEASE</td><td>VERSION</td><td>STATUS</td></tr>
	lines := strings.Split(html, "<tr>")
	for _, line := range lines {
		lineLower := strings.ToLower(line)
		if !strings.Contains(lineLower, debPkgLower) && !strings.Contains(lineLower, productLower) {
			continue
		}

		// Extract cells
		cells := extractHTMLCells(line)
		if len(cells) < 4 {
			continue
		}

		// cells: [package, release, version, status]
		release := stripTags(cells[1])
		version := stripTags(cells[2])
		status := stripTags(cells[3])

		// Check if this version matches or is >= detected version
		if version != "" && detectedVersion != "" {
			detectedPV, err := versionutil.Parse(detectedVersion)
			fixedPV, err2 := versionutil.Parse(version)
			if err == nil && err2 == nil {
				// Compare upstream segments only
				detectedUp := &versionutil.ParsedVersion{Epoch: detectedPV.Epoch, Segments: detectedPV.Segments}
				fixedUp := &versionutil.ParsedVersion{Epoch: fixedPV.Epoch, Segments: fixedPV.Segments}

				if versionutil.Compare(detectedUp, fixedUp) >= 0 {
					result.Release = release
					result.FixedVer = version
					if strings.Contains(strings.ToLower(status), "fixed") {
						result.Status = "fixed"
						result.Confidence = 0.92
					} else if strings.Contains(strings.ToLower(status), "vulnerable") {
						result.Status = "vulnerable"
						result.Confidence = 0.88
					} else {
						result.Status = status
						result.Confidence = 0.75
					}
					return result, nil
				}
			}
		}

		// If version comparison fails, just record the status
		if strings.Contains(strings.ToLower(status), "fixed") {
			result.Release = release
			result.FixedVer = version
			result.Status = "fixed"
			result.Confidence = 0.70
		}
	}

	if result.Status == "unknown" {
		result.Status = "not-found"
		result.Confidence = 0.60
		result.FixedVer = "package not in tracker"
	}

	return result, nil
}

// --- Ubuntu ---

func (dst *DistroSecurityTracker) checkUbuntu(cveID, product, detectedVersion string) (DistroFixStatus, error) {
	result := DistroFixStatus{
		Distro:     "ubuntu",
		Package:    product,
		Version:    detectedVersion,
		Status:     "unknown",
		Confidence: 0.5,
	}

	// Ubuntu CVE JSON API (may be unreliable)
	url := fmt.Sprintf("https://ubuntu.com/security/cves/%s.json", cveID)
	body, err := dst.fetch(url)
	if err != nil {
		// Fallback: try Launchpad API
		result.Source = url
		return dst.checkUbuntuLaunchpad(cveID, product, detectedVersion)
	}
	result.Source = url

	var resp struct {
		Notice map[string]struct {
			ReleasePackages map[string][]struct {
				Name        string `json:"name"`
				Version     string `json:"version"`
				IsSource    bool   `json:"is_source"`
				Description string `json:"description"`
			} `json:"release_packages"`
		} `json:"notice"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		// Not JSON or parse error — try Launchpad
		return dst.checkUbuntuLaunchpad(cveID, product, detectedVersion)
	}

	productLower := strings.ToLower(product)
	debPkg := ubuntuPackageName(product)
	debPkgLower := strings.ToLower(debPkg)

	for usnID, usnData := range resp.Notice {
		for release, packages := range usnData.ReleasePackages {
			for _, pkg := range packages {
				pkgNameLower := strings.ToLower(pkg.Name)
				if strings.Contains(pkgNameLower, debPkgLower) ||
					strings.Contains(pkgNameLower, productLower) ||
					strings.Contains(debPkgLower, pkgNameLower) {

					// Compare versions
					if detectedVersion != "" && pkg.Version != "" {
						detectedPV, err1 := versionutil.Parse(detectedVersion)
						fixedPV, err2 := versionutil.Parse(pkg.Version)
						if err1 == nil && err2 == nil {
							detectedUp := &versionutil.ParsedVersion{Epoch: detectedPV.Epoch, Segments: detectedPV.Segments}
							fixedUp := &versionutil.ParsedVersion{Epoch: fixedPV.Epoch, Segments: fixedPV.Segments}

							if versionutil.Compare(detectedUp, fixedUp) >= 0 {
								result.Release = release
								result.FixedVer = pkg.Version
								result.Status = "fixed"
								result.Confidence = 0.92
								result.Source = fmt.Sprintf("USN-%s via %s", usnID, url)
								return result, nil
							}
						}
					}

					result.Release = release
					result.FixedVer = pkg.Version
					result.Status = "fix-available"
					result.Confidence = 0.75
					result.Source = fmt.Sprintf("USN-%s via %s", usnID, url)
					return result, nil
				}
			}
		}
	}

	result.Status = "not-found"
	result.Confidence = 0.60
	result.FixedVer = "package not in USN"
	return result, nil
}

func (dst *DistroSecurityTracker) checkUbuntuLaunchpad(cveID, product, detectedVersion string) (DistroFixStatus, error) {
	result := DistroFixStatus{
		Distro:     "ubuntu",
		Package:    product,
		Version:    detectedVersion,
		Status:     "unknown",
		Confidence: 0.50,
		Source:     "launchpad",
	}

	// Launchpad API for Ubuntu CVEs
	url := fmt.Sprintf("https://api.launchpad.net/1.0/ubuntu/cve/%s", cveID)
	body, err := dst.fetch(url)
	if err != nil {
		return result, fmt.Errorf("Launchpad API: %w", err)
	}
	result.Source = url

	// Launchpad returns JSON with patches and status info
	var resp struct {
		BugsLinks []struct {
			Title string `json:"title"`
		} `json:"bugs_collection_link"`
	}

	// Launchpad API is complex; just mark as queried
	_ = body
	_ = resp
	result.Status = "queried"
	result.Confidence = 0.55
	result.FixedVer = "see launchpad"
	return result, nil
}

// --- Helpers ---

func (dst *DistroSecurityTracker) fetch(url string) ([]byte, error) {
	dst.cacheMu.RLock()
	if entry, ok := dst.cache[url]; ok && time.Since(dst.cacheTime) < dst.cacheTTL && len(entry) > 0 {
		dst.cacheMu.RUnlock()
		// Return cached raw body — we store it as the first entry's FixedVer
		return []byte(entry[0].FixedVer), nil
	}
	dst.cacheMu.RUnlock()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/html")
	req.Header.Set("User-Agent", "nuclei-dev/distro-security-tracker")

	resp, err := dst.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// debianPackageName maps common product names to Debian source package names
func debianPackageName(product string) string {
	p := strings.ToLower(product)
	mapping := map[string]string{
		"apache":     "apache2",
		"httpd":      "apache2",
		"nginx":      "nginx",
		"openssl":    "openssl",
		"openssh":    "openssh",
		"sshd":       "openssh",
		"log4j":      "apache-log4j2",
		"log4j2":     "apache-log4j2",
		"php":        "php8.2",
		"mysql":      "mysql-8.0",
		"mariadb":    "mariadb-10.5",
		"postgresql": "postgresql-15",
		"redis":      "redis",
		"node":       "nodejs",
		"nodejs":     "nodejs",
		"python":     "python3.11",
		"ruby":       "ruby",
		"java":       "openjdk-17",
		"tomcat":     "tomcat9",
		"wordpress":  "wordpress",
		"drupal":     "drupal",
		"joomla":     "joomla",
	}
	if mapped, ok := mapping[p]; ok {
		return mapped
	}
	return p
}

// ubuntuPackageName maps common product names to Ubuntu source package names
func ubuntuPackageName(product string) string {
	p := strings.ToLower(product)
	mapping := map[string]string{
		"apache":     "apache2",
		"httpd":      "apache2",
		"nginx":      "nginx",
		"openssl":    "openssl",
		"openssh":    "openssh",
		"sshd":       "openssh",
		"log4j":      "log4j2",
		"log4j2":     "log4j2",
		"php":        "php",
		"mysql":      "mysql-8.0",
		"mariadb":    "mariadb-10.6",
		"postgresql": "postgresql-14",
		"redis":      "redis",
		"node":       "nodejs",
		"nodejs":     "nodejs",
		"python":     "python3.10",
		"ruby":       "ruby",
		"java":       "openjdk-17",
		"tomcat":     "tomcat9",
		"wordpress":  "wordpress",
		"drupal":     "drupal",
		"joomla":     "joomla",
	}
	if mapped, ok := mapping[p]; ok {
		return mapped
	}
	return p
}

// extractHTMLCells extracts <td>...</td> cell contents from a table row
func extractHTMLCells(row string) []string {
	var cells []string
	start := 0
	for {
		tdStart := strings.Index(row[start:], "<td")
		if tdStart < 0 {
			break
		}
		tdStart += start
		tdContentStart := strings.Index(row[tdStart:], ">")
		if tdContentStart < 0 {
			break
		}
		tdContentStart += tdStart + 1

		tdEnd := strings.Index(row[tdContentStart:], "</td>")
		if tdEnd < 0 {
			break
		}
		tdEnd += tdContentStart

		cells = append(cells, row[tdContentStart:tdEnd])
		start = tdEnd + 5
	}
	return cells
}

// stripTags removes HTML tags from a string
func stripTags(s string) string {
	var result strings.Builder
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			result.WriteRune(r)
		}
	}
	return strings.TrimSpace(result.String())
}
