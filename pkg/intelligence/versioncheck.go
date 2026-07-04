package intelligence

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/versionutil"
)

// VersionCheckResult represents the outcome of a version vulnerability check
type VersionCheckResult struct {
	CVEID      string
	Detected   string
	Vulnerable bool
	Confidence float64
	Reason     string
}

// VersionChecker compares detected versions against CVE affected ranges
type VersionChecker struct {
	distroFixTracker map[string]map[string]string
	securityTracker  *DistroSecurityTracker
}

// NewVersionChecker creates a version checker
func NewVersionChecker() *VersionChecker {
	return &VersionChecker{
		distroFixTracker: getDefaultDistroFixes(),
		securityTracker:  NewDistroSecurityTracker(),
	}
}

// CheckVersion compares a detected version against CVE affected ranges
func (vc *VersionChecker) CheckVersion(detected string, ranges []VersionRange, cveID string) VersionCheckResult {
	result := VersionCheckResult{
		CVEID:      cveID,
		Detected:   detected,
		Confidence: 0.5,
	}

	if detected == "" {
		result.Reason = "no version detected"
		return result
	}

	parsedDetected, err := versionutil.Parse(detected)
	if err != nil {
		result.Reason = fmt.Sprintf("unparseable version '%s': %v", detected, err)
		return result
	}

	for _, vr := range ranges {
		var fromPV, toPV *versionutil.ParsedVersion
		if vr.From != "" {
			fromPV, _ = versionutil.Parse(vr.From)
		}
		if vr.To != "" {
			toPV, _ = versionutil.Parse(vr.To)
		}
		if versionutil.InRange(parsedDetected, fromPV, toPV) {
			result.Vulnerable = true
			result.Confidence = 0.85
			result.Reason = fmt.Sprintf("version %s is in affected range [%s, %s)", detected, vr.From, vr.To)
			return result
		}
	}

	result.Vulnerable = false
	result.Confidence = 0.75
	result.Reason = fmt.Sprintf("version %s is outside all affected ranges", detected)
	return result
}

// CheckVersionWithDistro checks version accounting for distro-specific backported fixes.
// It first checks the static fix map, then falls back to querying the distro's live
// security tracker API (Red Hat, Debian, Ubuntu) for accurate backport status.
func (vc *VersionChecker) CheckVersionWithDistro(detected, distro, product string, ranges []VersionRange, cveID string) VersionCheckResult {
	result := vc.CheckVersion(detected, ranges, cveID)

	if !result.Vulnerable {
		return result
	}

	parsedDetected, err := versionutil.Parse(detected)
	if err != nil {
		return result
	}

	// Determine the distro from the version suffix or from the explicit parameter
	effectiveDistro := distro
	if parsedDetected.Distro != "" {
		if suffixDistro := versionutil.IdentifyDistroFromSuffix(parsedDetected.Distro); suffixDistro != "" {
			effectiveDistro = suffixDistro
		}
	}

	if effectiveDistro == "" {
		return result
	}

	// Step 1: Check static fix map (fast, no network)
	staticResolved := false
	if fixes, ok := vc.distroFixTracker[effectiveDistro]; ok {
		if fixedUpstream, ok := fixes[strings.ToLower(product)]; ok {
			parsedFixed, err := versionutil.Parse(fixedUpstream)
			if err == nil {
				detectedUpstream := &versionutil.ParsedVersion{
					Epoch:    parsedDetected.Epoch,
					Segments: parsedDetected.Segments,
				}
				fixedUpstreamParsed := &versionutil.ParsedVersion{
					Epoch:    parsedFixed.Epoch,
					Segments: parsedFixed.Segments,
				}

				if versionutil.Compare(detectedUpstream, fixedUpstreamParsed) >= 0 {
					result.Vulnerable = false
					result.Confidence = 0.88
					result.Reason = fmt.Sprintf("upstream version %s matches %s fixed upstream %s (patched release)",
						detected, effectiveDistro, fixedUpstream)
					staticResolved = true
				} else {
					result.Confidence = 0.80
					result.Reason = fmt.Sprintf("version %s is below %s fixed upstream %s (checking live tracker)",
						detected, effectiveDistro, fixedUpstream)
				}
			}
		}
	}

	if staticResolved {
		return result
	}

	// Step 2: Query live distro security tracker API for accurate backport status
	if vc.securityTracker != nil && cveID != "" {
		fixStatus, err := vc.securityTracker.CheckBackport(cveID, product, detected, effectiveDistro)
		if err == nil {
			switch fixStatus.Status {
			case "not-affected":
				result.Vulnerable = false
				result.Confidence = fixStatus.Confidence
				result.Reason = fmt.Sprintf("%s security tracker: %s is not affected (via %s)",
					effectiveDistro, product, fixStatus.Source)
			case "fixed":
				result.Vulnerable = false
				result.Confidence = fixStatus.Confidence
				result.Reason = fmt.Sprintf("%s security tracker: version %s includes fix (fixed in %s, via %s)",
					effectiveDistro, detected, fixStatus.FixedVer, fixStatus.Source)
			case "vulnerable":
				result.Vulnerable = true
				result.Confidence = fixStatus.Confidence
				result.Reason = fmt.Sprintf("%s security tracker: version %s is vulnerable (via %s)",
					effectiveDistro, detected, fixStatus.Source)
			case "wont-fix", "fix-deferred":
				result.Vulnerable = true
				result.Confidence = fixStatus.Confidence
				result.Reason = fmt.Sprintf("%s security tracker: %s (%s, via %s)",
					effectiveDistro, fixStatus.Status, product, fixStatus.Source)
			}
		}
	}

	return result
}

// getDefaultDistroFixes returns known fixed upstream versions for common distros.
// These are the upstream versions at which each distro applied the security patch;
// the actual package revision (e.g., -1ubuntu0.1) is not stored, only the upstream
// version for comparison against detected upstream versions.
func getDefaultDistroFixes() map[string]map[string]string {
	return map[string]map[string]string{
		"debian": {
			"openssl": "1.1.1n",
			"log4j":   "2.17.1",
			"apache":  "2.4.56",
			"nginx":   "1.18.0",
			"openssh": "8.4p1",
		},
		"ubuntu": {
			"openssl": "1.1.1f",
			"log4j":   "2.17.1",
			"apache":  "2.4.41",
			"nginx":   "1.18.0",
			"openssh": "8.2p1",
		},
		"rhel": {
			"openssl": "1.1.1k",
			"log4j":   "2.17.1",
			"apache":  "2.4.37",
			"nginx":   "1.20.1",
			"openssh": "8.0p1",
		},
	}
}

// ExtractVersionFromHeader extracts a version from an HTTP header value
// e.g., "Server: Apache/2.4.41" -> "2.4.41"
func ExtractVersionFromHeader(headerValue string) string {
	if idx := strings.Index(headerValue, "/"); idx >= 0 {
		ver := strings.TrimSpace(headerValue[idx+1:])
		ver = strings.TrimRight(ver, " \t\r\n")
		return ver
	}
	return ""
}

// ExtractVersionFromBody extracts a version from response body using a regex
func ExtractVersionFromBody(body string, versionRegex string) string {
	re, err := regexp.Compile(versionRegex)
	if err != nil {
		return ""
	}
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// CheckBelowSafeVersion checks if a detected version is below the known safe
// version for a product on a given distro. This is useful when no CVE ranges
// are available — it flags any version older than the distro's patched version.
func (vc *VersionChecker) CheckBelowSafeVersion(detected, distro, product string) VersionCheckResult {
	result := VersionCheckResult{
		CVEID:      "",
		Detected:   detected,
		Confidence: 0.5,
	}

	if detected == "" {
		result.Reason = "no version detected"
		return result
	}

	parsedDetected, err := versionutil.Parse(detected)
	if err != nil {
		result.Reason = fmt.Sprintf("unparseable version '%s': %v", detected, err)
		return result
	}

	if fixes, ok := vc.distroFixTracker[distro]; ok {
		if fixedVersion, ok := fixes[strings.ToLower(product)]; ok {
			parsedFixed, err := versionutil.Parse(fixedVersion)
			if err != nil {
				result.Reason = fmt.Sprintf("could not parse safe version '%s': %v", fixedVersion, err)
				return result
			}
			detectedUpstream := &versionutil.ParsedVersion{
				Epoch:    parsedDetected.Epoch,
				Segments: parsedDetected.Segments,
			}
			if versionutil.Compare(detectedUpstream, parsedFixed) < 0 {
				result.Vulnerable = true
				result.Confidence = 0.7
				result.Reason = fmt.Sprintf("version %s is below %s safe version %s on %s", detected, product, fixedVersion, distro)
				return result
			}
			result.Vulnerable = false
			result.Confidence = 0.8
			result.Reason = fmt.Sprintf("version %s is at or above %s safe version %s on %s", detected, product, fixedVersion, distro)
			return result
		}
	}

	result.Reason = fmt.Sprintf("no safe version known for %s on %s", product, distro)
	return result
}
