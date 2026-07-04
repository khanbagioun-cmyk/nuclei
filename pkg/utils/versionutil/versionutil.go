// Package versionutil provides version parsing and comparison utilities.
// It is deliberately dependency-free to avoid import cycles when used from DSL.
package versionutil

import (
	"fmt"
	"regexp"
	"strings"
)

// ParsedVersion represents a parsed semantic version
type ParsedVersion struct {
	Epoch    int
	Segments []int
	Pre      string
	Build    string
	Distro   string
	Raw      string
}

// versionRegex parses versions like: 1.2.3, 1:2.0-1.el9, 1.2.3-ubuntu4, 5.5.15+deb11, 1.2.3-rc1
var versionRegex = regexp.MustCompile(`^(?:(\d+):)?(\d+(?:\.\d+)*)(?:[-+~]([a-zA-Z0-9.~+]+))?(?:-([a-z]+\d+))?$`)

// Parse parses a version string into structured components.
func Parse(s string) (*ParsedVersion, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty version string")
	}

	pv := &ParsedVersion{Raw: s}

	// Extract distro suffix if present (e.g., -1.el9, -1ubuntu4, +deb11)
	distroSuffix := ""
	if idx := strings.IndexAny(s, "+~"); idx > 0 {
		distroSuffix = s[idx:]
		s = s[:idx]
	} else if parts := strings.SplitN(s, "-", 2); len(parts) == 2 {
		distroPart := parts[1]
		if IsDistroSuffix(distroPart) {
			distroSuffix = "-" + distroPart
			s = parts[0]
		}
	}
	pv.Distro = distroSuffix

	// Parse epoch
	if idx := strings.Index(s, ":"); idx > 0 {
		var epoch int
		fmt.Sscanf(s[:idx], "%d", &epoch)
		pv.Epoch = epoch
		s = s[idx+1:]
	}

	// Parse pre-release / build metadata
	if idx := strings.IndexAny(s, "-+~"); idx > 0 {
		pv.Pre = s[idx+1:]
		s = s[:idx]
	}

	// Parse version segments
	segStrs := strings.Split(s, ".")
	for _, seg := range segStrs {
		var n int
		fmt.Sscanf(seg, "%d", &n)
		pv.Segments = append(pv.Segments, n)
	}

	if len(pv.Segments) == 0 {
		return nil, fmt.Errorf("no version segments found in '%s'", s)
	}

	return pv, nil
}

// IsDistroSuffix checks if a suffix looks like a distro-specific package revision.
func IsDistroSuffix(s string) bool {
	s = strings.ToLower(s)
	if strings.Contains(s, "el") {
		return true
	}
	if strings.Contains(s, "fc") {
		return true
	}
	if strings.Contains(s, "ubuntu") {
		return true
	}
	if strings.Contains(s, "deb") {
		return true
	}
	if strings.Contains(s, "suse") || strings.Contains(s, "sles") {
		return true
	}
	if strings.Contains(s, "amzn") {
		return true
	}
	if strings.Contains(s, "arch") {
		return true
	}
	if strings.Contains(s, "alpine") {
		return true
	}
	return false
}

// Compare compares two parsed versions.
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
func Compare(a, b *ParsedVersion) int {
	if a.Epoch != b.Epoch {
		if a.Epoch < b.Epoch {
			return -1
		}
		return 1
	}

	maxLen := len(a.Segments)
	if len(b.Segments) > maxLen {
		maxLen = len(b.Segments)
	}

	for i := 0; i < maxLen; i++ {
		var aSeg, bSeg int
		if i < len(a.Segments) {
			aSeg = a.Segments[i]
		}
		if i < len(b.Segments) {
			bSeg = b.Segments[i]
		}
		if aSeg < bSeg {
			return -1
		}
		if aSeg > bSeg {
			return 1
		}
	}

	if a.Pre == "" && b.Pre != "" {
		return 1
	}
	if a.Pre != "" && b.Pre == "" {
		return -1
	}
	if a.Pre != b.Pre {
		if a.Pre < b.Pre {
			return -1
		}
		return 1
	}

	return 0
}

// CompareStrings is a convenience function that parses and compares two version strings.
func CompareStrings(a, b string) int {
	pa, err := Parse(a)
	if err != nil {
		return -2
	}
	pb, err := Parse(b)
	if err != nil {
		return -2
	}
	return Compare(pa, pb)
}

// InRange checks if a version falls within [from, to).
func InRange(v, from, to *ParsedVersion) bool {
	if from != nil && Compare(v, from) < 0 {
		return false
	}
	if to != nil && Compare(v, to) >= 0 {
		return false
	}
	return true
}

// InRangeStrings checks if a version string falls within [from, to).
func InRangeStrings(version, from, to string) bool {
	v, err := Parse(version)
	if err != nil {
		return false
	}
	var fromPV, toPV *ParsedVersion
	if from != "" {
		fromPV, _ = Parse(from)
	}
	if to != "" {
		toPV, _ = Parse(to)
	}
	return InRange(v, fromPV, toPV)
}

// IdentifyDistroFromSuffix maps a version suffix to a distro name.
func IdentifyDistroFromSuffix(suffix string) string {
	suffix = strings.ToLower(suffix)
	if strings.Contains(suffix, "ubuntu") {
		return "ubuntu"
	}
	if strings.Contains(suffix, "deb") {
		return "debian"
	}
	if strings.Contains(suffix, "el") {
		return "rhel"
	}
	if strings.Contains(suffix, "fc") {
		return "fedora"
	}
	if strings.Contains(suffix, "amzn") {
		return "amazon"
	}
	if strings.Contains(suffix, "suse") || strings.Contains(suffix, "sles") {
		return "suse"
	}
	return ""
}
