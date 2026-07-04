package intelligence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ScanProfile is a curated scan profile that bundles nuclei flags
// for a specific scanning scenario (e.g., critical CVE sweep, quick KEV)
type ScanProfile struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Severity    []string `json:"severity"`
	Protocols   []string `json:"protocols"`
	ExtraArgs   []string `json:"extra_args"`
	ProfileOnly bool     `json:"profile_only"`
	SkipDAST    bool     `json:"skip_dast"`
	SkipWorkflows bool   `json:"skip_workflows"`
}

// BuiltInProfiles returns curated profiles for common scanning scenarios
func BuiltInProfiles() []ScanProfile {
	return []ScanProfile{
		{
			Name:        "critical-cve-sweep",
			Description: "Focus on critical CVEs: KEV, VKEV, exploit, and high-severity CVE templates only",
			Tags:        []string{"kev,vkev,exploit,cve"},
			Severity:    []string{"critical", "high"},
			Protocols:   []string{"http"},
			ExtraArgs:   []string{},
			ProfileOnly: false,
			SkipDAST:    true,
			SkipWorkflows: false,
		},
		{
			Name:        "quick-kev-sweep",
			Description: "Fast scan: only CISA KEV + VulnCheck KEV tagged templates, no DAST, no workflows",
			Tags:        []string{"kev,vkev"},
			Severity:    []string{"critical", "high", "medium"},
			Protocols:   []string{"http"},
			ExtraArgs:   []string{},
			ProfileOnly: false,
			SkipDAST:    true,
			SkipWorkflows: true,
		},
		{
			Name:        "full-exposure-audit",
			Description: "Comprehensive exposure audit: all exposure, misconfig, and config templates",
			Tags:        []string{"exposure,misconfig,config"},
			Severity:    []string{"critical", "high", "medium", "low", "info"},
			Protocols:   []string{"http"},
			ExtraArgs:   []string{},
			ProfileOnly: false,
			SkipDAST:    false,
			SkipWorkflows: false,
		},
		{
			Name:        "wordpress-deep",
			Description: "WordPress-specific deep scan: wp-plugin, wp-theme, wordpress tags + DAST + workflows",
			Tags:        []string{"wordpress,wp-plugin,wp-theme,wp"},
			Severity:    []string{"critical", "high", "medium", "low"},
			Protocols:   []string{"http"},
			ExtraArgs:   []string{},
			ProfileOnly: false,
			SkipDAST:    false,
			SkipWorkflows: true,
		},
		{
			Name:        "tech-discovery-only",
			Description: "Phase 1 only: rapid tech detection, no vulnerability scanning",
			Tags:        []string{"tech,discovery,technologies"},
			Severity:    []string{"info"},
			Protocols:   []string{"http"},
			ExtraArgs:   []string{},
			ProfileOnly: true,
			SkipDAST:    true,
			SkipWorkflows: true,
		},
		{
			Name:        "dast-injection",
			Description: "DAST-only: run fuzzing/injection templates against discovered endpoints",
			Tags:        []string{},
			Severity:    []string{"critical", "high", "medium", "low"},
			Protocols:   []string{"http"},
			ExtraArgs:   []string{"-dast"},
			ProfileOnly: false,
			SkipDAST:    false,
			SkipWorkflows: true,
		},
	}
}

// GetProfileByName looks up a built-in profile by name
func GetProfileByName(name string) (*ScanProfile, error) {
	for _, p := range BuiltInProfiles() {
		if p.Name == name {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("profile '%s' not found", name)
}

// SaveProfile writes a scan profile to a JSON file
func SaveProfile(profile *ScanProfile, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadProfile reads a scan profile from a JSON file
func LoadProfile(path string) (*ScanProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p ScanProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ToSmartChainArgs converts a scan profile to smartchain CLI arguments
func (p *ScanProfile) ToSmartChainArgs() []string {
	var args []string

	if p.ProfileOnly {
		args = append(args, "-profile-only")
		return args
	}

	if len(p.Tags) > 0 {
		// Join tags as comma-separated
		args = append(args, "-tags", joinStrings(p.Tags, ","))
	}
	if len(p.Severity) > 0 {
		args = append(args, "-sv", joinStrings(p.Severity, ","))
	}
	if p.SkipDAST {
		args = append(args, "-dast=false")
	}
	if p.SkipWorkflows {
		args = append(args, "-workflows=false")
	}
	args = append(args, p.ExtraArgs...)

	return args
}

func joinStrings(s []string, sep string) string {
	if len(s) == 0 {
		return ""
	}
	result := s[0]
	for i := 1; i < len(s); i++ {
		result += sep + s[i]
	}
	return result
}
