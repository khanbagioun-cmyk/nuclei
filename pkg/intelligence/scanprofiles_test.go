package intelligence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltInProfiles(t *testing.T) {
	profiles := BuiltInProfiles()
	if len(profiles) < 5 {
		t.Errorf("expected at least 5 built-in profiles, got %d", len(profiles))
	}

	names := make(map[string]bool)
	for _, p := range profiles {
		if p.Name == "" {
			t.Error("profile has empty name")
		}
		if p.Description == "" {
			t.Errorf("profile '%s' has empty description", p.Name)
		}
		if names[p.Name] {
			t.Errorf("duplicate profile name: %s", p.Name)
		}
		names[p.Name] = true
	}

	expected := []string{"critical-cve-sweep", "quick-kev-sweep", "full-exposure-audit", "wordpress-deep", "tech-discovery-only", "dast-injection"}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("expected profile '%s' not found", name)
		}
	}
}

func TestGetProfileByName(t *testing.T) {
	p, err := GetProfileByName("critical-cve-sweep")
	if err != nil {
		t.Fatalf("expected to find 'critical-cve-sweep', got error: %v", err)
	}
	if p == nil {
		t.Fatal("profile is nil")
	}
	if len(p.Tags) == 0 {
		t.Error("expected non-empty tags")
	}

	_, err = GetProfileByName("nonexistent-profile")
	if err == nil {
		t.Error("expected error for non-existent profile")
	}
}

func TestSaveLoadProfile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "profile.json")

	original := &ScanProfile{
		Name:        "test-profile",
		Description: "A test profile",
		Tags:        []string{"cve,kev,vkev"},
		Severity:    []string{"critical,high"},
		Protocols:   []string{"http"},
		ExtraArgs:   []string{"-rate-limit", "100"},
		SkipDAST:    true,
		SkipWorkflows: false,
	}

	if err := SaveProfile(original, path); err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("profile file not created: %v", err)
	}

	loaded, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	if loaded.Name != original.Name {
		t.Errorf("name mismatch: got '%s', want '%s'", loaded.Name, original.Name)
	}
	if loaded.Description != original.Description {
		t.Errorf("description mismatch: got '%s', want '%s'", loaded.Description, original.Description)
	}
	if loaded.SkipDAST != original.SkipDAST {
		t.Errorf("SkipDAST mismatch: got %v, want %v", loaded.SkipDAST, original.SkipDAST)
	}
	if loaded.SkipWorkflows != original.SkipWorkflows {
		t.Errorf("SkipWorkflows mismatch: got %v, want %v", loaded.SkipWorkflows, original.SkipWorkflows)
	}
	if len(loaded.ExtraArgs) != len(original.ExtraArgs) {
		t.Errorf("ExtraArgs length mismatch: got %d, want %d", len(loaded.ExtraArgs), len(original.ExtraArgs))
	}
}

func TestScanProfile_ToSmartChainArgs(t *testing.T) {
	tests := []struct {
		name     string
		profile  *ScanProfile
		expected []string
	}{
		{
			name: "profile-only mode",
			profile: &ScanProfile{
				Name:        "discovery",
				ProfileOnly: true,
			},
			expected: []string{"-profile-only"},
		},
		{
			name: "critical-cve-sweep",
			profile: &ScanProfile{
				Name:          "critical-cve-sweep",
				Tags:          []string{"kev,vkev,exploit,cve"},
				Severity:      []string{"critical", "high"},
				SkipDAST:      true,
				SkipWorkflows: false,
			},
			expected: []string{"-tags", "kev,vkev,exploit,cve", "-sv", "critical,high", "-dast=false"},
		},
		{
			name: "quick-kev-sweep",
			profile: &ScanProfile{
				Name:          "quick-kev-sweep",
				Tags:          []string{"kev,vkev"},
				Severity:      []string{"critical", "high", "medium"},
				SkipDAST:      true,
				SkipWorkflows: true,
			},
			expected: []string{"-tags", "kev,vkev", "-sv", "critical,high,medium", "-dast=false", "-workflows=false"},
		},
		{
			name: "with extra args",
			profile: &ScanProfile{
				Name:      "custom",
				Tags:      []string{"cve"},
				ExtraArgs: []string{"-rate-limit", "100"},
			},
			expected: []string{"-tags", "cve", "-rate-limit", "100"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.profile.ToSmartChainArgs()
			if !equalSlices(args, tt.expected) {
				t.Errorf("ToSmartChainArgs() = %v, want %v", args, tt.expected)
			}
		})
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
