package orchestrator

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.RateLimit != 150 {
		t.Errorf("expected rate limit 150, got %d", cfg.RateLimit)
	}
	if cfg.Concurrency != 25 {
		t.Errorf("expected concurrency 25, got %d", cfg.Concurrency)
	}
	if cfg.Timeout != 30*time.Minute {
		t.Errorf("expected timeout 30m, got %v", cfg.Timeout)
	}
	if len(cfg.BannerPorts) == 0 {
		t.Error("expected non-empty banner ports")
	}
}

func TestScanConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *ScanConfig
		wantErr bool
	}{
		{
			name:    "empty targets",
			config:  &ScanConfig{Targets: []string{}},
			wantErr: true,
		},
		{
			name:    "negative rate limit",
			config:  &ScanConfig{Targets: []string{"localhost"}, RateLimit: -1},
			wantErr: true,
		},
		{
			name:    "negative concurrency",
			config:  &ScanConfig{Targets: []string{"localhost"}, Concurrency: -5},
			wantErr: true,
		},
		{
			name:    "valid config",
			config:  &ScanConfig{Targets: []string{"localhost"}, RateLimit: 50, Concurrency: 10},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestScanConfigBuilder(t *testing.T) {
	cfg := &ScanConfig{}
	cfg.SetTargets("a.com", "b.com").
		SetRateLimit(200).
		SetConcurrency(50).
		SetTimeout(10 * time.Minute).
		SetStages(StageBannerGrab, StageVulnScan)

	if len(cfg.Targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(cfg.Targets))
	}
	if cfg.RateLimit != 200 {
		t.Errorf("expected rate limit 200, got %d", cfg.RateLimit)
	}
	if cfg.Concurrency != 50 {
		t.Errorf("expected concurrency 50, got %d", cfg.Concurrency)
	}
	if cfg.Timeout != 10*time.Minute {
		t.Errorf("expected timeout 10m, got %v", cfg.Timeout)
	}
	if len(cfg.Stages) != 2 {
		t.Errorf("expected 2 stages, got %d", len(cfg.Stages))
	}
}

func TestStageName(t *testing.T) {
	tests := []struct {
		stage    ScanStage
		expected string
	}{
		{StageRecon, "recon"},
		{StageBannerGrab, "banner-grab"},
		{StageVulnScan, "vulnerability-scan"},
		{StageDeepScan, "deep-scan"},
	}

	for _, tt := range tests {
		got := tt.stage.StageName()
		if got != tt.expected {
			t.Errorf("StageName() = %q, want %q", got, tt.expected)
		}
	}
}

func TestBannerGrabStage(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
		time.Sleep(200 * time.Millisecond)
	}()

	port := ln.Addr().(*net.TCPAddr).Port

	cfg := &ScanConfig{
		Targets:           []string{"127.0.0.1"},
		Stages:            []ScanStage{StageBannerGrab},
		BannerGrabTimeout: 3 * time.Second,
		BannerPorts:       []int{port},
	}

	orch := New(cfg)
	result, err := orch.Run(context.Background())
	if err != nil {
		t.Fatalf("orchestrator run failed: %v", err)
	}

	if len(result.Banners) == 0 {
		t.Fatal("expected at least 1 banner result")
	}

	hasBanner := false
	for _, b := range result.Banners {
		if b.Banner != "" && b.Error == nil {
			hasBanner = true
			t.Logf("Banner from %s: %s (protocol: %s)", b.Address, b.Banner, b.Protocol)
		}
	}
	if !hasBanner {
		t.Error("no successful banners grabbed")
	}

	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}
	if _, ok := result.StageDurations["banner-grab"]; !ok {
		t.Error("expected banner-grab stage in durations")
	}
}

func TestScanResultProfile(t *testing.T) {
	result := &ScanResult{
		Duration:       5 * time.Second,
		TargetsScanned: 3,
		Findings:       nil,
		Banners:        nil,
		Errors:         []error{},
		StageDurations: map[string]time.Duration{
			"recon":   2 * time.Second,
			"vulnscan": 3 * time.Second,
		},
	}

	profile := result.Profile()
	if profile == "" {
		t.Error("expected non-empty profile")
	}
	if !contains(profile, "Total Duration") {
		t.Error("profile should contain 'Total Duration'")
	}
	if !contains(profile, "Throughput") {
		t.Error("profile should contain 'Throughput'")
	}
}

func TestScanResultSummary(t *testing.T) {
	result := &ScanResult{
		Duration:       10 * time.Second,
		TargetsScanned: 5,
		Errors:         []error{},
		StageDurations: map[string]time.Duration{},
	}

	summary := result.Summary()
	if summary == "" {
		t.Error("expected non-empty summary")
	}
	if !contains(summary, "Scan completed") {
		t.Error("summary should contain 'Scan completed'")
	}
	if !contains(summary, "Targets: 5") {
		t.Error("summary should contain target count")
	}
}

func TestNew(t *testing.T) {
	cfg := &ScanConfig{Targets: []string{"localhost"}}
	orch := New(cfg)
	if orch == nil {
		t.Fatal("expected non-nil orchestrator")
	}
	if orch.config != cfg {
		t.Error("expected config to be set")
	}
}

func TestNewWithNilConfig(t *testing.T) {
	orch := New(nil)
	if orch == nil {
		t.Fatal("expected non-nil orchestrator with nil config")
	}
	if orch.config == nil {
		t.Error("expected default config when nil provided")
	}
	if orch.config.RateLimit != 150 {
		t.Error("expected default rate limit")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
