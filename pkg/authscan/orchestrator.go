package authscan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ScanConfig defines a pre-auth + post-auth scanning workflow
type ScanConfig struct {
	// Target URL(s) to scan
	Targets []string `yaml:"targets" json:"targets"`
	// Template directories/files for pre-auth phase (unauthenticated recon)
	PreAuthTemplates []string `yaml:"pre_auth_templates" json:"pre_auth_templates"`
	// Template directories/files for post-auth phase (authenticated scanning)
	PostAuthTemplates []string `yaml:"post_auth_templates" json:"post_auth_templates"`
	// Additional nuclei flags
	ExtraFlags []string `yaml:"extra_flags" json:"extra_flags"`
	// Output directory for scan results
	OutputDir string `yaml:"output_dir" json:"output_dir"`
	// Nuclei binary path (defaults to nuclei-dev)
	NucleiBinary string `yaml:"nuclei_binary" json:"nuclei_binary"`
}

// ScanResult contains the results of a pre-auth + post-auth scan
type ScanResult struct {
	PreAuthFindings  []Finding `json:"pre_auth_findings"`
	PostAuthFindings []Finding `json:"post_auth_findings"`
	AuthSuccess      bool      `json:"auth_success"`
	AuthMethod       string    `json:"auth_method"`
	Duration         string    `json:"duration"`
}

// Finding is a simplified nuclei finding
type Finding struct {
	TemplateID string `json:"template-id"`
	Host       string `json:"host"`
	Severity   string `json:"severity"`
	Type       string `json:"type"`
	URL        string `json:"url"`
	Matcher    string `json:"matcher-name"`
}

// Orchestrator runs a pre-auth + post-auth scanning workflow
type Orchestrator struct {
	authConfig *AuthConfig
	scanConfig *ScanConfig
	session    *Session
}

// NewOrchestrator creates a new scan orchestrator
func NewOrchestrator(authCfg *AuthConfig, scanCfg *ScanConfig) *Orchestrator {
	if scanCfg.NucleiBinary == "" {
		scanCfg.NucleiBinary = "nuclei-dev"
	}
	if scanCfg.OutputDir == "" {
		scanCfg.OutputDir = filepath.Join(os.Getenv("HOME"), ".config", "nuclei-dev", "authscan-results")
	}
	return &Orchestrator{
		authConfig: authCfg,
		scanConfig: scanCfg,
	}
}

// Run executes the full pre-auth + auth + post-auth workflow
func (o *Orchestrator) Run() (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{AuthMethod: o.authConfig.Method}

	// Phase 1: Pre-auth scan (unauthenticated)
	if len(o.scanConfig.PreAuthTemplates) > 0 {
		preAuthFindings, err := o.runNuclei(o.scanConfig.PreAuthTemplates, nil)
		if err != nil {
			return result, fmt.Errorf("pre-auth scan failed: %w", err)
		}
		result.PreAuthFindings = preAuthFindings
	}

	// Phase 2: Authenticate
	session, err := NewSession(o.authConfig)
	if err != nil {
		return result, fmt.Errorf("session creation failed: %w", err)
	}
	o.session = session

	if err := session.Authenticate(); err != nil {
		return result, fmt.Errorf("authentication failed: %w", err)
	}
	result.AuthSuccess = true

	// Generate secrets file for nuclei
	secretsFile := filepath.Join(o.scanConfig.OutputDir, "session-secrets.yaml")
	if err := GenerateSecretsFile(session, secretsFile); err != nil {
		return result, fmt.Errorf("secrets file generation failed: %w", err)
	}

	// Start session monitor
	monitor := NewSessionMonitor(session, 5*time.Minute)
	monitor.Start()
	defer monitor.Stop()

	// Phase 3: Post-auth scan (authenticated)
	if len(o.scanConfig.PostAuthTemplates) > 0 {
		postAuthFindings, err := o.runNuclei(o.scanConfig.PostAuthTemplates, []string{"-sf", secretsFile})
		if err != nil {
			return result, fmt.Errorf("post-auth scan failed: %w", err)
		}
		result.PostAuthFindings = postAuthFindings
	}

	result.Duration = time.Since(startTime).String()
	return result, nil
}

// runNuclei executes a nuclei scan with the given templates and extra args
func (o *Orchestrator) runNuclei(templates []string, extraArgs []string) ([]Finding, error) {
	os.MkdirAll(o.scanConfig.OutputDir, 0755)
	outputFile := filepath.Join(o.scanConfig.OutputDir, fmt.Sprintf("scan-%d.jsonl", time.Now().UnixNano()))

	args := []string{
		"-jsonl",
		"-silent",
		"-nc",
		"-o", outputFile,
	}

	// Add templates
	for _, t := range templates {
		args = append(args, "-t", t)
	}

	// Add targets
	for _, target := range o.scanConfig.Targets {
		args = append(args, "-u", target)
	}

	// Add extra flags
	args = append(args, o.scanConfig.ExtraFlags...)

	// Add extra args (e.g., -sf secrets file)
	args = append(args, extraArgs...)

	cmd := exec.Command(o.scanConfig.NucleiBinary, args...)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// nuclei returns non-zero on findings sometimes, check if output exists
		if _, statErr := os.Stat(outputFile); statErr != nil {
			return nil, fmt.Errorf("nuclei execution failed: %w", err)
		}
	}

	// Parse JSONL output
	data, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read output: %w", err)
	}

	return parseFindings(data), nil
}

// parseFindings parses nuclei JSONL output into Finding structs
func parseFindings(data []byte) []Finding {
	var findings []Finding
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var f Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			continue
		}
		if f.TemplateID != "" {
			findings = append(findings, f)
		}
	}
	return findings
}

// AuthProfileFromURL discovers the login form and auth type from a target URL
func AuthProfileFromURL(targetURL string) (*AuthConfig, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	cfg := &AuthConfig{
		Domain: parsed.Hostname(),
		Method: "form",
		Timeout: 15 * time.Second,
		InsecureSkipVerify: true,
	}

	// Try common login paths
	loginPaths := []string{
		"/login", "/admin", "/auth", "/signin",
		"/admin/login", "/user/login", "/account/login",
		"/wp-login.php", "/api/login",
	}

	for _, path := range loginPaths {
		loginURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, path)
		cfg.LoginURL = loginURL

		session, err := NewSession(cfg)
		if err != nil {
			continue
		}

		// Try to GET the login page
		resp, err := session.client.Get(loginURL)
		if err != nil {
			continue
		}
		if resp.Body != nil {
			resp.Body.Close()
		}

		if resp.StatusCode == 200 {
			// Check if it has a login form
			// Re-fetch to parse
			resp2, err := session.client.Get(loginURL)
			if err != nil {
				continue
			}
			defer resp2.Body.Close()

			_, _, err = parseLoginForm(resp2, loginURL, "", "")
			if err == nil {
				cfg.LoginURL = loginURL
				return cfg, nil
			}
		}
	}

	return nil, fmt.Errorf("no login form discovered at %s", targetURL)
}
