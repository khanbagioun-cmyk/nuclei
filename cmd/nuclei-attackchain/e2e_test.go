package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"testing"
)

// TestE2E_SyntheticFindings tests the full pipeline with realistic nuclei JSONL output
func TestE2E_SyntheticFindings(t *testing.T) {
	binary := "/Users/WorkMain/nuclei-fork/bin/nuclei-attackchain"
	if _, err := exec.LookPath(binary); err != nil {
		t.Skipf("binary not found")
	}

	// Realistic nuclei JSONL output from a scan of a vulnerable host
	jsonl := `{"template-id":"tech-detect","info":{"name":"Apache Tech Detect","severity":"info","tags":["tech","fingerprint","apache"]},"type":"http","host":"vuln-target.com","matched-at":"http://vuln-target.com/","matcher-name":"apache","port":"80"}
{"template-id":"exposure-env-file","info":{"name":".env File Exposure","severity":"high","tags":["exposure","config","misconfig"]},"type":"http","host":"vuln-target.com","matched-at":"http://vuln-target.com/.env","matcher-name":"env-file"}
{"template-id":"CVE-2024-3094","info":{"name":"XZ Utils Backdoor","severity":"critical","tags":["cve","rce","backdoor"]},"type":"http","host":"vuln-target.com","matched-at":"http://vuln-target.com/ssh","matcher-name":"rce"}
{"template-id":"default-login-admin","info":{"name":"Admin Default Login","severity":"high","tags":["default-login","login","auth"]},"type":"http","host":"vuln-target.com","matched-at":"http://vuln-target.com/admin","matcher-name":"default-creds"}
{"template-id":"admin-panel-detect","info":{"name":"Admin Panel","severity":"info","tags":["panel","admin","dashboard"]},"type":"http","host":"vuln-target.com","matched-at":"http://vuln-target.com/admin/","matcher-name":"panel"}`

	// Run attackchain
	cmd := exec.Command(binary, "-i", "-", "-json", "-silent")
	cmd.Stdin = bytes.NewBufferString(jsonl)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("attackchain failed: %v", err)
	}

	var report struct {
		Summary struct {
			TotalChains    int     `json:"TotalChains"`
			CriticalChains int     `json:"CriticalChains"`
			MaxChainLength int     `json:"MaxChainLength"`
			MaxRiskScore   float64 `json:"MaxRiskScore"`
		} `json:"summary"`
		GraphStats struct {
			Nodes int `json:"nodes"`
			Edges int `json:"edges"`
		} `json:"graph_stats"`
		Chains []struct {
			Description    string  `json:"description"`
			FinalSeverity  string  `json:"final_severity"`
			RiskScore      float64 `json:"risk_score"`
			Length         int     `json:"length"`
		} `json:"chains"`
		Findings []struct {
			TemplateID string `json:"template_id"`
			VulnType   string `json:"vuln_type"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\noutput: %s", err, out.String())
	}

	// Verify findings
	if len(report.Findings) != 5 {
		t.Errorf("expected 5 findings, got %d", len(report.Findings))
	}

	// Verify graph
	if report.GraphStats.Nodes != 5 {
		t.Errorf("expected 5 nodes, got %d", report.GraphStats.Nodes)
	}
	if report.GraphStats.Edges < 3 {
		t.Errorf("expected at least 3 edges, got %d", report.GraphStats.Edges)
	}

	// Verify chains
	if report.Summary.TotalChains == 0 {
		t.Error("expected at least 1 attack chain")
	}
	if report.Summary.CriticalChains == 0 {
		t.Error("expected at least 1 critical chain")
	}
	if report.Summary.MaxRiskScore < 70 {
		t.Errorf("expected max risk score >= 70, got %.1f", report.Summary.MaxRiskScore)
	}

	// Verify the top chain involves multiple steps
	hasMultiStep := false
	for _, c := range report.Chains {
		if c.Length >= 2 {
			hasMultiStep = true
			break
		}
	}
	if !hasMultiStep {
		t.Error("expected at least one chain with 2+ steps")
	}

	// Verify critical severity chains exist
	hasCritical := false
	for _, c := range report.Chains {
		if c.FinalSeverity == "critical" {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("expected at least one critical severity chain")
	}
}

// TestE2E_PipelineNucleiToAttackChain tests piping nuclei output directly
func TestE2E_PipelineNucleiToAttackChain(t *testing.T) {
	binary := "/Users/WorkMain/nuclei-fork/bin/nuclei-attackchain"
	if _, err := exec.LookPath(binary); err != nil {
		t.Skipf("binary not found")
	}

	// Simulate a realistic pipe: nuclei -jsonl | nuclei-attackchain -i -
	// We use pre-generated JSONL that mimics nuclei output format
	jsonl := `{"template-id":"git-exposure","info":{"name":"Git Repository Exposure","severity":"high","tags":["exposure","git","backup"]},"type":"http","host":"target.local","matched-at":"http://target.local/.git/config","matcher-name":"git-config"}
{"template-id":"source-code-leak","info":{"name":"Source Code Leak","severity":"high","tags":["exposure","source-code"]},"type":"http","host":"target.local","matched-at":"http://target.local/source.zip","matcher-name":"source-zip"}
{"template-id":"db-creds-exposed","info":{"name":"Database Credentials","severity":"critical","tags":["exposure","config","credential"]},"type":"http","host":"target.local","matched-at":"http://target.local/config/database.yml","matcher-name":"db-creds"}
{"template-id":"admin-panel","info":{"name":"Admin Panel","severity":"info","tags":["panel","admin"]},"type":"http","host":"target.local","matched-at":"http://target.local/admin","matcher-name":"panel"}
{"template-id":"CVE-2024-1234-rce","info":{"name":"Admin Panel RCE","severity":"critical","tags":["cve","rce"]},"type":"http","host":"target.local","matched-at":"http://target.local/admin/exec","matcher-name":"rce"}`

	cmd := exec.Command(binary, "-i", "-", "-json", "-silent", "-max-depth", "10")
	cmd.Stdin = bytes.NewBufferString(jsonl)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed: %v", err)
	}

	var report struct {
		Summary struct {
			TotalChains int `json:"TotalChains"`
		} `json:"summary"`
		GraphStats struct {
			Nodes int `json:"nodes"`
			Edges int `json:"edges"`
		} `json:"graph_stats"`
	}
	json.Unmarshal(out.Bytes(), &report)

	if report.GraphStats.Nodes != 5 {
		t.Errorf("expected 5 nodes, got %d", report.GraphStats.Nodes)
	}
	if report.GraphStats.Edges < 3 {
		t.Errorf("expected at least 3 edges, got %d", report.GraphStats.Edges)
	}
	if report.Summary.TotalChains == 0 {
		t.Error("expected attack chains")
	}
}
