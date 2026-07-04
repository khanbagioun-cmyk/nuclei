package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const testJSONL = `{"template-id":"tech-detect","info":{"name":"Tech Detect","severity":"info","tags":["tech","fingerprint"]},"type":"http","host":"example.com","matched-at":"http://example.com/","matcher-name":"apache"}
{"template-id":"exposure-config","info":{"name":"Config Exposure","severity":"medium","tags":["exposure","config","misconfig"]},"type":"http","host":"example.com","matched-at":"http://example.com/.env","matcher-name":"config-file"}
{"template-id":"default-login","info":{"name":"Default Login","severity":"high","tags":["default-login","login"]},"type":"http","host":"example.com","matched-at":"http://example.com/login","matcher-name":"default-creds"}
{"template-id":"admin-panel","info":{"name":"Admin Panel","severity":"info","tags":["panel","admin","dashboard"]},"type":"http","host":"example.com","matched-at":"http://example.com/admin","matcher-name":"panel-detected"}
{"template-id":"CVE-2024-9999","info":{"name":"Apache RCE","severity":"critical","tags":["cve","rce","apache"]},"type":"http","host":"example.com","matched-at":"http://example.com/cgi-bin/","matcher-name":"rce"}`

func writeTestJSONL(t *testing.T) string {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	if err := os.WriteFile(path, []byte(testJSONL), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

const binaryPath = "/Users/WorkMain/nuclei-fork/bin/nuclei-attackchain"

func runCLI(args ...string) (string, int, error) {
	cmd := exec.Command(binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), cmd.ProcessState.ExitCode(), err
}

func TestCLI_TextOutput(t *testing.T) {
	path := writeTestJSONL(t)
	out, code, err := runCLI("-i", path, "-text", "-silent")
	if err != nil && code != 0 {
		t.Fatalf("CLI failed: %v\nstderr: %s", err, out)
	}
	if !contains(out, "Attack chains found") {
		t.Errorf("expected 'Attack chains found' in output, got: %s", out)
	}
}

func TestCLI_JSONOutput(t *testing.T) {
	path := writeTestJSONL(t)
	out, code, err := runCLI("-i", path, "-json", "-silent")
	if err != nil && code != 0 {
		t.Fatalf("CLI failed: %v\n", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput: %s", err, out)
	}
	if _, ok := report["summary"]; !ok {
		t.Error("expected 'summary' key in JSON report")
	}
	if _, ok := report["chains"]; !ok {
		t.Error("expected 'chains' key in JSON report")
	}
}

func TestCLI_Stdin(t *testing.T) {
	cmd := exec.Command(binaryPath, "-i", "-", "-json", "-silent")
	cmd.Stdin = bytes.NewBufferString(testJSONL)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("CLI failed: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestCLI_TopN(t *testing.T) {
	path := writeTestJSONL(t)
	out, code, err := runCLI("-i", path, "-json", "-silent", "-top", "1")
	if err != nil && code != 0 {
		t.Fatalf("CLI failed: %v", err)
	}

	var report struct {
		Chains []interface{} `json:"chains"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(report.Chains) > 1 {
		t.Errorf("expected at most 1 chain with -top 1, got %d", len(report.Chains))
	}
}

func TestCLI_NoInput(t *testing.T) {
	_, code, _ := runCLI("-silent")
	if code == 0 {
		t.Error("expected non-zero exit code when no input provided")
	}
}

func TestCLI_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(path, []byte(""), 0644)

	out, _, err := runCLI("-i", path, "-json", "-silent")
	if err != nil {
		t.Fatalf("CLI failed: %v", err)
	}
	if !contains(out, "total_chains") {
		t.Errorf("expected total_chains in output, got: %s", out)
	}
}

func TestCLI_MaxDepth(t *testing.T) {
	path := writeTestJSONL(t)
	out, code, err := runCLI("-i", path, "-json", "-silent", "-max-depth", "1")
	if err != nil && code != 0 {
		t.Fatalf("CLI failed: %v", err)
	}

	var report struct {
		Chains []struct {
			Length int `json:"length"`
		} `json:"chains"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, c := range report.Chains {
		if c.Length > 1 {
			t.Errorf("chain length %d > max-depth 1", c.Length)
		}
	}
}

func TestCLI_MinConfidence(t *testing.T) {
	path := writeTestJSONL(t)
	out, _, err := runCLI("-i", path, "-json", "-silent", "-min-confidence", "0.9")
	if err != nil {
		t.Fatalf("CLI failed: %v", err)
	}

	var report struct {
		Chains []struct {
			Confidence float64 `json:"confidence"`
		} `json:"chains"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, c := range report.Chains {
		if c.Confidence < 0.9 {
			t.Errorf("chain confidence %.2f < min 0.9", c.Confidence)
		}
	}
}

func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}
