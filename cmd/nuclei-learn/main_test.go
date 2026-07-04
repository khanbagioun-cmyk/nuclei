package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const binaryPath = "../../bin/nuclei-learn"

func buildBinary(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); os.IsNotExist(err) {
		cmd := exec.Command("/opt/homebrew/bin/go", "build", "-o", abs, "./cmd/nuclei-learn/")
		cmd.Dir = "../.."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build failed: %v\n%s", err, out)
		}
	}
	return abs
}

func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	bin := buildBinary(t)
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run CLI: %v", err)
		}
	}
	return stdout.String(), stderr.String(), exitCode
}

func runCLIWithStdin(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	bin := buildBinary(t)
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = strings.NewReader(stdin)
	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run CLI: %v", err)
		}
	}
	return stdout.String(), stderr.String(), exitCode
}

func TestCLI_Mark(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	stdout, _, code := runCLI(t, "-store", storeFile, "-mode", "mark",
		"-template", "CVE-2024-1234", "-host", "example.com",
		"-matcher", "rce", "-vuln-type", "rce",
		"-type", "fp", "-reason", "test environment")
	if code != 0 {
		t.Fatalf("exit code: %d", code)
	}
	if !strings.Contains(stdout, "Marked feedback") {
		t.Error("expected mark output")
	}
	if !strings.Contains(stdout, "CVE-2024-1234") {
		t.Error("expected template ID in output")
	}
}

func TestCLI_Mark_TP(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	stdout, _, code := runCLI(t, "-store", storeFile, "-mode", "mark",
		"-template", "CVE-2024-5678", "-host", "target.com",
		"-matcher", "sqli", "-vuln-type", "sqli",
		"-type", "tp", "-reason", "confirmed SQLi")
	if code != 0 {
		t.Fatalf("exit code: %d", code)
	}
	if !strings.Contains(stdout, "true_positive") {
		t.Error("expected TP type")
	}
}

func TestCLI_Mark_InvalidType(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	_, _, code := runCLI(t, "-store", storeFile, "-mode", "mark",
		"-template", "test", "-type", "invalid")
	if code == 0 {
		t.Error("expected non-zero exit for invalid type")
	}
}

func TestCLI_Mark_MissingTemplate(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	_, _, code := runCLI(t, "-store", storeFile, "-mode", "mark")
	if code == 0 {
		t.Error("expected non-zero exit for missing template")
	}
}

func TestCLI_Suppress(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	stdout, _, code := runCLI(t, "-store", storeFile, "-mode", "suppress",
		"-template", "bad-template", "-reason", "always FP")
	if code != 0 {
		t.Fatalf("exit code: %d", code)
	}
	if !strings.Contains(stdout, "Added suppression rule") {
		t.Error("expected suppress output")
	}
}

func TestCLI_Unsuppress(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	// First add a rule
	stdout, _, code := runCLI(t, "-store", storeFile, "-mode", "suppress",
		"-template", "bad-template", "-reason", "always FP")
	if code != 0 {
		t.Fatalf("suppress failed: %d", code)
	}
	// Extract rule ID from output
	lines := strings.Split(stdout, "\n")
	var ruleID string
	for _, l := range lines {
		if strings.Contains(l, "Added suppression rule:") {
			parts := strings.SplitN(l, ":", 2)
			if len(parts) == 2 {
				ruleID = strings.TrimSpace(parts[1])
			}
		}
	}
	if ruleID == "" {
		t.Fatal("could not extract rule ID")
	}
	// Now remove it
	stdout2, _, code2 := runCLI(t, "-store", storeFile, "-mode", "unsuppress",
		"-rule-id", ruleID)
	if code2 != 0 {
		t.Fatalf("unsuppress exit: %d", code2)
	}
	if !strings.Contains(stdout2, "Removed suppression rule") {
		t.Error("expected removal output")
	}
}

func TestCLI_Unsuppress_NotFound(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	_, _, code := runCLI(t, "-store", storeFile, "-mode", "unsuppress",
		"-rule-id", "nonexistent")
	if code == 0 {
		t.Error("expected non-zero exit for not found")
	}
}

func TestCLI_Report_Text(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	// Add some data
	runCLI(t, "-store", storeFile, "-mode", "mark",
		"-template", "t1", "-host", "h1.com", "-vuln-type", "sqli",
		"-type", "fp", "-reason", "test")
	runCLI(t, "-store", storeFile, "-mode", "mark",
		"-template", "t2", "-host", "h2.com", "-vuln-type", "xss",
		"-type", "tp", "-reason", "confirmed")
	runCLI(t, "-store", storeFile, "-mode", "suppress",
		"-template", "t3", "-reason", "manual suppress")

	stdout, _, code := runCLI(t, "-store", storeFile, "-mode", "report")
	if code != 0 {
		t.Fatalf("exit code: %d", code)
	}
	if !strings.Contains(stdout, "Template Learning Report") {
		t.Error("expected report header")
	}
	if !strings.Contains(stdout, "False positives:") {
		t.Error("expected FP stats")
	}
	if !strings.Contains(stdout, "t3") {
		t.Error("expected suppression rule t3")
	}
}

func TestCLI_Report_JSON(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	runCLI(t, "-store", storeFile, "-mode", "mark",
		"-template", "t1", "-host", "h1.com", "-vuln-type", "sqli",
		"-type", "fp", "-reason", "test")

	stdout, _, code := runCLI(t, "-store", storeFile, "-mode", "report", "-json")
	if code != 0 {
		t.Fatalf("exit code: %d", code)
	}
	var report map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if report["stats"] == nil {
		t.Error("expected stats in JSON report")
	}
}

func TestCLI_Filter(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	// Add suppression for fp-template
	runCLI(t, "-store", storeFile, "-mode", "suppress",
		"-template", "fp-template", "-reason", "known FP")

	jsonl := `{"template-id":"fp-template","info":{"name":"FP","severity":"high","tags":["xss"]},"host":"example.com","matched-at":"http://example.com/","matcher-name":"m1"}
{"template-id":"real-vuln","info":{"name":"Real","severity":"critical","tags":["cve","rce"]},"host":"example.com","matched-at":"http://example.com/admin","matcher-name":"rce"}`

	stdout, stderr, code := runCLIWithStdin(t, jsonl,
		"-store", storeFile, "-mode", "filter")
	if code != 0 {
		t.Fatalf("exit code: %d", code)
	}
	if strings.Contains(stdout, "fp-template") {
		t.Error("expected fp-template to be filtered out")
	}
	if !strings.Contains(stdout, "real-vuln") {
		t.Error("expected real-vuln to pass through")
	}
	if !strings.Contains(stderr, "Filtered:") {
		t.Error("expected filter stats on stderr")
	}
}

func TestCLI_FNCheck(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	// Mark a TP on host-a
	runCLI(t, "-store", storeFile, "-mode", "mark",
		"-template", "CVE-2024-1234", "-host", "host-a.com",
		"-vuln-type", "rce", "-type", "tp", "-reason", "confirmed")

	// Feed findings: only host-a has the finding, host-b doesn't
	jsonl := `{"template-id":"CVE-2024-1234","info":{"name":"RCE","severity":"critical","tags":["rce"]},"host":"host-a.com","matched-at":"http://host-a.com/","matcher-name":"rce"}
{"template-id":"other","info":{"name":"Other","severity":"info","tags":["tech"]},"host":"host-b.com","matched-at":"http://host-b.com/","matcher-name":"info"}`

	stdout, _, code := runCLIWithStdin(t, jsonl,
		"-store", storeFile, "-mode", "fn-check")
	if code != 0 {
		t.Fatalf("exit code: %d", code)
	}
	if !strings.Contains(stdout, "false negatives") {
		t.Error("expected FN check output")
	}
}

func TestCLI_FNCheck_JSON(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	runCLI(t, "-store", storeFile, "-mode", "mark",
		"-template", "CVE-2024-1234", "-host", "host-a.com",
		"-vuln-type", "rce", "-type", "tp", "-reason", "confirmed")

	jsonl := `{"template-id":"CVE-2024-1234","info":{"name":"RCE","severity":"critical","tags":["rce"]},"host":"host-a.com","matched-at":"http://host-a.com/","matcher-name":"rce"}
{"template-id":"other","info":{"name":"Other","severity":"info","tags":["tech"]},"host":"host-b.com","matched-at":"http://host-b.com/","matcher-name":"info"}`

	stdout, _, code := runCLIWithStdin(t, jsonl,
		"-store", storeFile, "-mode", "fn-check", "-json")
	if code != 0 {
		t.Fatalf("exit code: %d", code)
	}
	var results []map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if len(results) == 0 {
		t.Error("expected at least 1 FN result")
	}
}

func TestCLI_Persistence(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	// Mark feedback
	runCLI(t, "-store", storeFile, "-mode", "mark",
		"-template", "persist-test", "-host", "persist.com",
		"-vuln-type", "sqli", "-type", "fp", "-reason", "persist check")

	// Load report from same store
	stdout, _, code := runCLI(t, "-store", storeFile, "-mode", "report")
	if code != 0 {
		t.Fatalf("exit code: %d", code)
	}
	if !strings.Contains(stdout, "persist-test") {
		t.Error("expected persisted template in report")
	}
}

func TestCLI_NoMode(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	_, _, code := runCLI(t, "-store", storeFile)
	if code == 0 {
		t.Error("expected non-zero exit for missing mode")
	}
}

func TestCLI_DefaultStorePath(t *testing.T) {
	// Verify default store path works (just ensure it doesn't crash)
	// Use a temp HOME to avoid polluting real config
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	bin := buildBinary(t)
	cmd := exec.Command(bin, "-mode", "report")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}
	if exitCode != 0 {
		t.Errorf("expected exit 0 for default store, got %d. stderr: %s", exitCode, stderr.String())
	}
}

// Ensure the binary is built before any test runs
func TestMain(m *testing.M) {
	// Pre-build
	abs, _ := filepath.Abs(binaryPath)
	if _, err := os.Stat(abs); os.IsNotExist(err) {
		cmd := exec.Command("/opt/homebrew/bin/go", "build", "-o", abs, "./cmd/nuclei-learn/")
		cmd.Dir = "../.."
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		cmd.Run()
	}
	os.Exit(m.Run())
}
