package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2E_LearningWorkflow(t *testing.T) {
	bin := buildBinary(t)
	storeFile := t.TempDir() + "/e2e-store.json"

	// Step 1: Run nuclei scan and capture JSONL (simulated)
	// We'll use synthetic findings to simulate nuclei output
	nucleiOutput := `{"template-id":"CVE-2024-FAKE-RCE","info":{"name":"Fake RCE","severity":"critical","tags":["cve","rce"]},"host":"target.example.com","matched-at":"http://target.example.com/admin","matcher-name":"rce-detected"}
{"template-id":"CVE-2024-FAKE-RCE","info":{"name":"Fake RCE","severity":"critical","tags":["cve","rce"]},"host":"target.example.com","matched-at":"http://target.example.com/api","matcher-name":"rce-detected"}
{"template-id":"tech-detect","info":{"name":"Tech Detection","severity":"info","tags":["tech"]},"host":"target.example.com","matched-at":"http://target.example.com/","matcher-name":"nginx"}`

	// Step 2: User reviews findings and marks the RCE as a false positive
	cmd := exec.Command(bin, "-store", storeFile, "-mode", "mark",
		"-template", "CVE-2024-FAKE-RCE", "-host", "target.example.com",
		"-matcher", "rce-detected", "-vuln-type", "rce",
		"-type", "fp", "-reason", "RCE pattern matched but server is read-only")
	var markOut strings.Builder
	cmd.Stdout = &markOut
	cmd.Stderr = &markOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("mark failed: %v\n%s", err, markOut.String())
	}
	if !strings.Contains(markOut.String(), "Marked feedback") {
		t.Error("expected mark output")
	}

	// Step 3: Mark the same FP multiple times to trigger auto-suppression (threshold=3)
	for i := 0; i < 2; i++ {
		cmd := exec.Command(bin, "-store", storeFile, "-mode", "mark",
			"-template", "CVE-2024-FAKE-RCE", "-host", "target.example.com",
			"-matcher", "rce-detected", "-vuln-type", "rce",
			"-type", "fp", "-reason", "still FP")
		cmd.Stdout = &markOut
		cmd.Stderr = &markOut
		if err := cmd.Run(); err != nil {
			t.Fatalf("mark %d failed: %v", i+2, err)
		}
	}

	// Step 4: Verify auto-suppression kicked in
	cmd4 := exec.Command(bin, "-store", storeFile, "-mode", "report", "-json")
	var reportOut strings.Builder
	cmd4.Stdout = &reportOut
	if err := cmd4.Run(); err != nil {
		t.Fatalf("report failed: %v", err)
	}
	if !strings.Contains(reportOut.String(), "AutoSuppressed") {
		t.Error("expected auto-suppressed flag in report")
	}

	// Step 5: Re-run filter on the same nuclei output — FP should be gone
	cmd5 := exec.Command(bin, "-store", storeFile, "-mode", "filter")
	cmd5.Stdin = strings.NewReader(nucleiOutput)
	var filterOut, filterErr strings.Builder
	cmd5.Stdout = &filterOut
	cmd5.Stderr = &filterErr
	if err := cmd5.Run(); err != nil {
		t.Fatalf("filter failed: %v", err)
	}

	// The 2 RCE findings should be suppressed, only tech-detect should remain
	if strings.Contains(filterOut.String(), "CVE-2024-FAKE-RCE") {
		t.Error("expected CVE-2024-FAKE-RCE to be filtered out (auto-suppressed)")
	}
	if !strings.Contains(filterOut.String(), "tech-detect") {
		t.Error("expected tech-detect to pass through")
	}
	if !strings.Contains(filterErr.String(), "2 suppressed") {
		t.Errorf("expected 2 suppressed, got: %s", filterErr.String())
	}

	// Step 6: Generate text report and verify it shows learning data
	cmd6 := exec.Command(bin, "-store", storeFile, "-mode", "report")
	var textReport strings.Builder
	cmd6.Stdout = &textReport
	if err := cmd6.Run(); err != nil {
		t.Fatalf("text report failed: %v", err)
	}
	if !strings.Contains(textReport.String(), "False positives:") {
		t.Error("expected FP stats in report")
	}
	if !strings.Contains(textReport.String(), "Auto-suppressed:") {
		t.Error("expected auto-suppressed stats")
	}
}

func TestE2E_ManualSuppressWorkflow(t *testing.T) {
	bin := buildBinary(t)
	storeFile := t.TempDir() + "/e2e-manual.json"

	// Step 1: Add manual suppression rule
	cmd := exec.Command(bin, "-store", storeFile, "-mode", "suppress",
		"-template", "annoying-template", "-host", "noisy.example.com",
		"-reason", "Always FP on this host")
	var suppressOut strings.Builder
	cmd.Stdout = &suppressOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("suppress failed: %v", err)
	}

	// Extract rule ID
	ruleID := ""
	for _, line := range strings.Split(suppressOut.String(), "\n") {
		if strings.Contains(line, "Added suppression rule:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ruleID = strings.TrimSpace(parts[1])
			}
		}
	}
	if ruleID == "" {
		t.Fatal("could not extract rule ID")
	}

	// Step 2: Filter nuclei output with the suppression active
	jsonl := `{"template-id":"annoying-template","info":{"name":"Annoying","severity":"high","tags":["xss"]},"host":"noisy.example.com","matched-at":"http://noisy.example.com/","matcher-name":"xss"}
{"template-id":"real-vuln","info":{"name":"Real Vuln","severity":"critical","tags":["sqli"]},"host":"noisy.example.com","matched-at":"http://noisy.example.com/api","matcher-name":"sqli"}`

	cmd2 := exec.Command(bin, "-store", storeFile, "-mode", "filter")
	cmd2.Stdin = strings.NewReader(jsonl)
	var filterOut strings.Builder
	cmd2.Stdout = &filterOut
	if err := cmd2.Run(); err != nil {
		t.Fatalf("filter failed: %v", err)
	}
	if strings.Contains(filterOut.String(), "annoying-template") {
		t.Error("expected annoying-template to be suppressed")
	}
	if !strings.Contains(filterOut.String(), "real-vuln") {
		t.Error("expected real-vuln to pass")
	}

	// Step 3: Remove suppression
	cmd3 := exec.Command(bin, "-store", storeFile, "-mode", "unsuppress",
		"-rule-id", ruleID)
	if err := cmd3.Run(); err != nil {
		t.Fatalf("unsuppress failed: %v", err)
	}

	// Step 4: Filter again — now annoying-template should pass
	cmd4 := exec.Command(bin, "-store", storeFile, "-mode", "filter")
	cmd4.Stdin = strings.NewReader(jsonl)
	var filterOut2 strings.Builder
	cmd4.Stdout = &filterOut2
	if err := cmd4.Run(); err != nil {
		t.Fatalf("filter 2 failed: %v", err)
	}
	if !strings.Contains(filterOut2.String(), "annoying-template") {
		t.Error("expected annoying-template to pass after unsuppress")
	}
}

func TestE2E_FNCheckWorkflow(t *testing.T) {
	bin := buildBinary(t)
	storeFile := t.TempDir() + "/e2e-fn.json"

	// Step 1: Mark a TP on host-a
	cmd := exec.Command(bin, "-store", storeFile, "-mode", "mark",
		"-template", "CVE-2024-REAL", "-host", "host-a.example.com",
		"-vuln-type", "sqli", "-type", "tp", "-reason", "confirmed SQLi")
	if err := cmd.Run(); err != nil {
		t.Fatalf("mark failed: %v", err)
	}

	// Step 2: Feed scan results that include host-b (which should have had the same vuln)
	jsonl := `{"template-id":"CVE-2024-REAL","info":{"name":"SQLi","severity":"critical","tags":["sqli"]},"host":"host-a.example.com","matched-at":"http://host-a.example.com/","matcher-name":"sqli"}
{"template-id":"tech-detect","info":{"name":"Tech","severity":"info","tags":["tech"]},"host":"host-b.example.com","matched-at":"http://host-b.example.com/","matcher-name":"apache"}`

	cmd2 := exec.Command(bin, "-store", storeFile, "-mode", "fn-check", "-json")
	cmd2.Stdin = strings.NewReader(jsonl)
	var fnOut strings.Builder
	cmd2.Stdout = &fnOut
	if err := cmd2.Run(); err != nil {
		t.Fatalf("fn-check failed: %v", err)
	}

	if !strings.Contains(fnOut.String(), "host-b.example.com") {
		t.Error("expected FN detection for host-b")
	}
	if !strings.Contains(fnOut.String(), "CVE-2024-REAL") {
		t.Error("expected template ID in FN output")
	}
}

// Ensure binary is built before E2E tests
func init() {
	abs, _ := filepath.Abs(binaryPath)
	exec.Command("/opt/homebrew/bin/go", "build", "-o", abs, "./cmd/nuclei-learn/").Run()
}
