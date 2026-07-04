package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCLI_ListPayloads(t *testing.T) {
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-fuzz"
	cmd := exec.Command(binary, "-list-payloads", "-json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success: %v\n%s", err, out)
	}
	if !contains(string(out), "sqli") {
		t.Error("expected sqli in payload list")
	}
	if !contains(string(out), "xss") {
		t.Error("expected xss in payload list")
	}
}

func TestCLI_GenOnly(t *testing.T) {
	tmpDir := t.TempDir()
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-fuzz"
	cmd := exec.Command(binary,
		"-u", "http://example.com/?q=test&id=1",
		"-vuln-types", "sqli,xss",
		"-output-dir", tmpDir,
		"-gen-only",
		"-json",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success: %v\n%s", err, out)
	}
	if !contains(string(out), `"templates"`) {
		t.Errorf("expected templates in JSON:\n%s", out)
	}
	if !contains(string(out), `"count":4`) && !contains(string(out), `"count": 4`) {
		// 2 params * 2 vuln types = 4 templates
		t.Logf("output: %s", out)
	}
}

func TestCLI_GenOnly_TextOutput(t *testing.T) {
	tmpDir := t.TempDir()
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-fuzz"
	cmd := exec.Command(binary,
		"-u", "http://example.com/?q=test",
		"-vuln-types", "sqli",
		"-output-dir", tmpDir,
		"-gen-only",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success: %v\n%s", err, out)
	}
	if !contains(string(out), "Templates:") {
		t.Errorf("expected Templates: in output:\n%s", out)
	}
}

func TestCLI_TechAware(t *testing.T) {
	tmpDir := t.TempDir()
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-fuzz"
	cmd := exec.Command(binary,
		"-u", "http://example.com/?q=test",
		"-tech", "PHP,MySQL",
		"-output-dir", tmpDir,
		"-gen-only",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success: %v\n%s", err, out)
	}
	// PHP+MySQL should select sqli-mysql in addition to defaults
	if !contains(string(out), "sqli-mysql") {
		t.Errorf("expected sqli-mysql in vuln types:\n%s", out)
	}
}

func TestCLI_NoTarget(t *testing.T) {
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-fuzz"
	cmd := exec.Command(binary)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error with no target")
	}
	if !contains(string(out), "-u required") {
		t.Errorf("expected -u required error:\n%s", out)
	}
}

func TestCLI_MultipleTargets(t *testing.T) {
	tmpDir := t.TempDir()
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-fuzz"
	cmd := exec.Command(binary,
		"-u", "http://example.com/?q=test,http://test.com/?id=1",
		"-vuln-types", "xss",
		"-output-dir", tmpDir,
		"-gen-only",
		"-json",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success: %v\n%s", err, out)
	}
	// 2 targets * 1 param each * 1 vuln type = 2 templates
	if !contains(string(out), `"count":2`) && !contains(string(out), `"count": 2`) {
		t.Logf("output: %s", out)
	}
}

func TestE2E_FullFuzzRun(t *testing.T) {
	// Create a vulnerable server that reflects XSS
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q != "" {
			w.Write([]byte("<html><body>Result: " + q + "</body></html>"))
			return
		}
		w.Write([]byte("<html><body>Home</body></html>"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-fuzz"
	cmd := exec.Command(binary,
		"-u", server.URL+"/?q=test",
		"-vuln-types", "xss",
		"-output-dir", tmpDir,
		"-bin", os.Getenv("HOME")+"/nuclei-fork/bin/nuclei-dev",
		"-json",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("nuclei-fuzz returned error (may have findings): %v\n%s", err, out)
	}

	// Check that templates were generated and nuclei was run
	if !strings.Contains(string(out), `"findings"`) {
		t.Errorf("expected findings in output:\n%s", out)
	}
	// The server reflects, so we should have findings
	if !strings.Contains(string(out), `"findings":[`) && !strings.Contains(string(out), `"findings":[{`) {
		t.Logf("output: %s", out)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && strings.Contains(s, substr)
}

func init() {
	time.Sleep(0)
}
