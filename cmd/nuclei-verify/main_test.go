package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestCLI_SingleVerify_XSS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Write([]byte("<html>" + q + "</html>"))
	}))
	defer server.Close()

	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-verify"
	cmd := exec.Command(binary,
		"-host", server.URL,
		"-type", "xss",
		"-param", "q",
		"-path", "/",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected exit 0 for verified, got err: %v\noutput: %s", err, out)
	}
	if !contains(string(out), "VERIFIED") {
		t.Errorf("expected VERIFIED in output:\n%s", out)
	}
}

func TestCLI_SingleVerify_NotVuln(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("safe page"))
	}))
	defer server.Close()

	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-verify"
	cmd := exec.Command(binary,
		"-host", server.URL,
		"-type", "xss",
		"-param", "q",
		"-path", "/",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for NOT VERIFIED")
	}
	if !contains(string(out), "NOT VERIFIED") {
		t.Errorf("expected NOT VERIFIED in output:\n%s", out)
	}
}

func TestCLI_JSONL_Batch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Write([]byte("<html>" + q + "</html>"))
	}))
	defer server.Close()

	jsonl := fmt.Sprintf(`{"template-id":"xss-reflected","host":"%s","type":"xss","matcher-name":"reflected"}
{"template-id":"sqli-test","host":"%s","type":"sqli","matcher-name":"time-delay"}
`, server.URL, server.URL)

	tmpFile := os.Getenv("HOME") + "/.config/nuclei-dev/test-findings.jsonl"
	os.WriteFile(tmpFile, []byte(jsonl), 0644)
	defer os.Remove(tmpFile)

	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-verify"
	cmd := exec.Command(binary, "-jsonl", tmpFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// batch mode doesn't exit non-zero
	}
	if !contains(string(out), "Verified 2 findings") {
		t.Errorf("expected 'Verified 2 findings' in output:\n%s", out)
	}
	if !contains(string(out), "Summary:") {
		t.Errorf("expected Summary in output:\n%s", out)
	}
}

func TestCLI_JSON_Output(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Write([]byte("<html>" + q + "</html>"))
	}))
	defer server.Close()

	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-verify"
	cmd := exec.Command(binary,
		"-host", server.URL,
		"-type", "xss",
		"-param", "q",
		"-json",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected exit 0, got: %v\n%s", err, out)
	}
	if !contains(string(out), `"verified":true`) {
		t.Errorf("expected JSON with verified:true:\n%s", out)
	}
}

func TestCLI_NoArgs(t *testing.T) {
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-verify"
	cmd := exec.Command(binary)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit with no args")
	}
	if !contains(string(out), "Usage:") {
		t.Errorf("expected usage message:\n%s", out)
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

func init() {
	time.Sleep(0)
}
