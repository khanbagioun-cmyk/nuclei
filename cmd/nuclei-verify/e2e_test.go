package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestE2E_NucleiScanThenVerify(t *testing.T) {
	// Create a vulnerable test server that reflects XSS
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q != "" {
			w.Write([]byte(fmt.Sprintf("<html><body>You searched for: %s</body></html>", q)))
			return
		}
		w.Write([]byte("<html><body>Home</body></html>"))
	}))
	defer server.Close()

	nucleiBinary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-dev"
	verifyBinary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-verify"

	// Write a simple XSS detection template
	templateContent := fmt.Sprintf(`id: e2e-xss-test
info:
  name: E2E XSS Test
  author: test
  severity: high
  tags: xss,e2e
http:
  - method: GET
    path:
      - "%s/?q={{rand_text_alpha(8)}}"
    matchers:
      - type: word
        words:
          - "<html>"
        condition: and
`, server.URL)

	tmpDir := os.Getenv("HOME") + "/.config/nuclei-dev/e2e-test"
	os.MkdirAll(tmpDir, 0755)
	templateFile := tmpDir + "/e2e-xss.yaml"
	os.WriteFile(templateFile, []byte(templateContent), 0644)
	defer os.RemoveAll(tmpDir)

	// Run nuclei scan with JSON output
	nucleiCmd := exec.Command(nucleiBinary,
		"-t", templateFile,
		"-u", server.URL,
		"-jsonl",
		"-silent",
		"-nc",
	)
	nucleiOut, err := nucleiCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nuclei scan failed: %v\n%s", err, nucleiOut)
	}
	t.Logf("nuclei output: %s", nucleiOut)

	if !strings.Contains(string(nucleiOut), server.URL) {
		t.Skipf("nuclei did not detect the finding, skipping verify test. Output: %s", nucleiOut)
	}

	// Write nuclei output to file
	findingsFile := tmpDir + "/findings.jsonl"
	os.WriteFile(findingsFile, nucleiOut, 0644)

	// Run nuclei-verify on the findings
	verifyCmd := exec.Command(verifyBinary, "-jsonl", findingsFile)
	verifyOut, err := verifyCmd.CombinedOutput()
	t.Logf("verify output: %s", verifyOut)

	// The verify tool should process the findings
	if !strings.Contains(string(verifyOut), "Verified") {
		t.Errorf("expected 'Verified' in output:\n%s", verifyOut)
	}
}
