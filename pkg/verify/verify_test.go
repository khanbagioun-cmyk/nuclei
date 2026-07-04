package verify

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifier_XSS_Reflection(t *testing.T) {
	// Server that reflects the param value unescaped
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Write([]byte("<html><body>Result: " + q + "</body></html>"))
	}))
	defer server.Close()

	v := NewVerifier(VerifierConfig{SafeMode: true, Timeout: 5 * time.Second})
	result := v.VerifyFinding("test-xss", server.URL, "xss", map[string]string{
		"param": "q",
		"path":  "/",
	})

	if !result.Verified {
		t.Errorf("expected XSS verified, got: %s (confidence: %.2f)", result.Evidence, result.Confidence)
	}
	if result.Confidence < 0.7 {
		t.Errorf("expected confidence >= 0.7, got %.2f", result.Confidence)
	}
	if !strings.Contains(result.Evidence, "reflected") {
		t.Errorf("evidence should mention reflection, got: %s", result.Evidence)
	}
}

func TestVerifier_XSS_NoReflection(t *testing.T) {
	// Server that does NOT reflect
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Search results</body></html>"))
	}))
	defer server.Close()

	v := NewVerifier(VerifierConfig{SafeMode: true, Timeout: 5 * time.Second})
	result := v.VerifyFinding("test-xss", server.URL, "xss", map[string]string{
		"param": "q",
		"path":  "/",
	})

	if result.Verified {
		t.Errorf("expected XSS NOT verified, got: %s", result.Evidence)
	}
	if result.Confidence > 0.5 {
		t.Errorf("expected low confidence, got %.2f", result.Confidence)
	}
}

func TestVerifier_PathTraversal_Success(t *testing.T) {
	// Server that serves /etc/passwd content when given traversal path
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "..") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
		} else {
			w.Write([]byte("not found"))
		}
	}))
	defer server.Close()

	v := NewVerifier(VerifierConfig{SafeMode: true, Timeout: 5 * time.Second})
	result := v.VerifyFinding("test-lfi", server.URL, "path-traversal", map[string]string{
		"param": "file",
		"path":  "/",
	})

	if !result.Verified {
		t.Errorf("expected path traversal verified, got: %s (confidence: %.2f)", result.Evidence, result.Confidence)
	}
	if result.Confidence < 0.9 {
		t.Errorf("expected confidence >= 0.9, got %.2f", result.Confidence)
	}
	if !strings.Contains(result.Evidence, "passwd") {
		t.Errorf("evidence should mention passwd, got: %s", result.Evidence)
	}
}

func TestVerifier_PathTraversal_NoVuln(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("404 not found"))
	}))
	defer server.Close()

	v := NewVerifier(VerifierConfig{SafeMode: true, Timeout: 5 * time.Second})
	result := v.VerifyFinding("test-lfi", server.URL, "lfi", map[string]string{
		"param": "file",
		"path":  "/",
	})

	if result.Verified {
		t.Errorf("expected path traversal NOT verified, got: %s", result.Evidence)
	}
}

func TestVerifier_OpenRedirect_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("redirect")
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		w.Write([]byte("home"))
	}))
	defer server.Close()

	v := NewVerifier(VerifierConfig{SafeMode: true, Timeout: 5 * time.Second})
	result := v.VerifyFinding("test-redirect", server.URL, "open-redirect", map[string]string{
		"param": "redirect",
		"path":  "/",
	})

	if !result.Verified {
		t.Errorf("expected open redirect verified, got: %s (confidence: %.2f)", result.Evidence, result.Confidence)
	}
	if result.Confidence < 0.9 {
		t.Errorf("expected confidence >= 0.9, got %.2f", result.Confidence)
	}
}

func TestVerifier_OpenRedirect_NoRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("home page"))
	}))
	defer server.Close()

	v := NewVerifier(VerifierConfig{SafeMode: true, Timeout: 5 * time.Second})
	result := v.VerifyFinding("test-redirect", server.URL, "open-redirect", map[string]string{
		"param": "redirect",
		"path":  "/",
	})

	if result.Verified {
		t.Errorf("expected open redirect NOT verified, got: %s", result.Evidence)
	}
}

func TestVerifier_SQLi_TimeDelay(t *testing.T) {
	// Server that sleeps when it sees SQLi payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(strings.ToLower(id), "sleep") {
			time.Sleep(5 * time.Second)
		}
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	v := NewVerifier(VerifierConfig{SafeMode: true, Timeout: 15 * time.Second})
	result := v.VerifyFinding("test-sqli", server.URL, "sqli", map[string]string{
		"param": "id",
		"path":  "/",
	})

	if !result.Verified {
		t.Errorf("expected SQLi verified, got: %s (confidence: %.2f)", result.Evidence, result.Confidence)
	}
	if result.Confidence < 0.85 {
		t.Errorf("expected confidence >= 0.85, got %.2f", result.Confidence)
	}
}

func TestVerifier_SQLi_NoDelay(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	v := NewVerifier(VerifierConfig{SafeMode: true, Timeout: 10 * time.Second})
	result := v.VerifyFinding("test-sqli", server.URL, "sql-injection", map[string]string{
		"param": "id",
		"path":  "/",
	})

	if result.Verified {
		t.Errorf("expected SQLi NOT verified, got: %s", result.Evidence)
	}
}

func TestVerifier_RCE_Timing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		if strings.Contains(cmd, "sleep") || strings.Contains(cmd, "ping") {
			time.Sleep(5 * time.Second)
		}
		w.Write([]byte("done"))
	}))
	defer server.Close()

	v := NewVerifier(VerifierConfig{SafeMode: true, Timeout: 15 * time.Second})
	result := v.VerifyFinding("test-rce", server.URL, "rce", map[string]string{
		"param": "cmd",
		"path":  "/",
	})

	if !result.Verified {
		t.Errorf("expected RCE verified, got: %s (confidence: %.2f)", result.Evidence, result.Confidence)
	}
}

func TestVerifier_UnknownVulnType(t *testing.T) {
	v := NewVerifier(VerifierConfig{SafeMode: true})
	result := v.VerifyFinding("test", "http://example.com", "csrf", nil)

	if result.Verified {
		t.Error("expected NOT verified for unknown vuln type")
	}
	if result.Confidence > 0.4 {
		t.Errorf("expected low confidence for unknown type, got %.2f", result.Confidence)
	}
	if result.Method != "none" {
		t.Errorf("expected method 'none', got '%s'", result.Method)
	}
}

func TestVerifier_SSRF_NoOAST(t *testing.T) {
	v := NewVerifier(VerifierConfig{SafeMode: true, Timeout: 5 * time.Second})
	result := v.VerifyFinding("test-ssrf", "http://example.com", "ssrf", map[string]string{
		"param": "url",
		"path":  "/",
	})

	if result.Verified {
		t.Error("expected SSRF NOT verified without OAST")
	}
	if result.Confidence > 0.4 {
		t.Errorf("expected low confidence without OAST, got %.2f", result.Confidence)
	}
}

func TestVerifier_SSRF_WithOAST(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	v := NewVerifier(VerifierConfig{
		SafeMode:   true,
		OastDomain: "oast.localtest",
		OastToken:  "test-token",
		Timeout:    10 * time.Second,
	})
	result := v.VerifyFinding("test-ssrf", server.URL, "ssrf", map[string]string{
		"param": "url",
		"path":  "/",
	})

	if result.Verified {
		// Can't truly verify without Interactsh API callback check
	}
	if result.Confidence < 0.5 {
		t.Errorf("expected confidence >= 0.5 with OAST configured, got %.2f", result.Confidence)
	}
	if !strings.Contains(result.Evidence, "oast") {
		t.Errorf("evidence should mention OAST, got: %s", result.Evidence)
	}
}
