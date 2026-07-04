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

func TestCLI_BearerAuthOnly(t *testing.T) {
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-auth"
	cmd := exec.Command(binary,
		"-method", "bearer",
		"-token", "test-token-123",
		"-domain", "example.com",
		"-auth-only",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success, got: %v\n%s", err, out)
	}
	if !contains(string(out), "Authentication successful") {
		t.Errorf("expected 'Authentication successful':\n%s", out)
	}
}

func TestCLI_BearerAuthOnly_JSON(t *testing.T) {
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-auth"
	cmd := exec.Command(binary,
		"-method", "bearer",
		"-token", "test-token-123",
		"-domain", "example.com",
		"-auth-only",
		"-json",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success: %v\n%s", err, out)
	}
	if !contains(string(out), `"method":"bearer"`) {
		t.Errorf("expected JSON with method bearer:\n%s", out)
	}
	if !contains(string(out), `"has_token":true`) {
		t.Errorf("expected has_token true:\n%s", out)
	}
}

func TestCLI_GenSecrets(t *testing.T) {
	tmpDir := t.TempDir()
	secretsPath := tmpDir + "/secrets.yaml"

	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-auth"
	cmd := exec.Command(binary,
		"-method", "bearer",
		"-token", "test-token-123",
		"-domain", "example.com",
		"-gen-secrets", secretsPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success: %v\n%s", err, out)
	}

	data, err := os.ReadFile(secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(data), "BearerToken") {
		t.Errorf("expected BearerToken in secrets file:\n%s", data)
	}
}

func TestCLI_CookieAuth(t *testing.T) {
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-auth"
	cmd := exec.Command(binary,
		"-method", "cookie",
		"-cookies", "session=abc123,csrf=xyz",
		"-domain", "example.com",
		"-auth-only",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success: %v\n%s", err, out)
	}
	if !contains(string(out), "Cookies: 2") {
		t.Errorf("expected 2 cookies:\n%s", out)
	}
}

func TestCLI_HeaderAuth(t *testing.T) {
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-auth"
	cmd := exec.Command(binary,
		"-method", "header",
		"-headers", "X-API-Key:mykey123,X-Tenant:acme",
		"-domain", "example.com",
		"-auth-only",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success: %v\n%s", err, out)
	}
	if !contains(string(out), "Authentication successful") {
		t.Errorf("expected success:\n%s", out)
	}
}

func TestCLI_FormLogin(t *testing.T) {
	loginHTML := `<html><body>
<form action="/login" method="POST">
	<input type="text" name="username" />
	<input type="password" name="password" />
	<button>Login</button>
</form>
</body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/login" {
			w.Write([]byte(loginHTML))
			return
		}
		if r.Method == "POST" && r.URL.Path == "/login" {
			r.ParseForm()
			if r.FormValue("username") == "admin" && r.FormValue("password") == "secret" {
				http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "sess-abc"})
				w.WriteHeader(200)
				return
			}
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-auth"
	cmd := exec.Command(binary,
		"-method", "form",
		"-login-url", server.URL+"/login",
		"-username", "admin",
		"-password", "secret",
		"-domain", "127.0.0.1",
		"-auth-only",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success: %v\n%s", err, out)
	}
	if !contains(string(out), "Authentication successful") {
		t.Errorf("expected success:\n%s", out)
	}
	if !contains(string(out), "Cookies: 1") {
		t.Errorf("expected 1 cookie:\n%s", out)
	}
}

func TestCLI_OAuth2(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"tok-oauth-123","expires_in":3600}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-auth"
	cmd := exec.Command(binary,
		"-method", "oauth2",
		"-oauth2-id", "client-123",
		"-oauth2-secret", "secret-456",
		"-oauth2-token-url", server.URL+"/token",
		"-domain", "api.example.com",
		"-auth-only",
		"-json",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success: %v\n%s", err, out)
	}
	if !contains(string(out), `"method":"oauth2"`) {
		t.Errorf("expected oauth2 method:\n%s", out)
	}
	if !contains(string(out), `"has_token":true`) {
		t.Errorf("expected has_token true:\n%s", out)
	}
}

func TestCLI_MissingDomain(t *testing.T) {
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-auth"
	cmd := exec.Command(binary,
		"-method", "bearer",
		"-token", "test",
		"-auth-only",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error for missing domain")
	}
	if !contains(string(out), "domain is required") {
		t.Errorf("expected domain error:\n%s", out)
	}
}

func TestCLI_InvalidMethod(t *testing.T) {
	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-auth"
	cmd := exec.Command(binary,
		"-method", "invalid",
		"-domain", "example.com",
		"-auth-only",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error for invalid method")
	}
	if !contains(string(out), "unsupported method") {
		t.Errorf("expected unsupported method error:\n%s", out)
	}
}

func TestE2E_FullScan(t *testing.T) {
	// Create a server with a protected endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for auth
		auth := r.Header.Get("Authorization")
		cookie := r.Header.Get("Cookie")

		if r.URL.Path == "/api/secret" {
			if auth == "Bearer test-token" || strings.Contains(cookie, "session=valid") {
				w.Write([]byte(`{"secret": "admin-password-123"}`))
				return
			}
			w.WriteHeader(401)
			w.Write([]byte("unauthorized"))
			return
		}
		w.Write([]byte("home"))
	}))
	defer server.Close()

	binary := os.Getenv("HOME") + "/nuclei-fork/bin/nuclei-auth"

	// Write a simple template for the post-auth scan
	tmpDir := t.TempDir()
	templateContent := `id: authscan-e2e-test
info:
  name: AuthScan E2E
  author: test
  severity: high
  tags: authscan,e2e
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/secret"
    matchers:
      - type: word
        words:
          - "admin-password"
`
	templateFile := tmpDir + "/e2e-template.yaml"
	os.WriteFile(templateFile, []byte(templateContent), 0644)

	cmd := exec.Command(binary,
		"-method", "bearer",
		"-token", "test-token",
		"-domain", "127.0.0.1",
		"-targets", server.URL,
		"-post-auth-t", templateFile,
		"-output-dir", tmpDir+"/results",
		"-json",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scan failed: %v\n%s", err, out)
	}

	if !contains(string(out), `"auth_success":true`) {
		t.Errorf("expected auth_success true:\n%s", out)
	}
	if !contains(string(out), `"post_auth_findings"`) {
		t.Errorf("expected post_auth_findings:\n%s", out)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && strings.Contains(s, substr)
}

func init() {
	time.Sleep(0)
}
