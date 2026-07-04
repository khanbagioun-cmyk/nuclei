package authscan

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSession_BasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(401)
			return
		}
		w.Write([]byte("authenticated"))
	}))
	defer server.Close()

	cfg := &AuthConfig{
		Method:   "basic",
		Username: "admin",
		Password: "secret",
		Domain:   "127.0.0.1",
		Timeout:  5 * time.Second,
	}

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := session.Authenticate(); err != nil {
		t.Fatalf("basic auth failed: %v", err)
	}

	if session.IsExpired() {
		t.Error("session should not be expired immediately after auth")
	}

	// Verify credentials are applied to requests
	req, _ := http.NewRequest("GET", server.URL+"/protected", nil)
	session.ApplyToRequest(req)
	user, pass, ok := req.BasicAuth()
	if !ok || user != "admin" || pass != "secret" {
		t.Errorf("basic auth not applied to request")
	}
}

func TestSession_BearerToken(t *testing.T) {
	cfg := &AuthConfig{
		Method:  "bearer",
		Token:   "my-jwt-token-123",
		Domain:  "example.com",
		Timeout: 5 * time.Second,
	}

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := session.Authenticate(); err != nil {
		t.Fatalf("bearer auth failed: %v", err)
	}

	if session.GetToken() != "my-jwt-token-123" {
		t.Errorf("expected token 'my-jwt-token-123', got '%s'", session.GetToken())
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)
	session.ApplyToRequest(req)
	auth := req.Header.Get("Authorization")
	if auth != "Bearer my-jwt-token-123" {
		t.Errorf("expected Bearer header, got '%s'", auth)
	}
}

func TestSession_CookieAuth(t *testing.T) {
	cfg := &AuthConfig{
		Method: "cookie",
		Domain: "example.com",
		Cookies: []CookieConfig{
			{Key: "session", Value: "abc123"},
			{Key: "csrf", Value: "xyz789"},
		},
		Timeout: 5 * time.Second,
	}

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := session.Authenticate(); err != nil {
		t.Fatalf("cookie auth failed: %v", err)
	}

	cookies := session.GetCookies()
	if len(cookies) != 2 {
		t.Errorf("expected 2 cookies, got %d", len(cookies))
	}

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	session.ApplyToRequest(req)
	cookieHeader := req.Header.Get("Cookie")
	if !strings.Contains(cookieHeader, "session=abc123") {
		t.Errorf("session cookie not in request: %s", cookieHeader)
	}
}

func TestSession_HeaderAuth(t *testing.T) {
	cfg := &AuthConfig{
		Method: "header",
		Domain: "example.com",
		Headers: []HeaderConfig{
			{Key: "X-API-Key", Value: "key123"},
			{Key: "X-Tenant", Value: "acme"},
		},
		Timeout: 5 * time.Second,
	}

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := session.Authenticate(); err != nil {
		t.Fatalf("header auth failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)
	session.ApplyToRequest(req)
	if req.Header.Get("X-API-Key") != "key123" {
		t.Errorf("X-API-Key not set")
	}
	if req.Header.Get("X-Tenant") != "acme" {
		t.Errorf("X-Tenant not set")
	}
}

func TestSession_FormLogin(t *testing.T) {
	// Simulate a login form page
	loginHTML := `<html><body>
<form action="/login" method="POST">
	<input type="text" name="username" />
	<input type="password" name="password" />
	<input type="hidden" name="csrf_token" value="abc123" />
	<button type="submit">Login</button>
</form>
</body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/login" {
			w.Write([]byte(loginHTML))
			return
		}
		if r.Method == "POST" && r.URL.Path == "/login" {
			r.ParseForm()
			user := r.FormValue("username")
			pass := r.FormValue("password")
			csrf := r.FormValue("csrf_token")
			if user == "admin" && pass == "secret" && csrf == "abc123" {
				http.SetCookie(w, &http.Cookie{
					Name:  "session_id",
					Value: "sess-" + user,
					Path:  "/",
				})
				http.Redirect(w, r, "/dashboard", 302)
				return
			}
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	cfg := &AuthConfig{
		Method:   "form",
		LoginURL: server.URL + "/login",
		Username: "admin",
		Password: "secret",
		Domain:   "127.0.0.1",
		Timeout:  10 * time.Second,
	}

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := session.Authenticate(); err != nil {
		t.Fatalf("form login failed: %v", err)
	}

	cookies := session.GetCookies()
	if len(cookies) == 0 {
		t.Error("expected session cookies after login")
	}

	found := false
	for _, c := range cookies {
		if c.Name == "session_id" && strings.HasPrefix(c.Value, "sess-") {
			found = true
		}
	}
	if !found {
		t.Error("session_id cookie not found")
	}
}

func TestSession_FormLogin_AutoDetectFields(t *testing.T) {
	// Form with non-standard field names
	loginHTML := `<html><body>
<form action="/auth" method="POST">
	<input type="email" name="email_addr" />
	<input type="password" name="passwd" />
	<button>Login</button>
</form>
</body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(loginHTML))
			return
		}
		r.ParseForm()
		if r.FormValue("email_addr") == "user@test.com" && r.FormValue("passwd") == "pass123" {
			http.SetCookie(w, &http.Cookie{Name: "auth", Value: "token-xyz"})
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(401)
	}))
	defer server.Close()

	cfg := &AuthConfig{
		Method:   "form",
		LoginURL: server.URL,
		Username: "user@test.com",
		Password: "pass123",
		Domain:   "127.0.0.1",
		Timeout:  10 * time.Second,
		// UsernameField and PasswordField intentionally empty for auto-detection
	}

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := session.Authenticate(); err != nil {
		t.Fatalf("form login with auto-detect failed: %v", err)
	}

	cookies := session.GetCookies()
	found := false
	for _, c := range cookies {
		if c.Name == "auth" {
			found = true
		}
	}
	if !found {
		t.Error("auth cookie not found after auto-detect login")
	}
}

func TestSession_OAuth2(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/token" {
			r.ParseForm()
			if r.FormValue("grant_type") != "client_credentials" {
				w.WriteHeader(400)
				return
			}
			if r.FormValue("client_id") != "test-client" {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"tok-123456","token_type":"Bearer","expires_in":3600}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	cfg := &AuthConfig{
		Method:             "oauth2",
		OAuth2ClientID:     "test-client",
		OAuth2ClientSecret: "test-secret",
		OAuth2TokenURL:     server.URL + "/token",
		OAuth2Scopes:       "read write",
		Domain:             "api.example.com",
		Timeout:            5 * time.Second,
	}

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := session.Authenticate(); err != nil {
		t.Fatalf("oauth2 auth failed: %v", err)
	}

	if session.GetToken() != "tok-123456" {
		t.Errorf("expected token 'tok-123456', got '%s'", session.GetToken())
	}

	if session.IsExpired() {
		t.Error("token should not be expired immediately")
	}

	// Test token expiry
	session.mu.Lock()
	session.tokenExpiry = time.Now().Add(-time.Minute)
	session.mu.Unlock()

	if !session.IsExpired() {
		t.Error("token should be expired")
	}

	// Test re-authentication
	if err := session.EnsureValid(); err != nil {
		t.Fatalf("re-auth failed: %v", err)
	}

	if session.GetToken() != "tok-123456" {
		t.Errorf("expected token after refresh 'tok-123456', got '%s'", session.GetToken())
	}
}

func TestSession_OAuth2_InvalidCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer server.Close()

	cfg := &AuthConfig{
		Method:             "oauth2",
		OAuth2ClientID:     "bad-client",
		OAuth2ClientSecret: "bad-secret",
		OAuth2TokenURL:     server.URL + "/token",
		Domain:             "api.example.com",
		Timeout:            5 * time.Second,
	}

	session, _ := NewSession(cfg)
	err := session.Authenticate()
	if err == nil {
		t.Error("expected error for invalid OAuth2 credentials")
	}
}

func TestSession_UnsupportedMethod(t *testing.T) {
	cfg := &AuthConfig{
		Method: "invalid",
		Domain: "example.com",
	}
	session, _ := NewSession(cfg)
	err := session.Authenticate()
	if err == nil {
		t.Error("expected error for unsupported method")
	}
}

func TestSession_FormLogin_NoForm(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>No form here</body></html>"))
	}))
	defer server.Close()

	cfg := &AuthConfig{
		Method:   "form",
		LoginURL: server.URL,
		Username: "admin",
		Password: "secret",
		Domain:   "127.0.0.1",
		Timeout:  5 * time.Second,
	}

	session, _ := NewSession(cfg)
	err := session.Authenticate()
	if err == nil {
		t.Error("expected error when no login form found")
	}
	if !strings.Contains(err.Error(), "no login form") {
		t.Errorf("expected 'no login form' error, got: %v", err)
	}
}

func TestSession_FormLogin_BadCredentials(t *testing.T) {
	loginHTML := `<html><body>
<form action="/login" method="POST">
	<input type="text" name="username" />
	<input type="password" name="password" />
	<button>Login</button>
</form>
</body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(loginHTML))
			return
		}
		w.WriteHeader(401)
	}))
	defer server.Close()

	cfg := &AuthConfig{
		Method:   "form",
		LoginURL: server.URL + "/login",
		Username: "wrong",
		Password: "creds",
		Domain:   "127.0.0.1",
		Timeout:  5 * time.Second,
	}

	session, _ := NewSession(cfg)
	err := session.Authenticate()
	if err == nil {
		t.Error("expected error for bad credentials")
	}
}

func TestParseRawCookie(t *testing.T) {
	c := parseRawCookie("Set-Cookie: session=abc123; Path=/; HttpOnly")
	if c == nil {
		t.Fatal("expected cookie")
	}
	if c.Name != "session" || c.Value != "abc123" {
		t.Errorf("expected session=abc123, got %s=%s", c.Name, c.Value)
	}
}

func TestGenerateSecretsFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := tmpDir + "/secrets.yaml"

	cfg := &AuthConfig{
		Method:  "bearer",
		Token:   "test-token",
		Domain:  "example.com",
		Timeout: 5 * time.Second,
	}

	session, _ := NewSession(cfg)
	if err := session.Authenticate(); err != nil {
		t.Fatal(err)
	}

	if err := GenerateSecretsFile(session, outputPath); err != nil {
		t.Fatalf("failed to generate secrets file: %v", err)
	}

	data, err := readFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(data, "BearerToken") {
		t.Error("expected BearerToken in secrets file")
	}
	if !strings.Contains(data, "example.com") {
		t.Error("expected domain in secrets file")
	}
	if !strings.Contains(data, "test-token") {
		t.Error("expected token in secrets file")
	}
}

func TestGenerateSecretsFile_BasicAuth(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &AuthConfig{
		Method:   "basic",
		Username: "admin",
		Password: "pass",
		Domain:   "example.com",
		Timeout:  5 * time.Second,
	}

	session, _ := NewSession(cfg)
	session.Authenticate()

	outputPath := tmpDir + "/basic-secrets.yaml"
	if err := GenerateSecretsFile(session, outputPath); err != nil {
		t.Fatalf("failed: %v", err)
	}

	data, _ := readFile(outputPath)
	if !strings.Contains(data, "BasicAuth") {
		t.Error("expected BasicAuth type")
	}
}

func TestGenerateSecretsFile_CookieAuth(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &AuthConfig{
		Method: "cookie",
		Domain: "example.com",
		Cookies: []CookieConfig{
			{Key: "session", Value: "abc"},
		},
		Timeout: 5 * time.Second,
	}

	session, _ := NewSession(cfg)
	session.Authenticate()

	outputPath := tmpDir + "/cookie-secrets.yaml"
	if err := GenerateSecretsFile(session, outputPath); err != nil {
		t.Fatalf("failed: %v", err)
	}

	data, _ := readFile(outputPath)
	if !strings.Contains(data, "Cookie") {
		t.Error("expected Cookie type")
	}
	if !strings.Contains(data, "key: session") || !strings.Contains(data, "value: abc") {
		t.Error("expected cookie key-value in secrets file")
	}
}

func TestSessionMonitor(t *testing.T) {
	cfg := &AuthConfig{
		Method:        "bearer",
		Token:         "test-token",
		Domain:        "example.com",
		Timeout:       5 * time.Second,
		SessionExpiry: 100 * time.Millisecond,
	}

	session, _ := NewSession(cfg)
	session.Authenticate()

	monitor := NewSessionMonitor(session, 50*time.Millisecond)
	monitor.Start()

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	if !session.IsExpired() {
		t.Log("session expired as expected")
	}

	monitor.Stop()
}

func TestSession_WrapTransport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	cfg := &AuthConfig{
		Method:  "bearer",
		Token:   "test-token",
		Domain:  "127.0.0.1",
		Timeout: 5 * time.Second,
	}

	session, _ := NewSession(cfg)
	session.Authenticate()

	client := &http.Client{
		Transport: session.WrapTransport(http.DefaultTransport),
	}

	resp, err := client.Get(server.URL + "/api")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSession_MissingConfig(t *testing.T) {
	// Basic auth without username
	cfg := &AuthConfig{
		Method: "basic",
		Domain: "example.com",
	}
	session, _ := NewSession(cfg)
	err := session.Authenticate()
	if err == nil || !strings.Contains(err.Error(), "username") {
		t.Errorf("expected username error, got: %v", err)
	}

	// Bearer without token
	cfg = &AuthConfig{Method: "bearer", Domain: "example.com"}
	session, _ = NewSession(cfg)
	err = session.Authenticate()
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Errorf("expected token error, got: %v", err)
	}

	// OAuth2 without client_id
	cfg = &AuthConfig{Method: "oauth2", Domain: "example.com"}
	session, _ = NewSession(cfg)
	err = session.Authenticate()
	if err == nil || !strings.Contains(err.Error(), "client_id") {
		t.Errorf("expected client_id error, got: %v", err)
	}
}

func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	return string(data), err
}
