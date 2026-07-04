// Package authscan provides authenticated scanning capabilities for nuclei.
// It extends the existing authprovider framework with:
// - Auto-login form discovery (detect login forms, fill credentials, extract session cookies)
// - OAuth2 client credentials flow (automated token acquisition + refresh)
// - Session monitor (detects session expiry, auto-refreshes credentials)
// - Pre-auth/post-auth template orchestration
package authscan

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuthConfig configures the authenticated scanning layer
type AuthConfig struct {
	// Target URL for the login endpoint (auto-discovered if empty for form login)
	LoginURL string `yaml:"login_url" json:"login_url"`
	// Auth method: form, basic, bearer, oauth2, cookie, header
	Method string `yaml:"method" json:"method"`
	// Credentials
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
	// Token for bearer/header auth
	Token string `yaml:"token" json:"token"`
	// OAuth2 config
	OAuth2ClientID     string `yaml:"oauth2_client_id" json:"oauth2_client_id"`
	OAuth2ClientSecret string `yaml:"oauth2_client_secret" json:"oauth2_client_secret"`
	OAuth2TokenURL     string `yaml:"oauth2_token_url" json:"oauth2_token_url"`
	OAuth2Scopes       string `yaml:"oauth2_scopes" json:"oauth2_scopes"`
	// Cookie/domain for cookie auth
	Cookies []CookieConfig `yaml:"cookies" json:"cookies"`
	Domain  string         `yaml:"domain" json:"domain"`
	// Headers for header auth
	Headers []HeaderConfig `yaml:"headers" json:"headers"`
	// Form login field name overrides (auto-detected if empty)
	UsernameField string `yaml:"username_field" json:"username_field"`
	PasswordField string `yaml:"password_field" json:"password_field"`
	// Session expiry detection
	SessionCheckURL    string        `yaml:"session_check_url" json:"session_check_url"`
	SessionExpiry      time.Duration `yaml:"session_expiry" json:"session_expiry"`
	// HTTP timeout for auth requests
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
	// InsecureSkipVerify skips TLS verification
	InsecureSkipVerify bool `yaml:"insecure" json:"insecure"`
}

// CookieConfig defines a cookie for authentication
type CookieConfig struct {
	Key   string `yaml:"key" json:"key"`
	Value string `yaml:"value" json:"value"`
	Raw   string `yaml:"raw" json:"raw"`
}

// HeaderConfig defines a header for authentication
type HeaderConfig struct {
	Key   string `yaml:"key" json:"key"`
	Value string `yaml:"value" json:"value"`
}

// Session represents an authenticated session
type Session struct {
	mu          sync.RWMutex
	cookies     []*http.Cookie
	token       string
	tokenExpiry time.Time
	domain      string
	client      *http.Client
	jar         *cookiejar.Jar
	config      *AuthConfig
	lastRefresh time.Time
}

// NewSession creates a new authentication session
func NewSession(cfg *AuthConfig) (*Session, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.SessionExpiry == 0 {
		cfg.SessionExpiry = 30 * time.Minute
	}

	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
	}
	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow up to 10 redirects, preserving cookies
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	return &Session{
		client: client,
		jar:    jar,
		config: cfg,
		domain: cfg.Domain,
	}, nil
}

// Authenticate performs the authentication based on the configured method
func (s *Session) Authenticate() error {
	switch strings.ToLower(s.config.Method) {
	case "form":
		return s.authenticateForm()
	case "basic":
		return s.authenticateBasic()
	case "bearer":
		return s.authenticateBearer()
	case "oauth2":
		return s.authenticateOAuth2()
	case "cookie":
		return s.authenticateCookie()
	case "header":
		return s.authenticateHeader()
	default:
		return fmt.Errorf("unsupported auth method: %s", s.config.Method)
	}
}

// GetClient returns the HTTP client with session cookies/token attached
func (s *Session) GetClient() *http.Client {
	return s.client
}

// GetCookies returns the current session cookies
func (s *Session) GetCookies() []*http.Cookie {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cookies
}

// GetToken returns the current bearer token (for OAuth2/bearer auth)
func (s *Session) GetToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Token-based auth: check token expiry
	if s.token != "" && !s.tokenExpiry.IsZero() {
		return time.Now().After(s.tokenExpiry)
	}

	// Cookie-based auth: check session expiry
	if !s.lastRefresh.IsZero() && s.config.SessionExpiry > 0 {
		return time.Now().After(s.lastRefresh.Add(s.config.SessionExpiry))
	}

	return false
}

// EnsureValid checks if the session is valid and re-authenticates if expired
func (s *Session) EnsureValid() error {
	if !s.IsExpired() {
		return nil
	}
	return s.Authenticate()
}

// ApplyToRequest applies the session credentials to an HTTP request
func (s *Session) ApplyToRequest(req *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Apply basic auth
	if strings.ToLower(s.config.Method) == "basic" && s.config.Username != "" {
		req.SetBasicAuth(s.config.Username, s.config.Password)
	}

	// Apply cookies (jar handles this automatically, but also set manually for safety)
	for _, cookie := range s.cookies {
		req.AddCookie(cookie)
	}

	// Apply token if present
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	// Apply custom headers
	for _, h := range s.config.Headers {
		req.Header.Set(h.Key, h.Value)
	}
}

// --- Basic Auth ---

func (s *Session) authenticateBasic() error {
	if s.config.Username == "" || s.config.Password == "" {
		return fmt.Errorf("basic auth requires username and password")
	}
	// Basic auth doesn't need a login request — credentials are sent per-request
	// Store credentials for ApplyToRequest
	s.mu.Lock()
	s.lastRefresh = time.Now()
	s.mu.Unlock()
	return nil
}

// --- Bearer Token Auth ---

func (s *Session) authenticateBearer() error {
	if s.config.Token == "" {
		return fmt.Errorf("bearer auth requires token")
	}
	s.mu.Lock()
	s.token = s.config.Token
	s.lastRefresh = time.Now()
	// Bearer tokens don't have a known expiry; use configured session expiry
	s.tokenExpiry = time.Now().Add(s.config.SessionExpiry)
	s.mu.Unlock()
	return nil
}

// --- Header Auth ---

func (s *Session) authenticateHeader() error {
	if len(s.config.Headers) == 0 {
		return fmt.Errorf("header auth requires at least one header")
	}
	s.mu.Lock()
	s.lastRefresh = time.Now()
	s.mu.Unlock()
	return nil
}

// --- Cookie Auth ---

func (s *Session) authenticateCookie() error {
	if len(s.config.Cookies) == 0 {
		return fmt.Errorf("cookie auth requires at least one cookie")
	}
	s.mu.Lock()
	s.cookies = nil
	for _, c := range s.config.Cookies {
		cookie := &http.Cookie{
			Name:  c.Key,
			Value: c.Value,
		}
		if c.Raw != "" {
			parsed := parseRawCookie(c.Raw)
			if parsed != nil {
				cookie = parsed
			}
		}
		s.cookies = append(s.cookies, cookie)
	}
	s.lastRefresh = time.Now()
	s.mu.Unlock()
	return nil
}

// parseRawCookie parses a raw Set-Cookie header value
func parseRawCookie(raw string) *http.Cookie {
	raw = strings.TrimPrefix(raw, "Set-Cookie: ")
	parts := strings.SplitN(raw, ";", 2)
	if len(parts) == 0 {
		return nil
	}
	kv := strings.SplitN(parts[0], "=", 2)
	if len(kv) != 2 {
		return nil
	}
	return &http.Cookie{
		Name:  strings.TrimSpace(kv[0]),
		Value: strings.TrimSpace(kv[1]),
	}
}

// --- Form Login ---

func (s *Session) authenticateForm() error {
	loginURL := s.config.LoginURL
	if loginURL == "" {
		return fmt.Errorf("form auth requires login_url")
	}
	if s.config.Username == "" || s.config.Password == "" {
		return fmt.Errorf("form auth requires username and password")
	}

	// Step 1: GET the login page to discover the form
	resp, err := s.client.Get(loginURL)
	if err != nil {
		return fmt.Errorf("failed to fetch login page: %w", err)
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	// Step 2: Parse the form to find field names and action URL
	formData, formAction, err := parseLoginForm(resp, loginURL, s.config.UsernameField, s.config.PasswordField)
	if err != nil {
		return fmt.Errorf("failed to parse login form: %w", err)
	}

	// Fill credentials
	formData.Set(formData.Get("__username_field__"), s.config.Username)
	formData.Set(formData.Get("__password_field__"), s.config.Password)
	formData.Del("__username_field__")
	formData.Del("__password_field__")

	// Step 3: POST credentials to the form action URL
	actionURL := formAction
	if actionURL == "" {
		actionURL = loginURL
	}
	resp2, err := s.client.PostForm(actionURL, formData)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	if resp2.Body != nil {
		defer resp2.Body.Close()
	}

	// Step 4: Extract session cookies from the response
	s.mu.Lock()
	s.cookies = s.jar.Cookies(resp2.Request.URL)
	s.lastRefresh = time.Now()
	s.mu.Unlock()

	// Check for login success: cookies present OR 200/302 status
	if len(s.cookies) > 0 || resp2.StatusCode == 200 || resp2.StatusCode == 302 {
		return nil
	}

	return fmt.Errorf("login failed with status %d", resp2.StatusCode)
}

// --- OAuth2 ---

func (s *Session) authenticateOAuth2() error {
	if s.config.OAuth2ClientID == "" || s.config.OAuth2ClientSecret == "" || s.config.OAuth2TokenURL == "" {
		return fmt.Errorf("oauth2 requires client_id, client_secret, and token_url")
	}

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {s.config.OAuth2ClientID},
		"client_secret": {s.config.OAuth2ClientSecret},
	}
	if s.config.OAuth2Scopes != "" {
		data.Set("scope", s.config.OAuth2Scopes)
	}

	resp, err := s.client.PostForm(s.config.OAuth2TokenURL, data)
	if err != nil {
		return fmt.Errorf("oauth2 token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("oauth2 token request failed with status %d", resp.StatusCode)
	}

	token, expiry, err := parseOAuth2TokenResponse(resp)
	if err != nil {
		return fmt.Errorf("failed to parse oauth2 token response: %w", err)
	}

	s.mu.Lock()
	s.token = token
	s.tokenExpiry = expiry
	s.lastRefresh = time.Now()
	s.mu.Unlock()

	return nil
}
