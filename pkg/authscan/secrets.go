package authscan

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SecretsFile represents a nuclei-compatible authx secrets file
type SecretsFile struct {
	ID      string       `yaml:"id"`
	Info    FileInfo     `yaml:"info"`
	Secrets []SecretDef  `yaml:"static"`
}

// FileInfo is metadata for the secrets file
type FileInfo struct {
	Name        string `yaml:"name"`
	Author      string `yaml:"author"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
}

// SecretDef is a single secret definition matching authx.Secret
type SecretDef struct {
	Type         string      `yaml:"type"`
	Domains      []string    `yaml:"domains"`
	Headers      []HeaderDef `yaml:"headers,omitempty"`
	Cookies      []CookieDef `yaml:"cookies,omitempty"`
	Username     string      `yaml:"username,omitempty"`
	Password     string      `yaml:"password,omitempty"`
	Token        string      `yaml:"token,omitempty"`
}

// HeaderDef is a key-value header pair
type HeaderDef struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

// CookieDef is a key-value cookie pair
type CookieDef struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

// GenerateSecretsFile creates a nuclei-compatible secrets YAML file from an authenticated session.
// This file can be passed to nuclei via -sf flag to apply auth to all scan requests.
func GenerateSecretsFile(session *Session, outputPath string) error {
	if session == nil {
		return fmt.Errorf("nil session")
	}

	domain := session.domain
	if domain == "" {
		return fmt.Errorf("domain is required to generate secrets file")
	}

	secret := SecretDef{
		Domains: []string{domain},
	}

	session.mu.RLock()
	defer session.mu.RUnlock()

	switch strings.ToLower(session.config.Method) {
	case "basic":
		secret.Type = "BasicAuth"
		secret.Username = session.config.Username
		secret.Password = session.config.Password
	case "bearer", "oauth2":
		secret.Type = "BearerToken"
		secret.Token = session.token
	case "header":
		secret.Type = "Header"
		for _, h := range session.config.Headers {
			secret.Headers = append(secret.Headers, HeaderDef{
				Key:   h.Key,
				Value: h.Value,
			})
		}
	case "cookie", "form":
		secret.Type = "Cookie"
		for _, c := range session.cookies {
			secret.Cookies = append(secret.Cookies, CookieDef{
				Key:   c.Name,
				Value: c.Value,
			})
		}
	default:
		return fmt.Errorf("unsupported method for secrets file: %s", session.config.Method)
	}

	sf := SecretsFile{
		ID: "authscan-session",
		Info: FileInfo{
			Name:        "AuthScan Generated Secrets",
			Author:      "nuclei-auth",
			Severity:    "info",
			Description: fmt.Sprintf("Auto-generated from %s auth session at %s", session.config.Method, time.Now().Format(time.RFC3339)),
		},
		Secrets: []SecretDef{secret},
	}

	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		os.MkdirAll(dir, 0755)
	}

	data, err := yaml.Marshal(sf)
	if err != nil {
		return fmt.Errorf("failed to marshal secrets file: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write secrets file: %w", err)
	}

	return nil
}

// SessionMonitor periodically checks session validity and re-authenticates if needed.
// It runs in a goroutine and can be stopped via Stop().
type SessionMonitor struct {
	session  *Session
	interval time.Duration
	stopCh   chan struct{}
	done     chan struct{}
}

// NewSessionMonitor creates a session monitor that checks every interval
func NewSessionMonitor(session *Session, interval time.Duration) *SessionMonitor {
	if interval == 0 {
		interval = 5 * time.Minute
	}
	return &SessionMonitor{
		session:  session,
		interval: interval,
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start begins monitoring the session in a background goroutine
func (m *SessionMonitor) Start() {
	go func() {
		defer close(m.done)
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if m.session.IsExpired() {
					_ = m.session.Authenticate()
				}
			case <-m.stopCh:
				return
			}
		}
	}()
}

// Stop stops the session monitor
func (m *SessionMonitor) Stop() {
	select {
	case <-m.stopCh:
		// already closed
	default:
		close(m.stopCh)
	}
	<-m.done
}

// WrapTransport wraps an HTTP transport to inject session credentials into all requests
func (s *Session) WrapTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &sessionTransport{
		base:    base,
		session: s,
	}
}

type sessionTransport struct {
	base    http.RoundTripper
	session *Session
}

func (t *sessionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Ensure session is valid before each request
	_ = t.session.EnsureValid()

	// Apply session credentials
	t.session.ApplyToRequest(req)

	return t.base.RoundTrip(req)
}
