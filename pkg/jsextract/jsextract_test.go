package jsextract

import (
	"strings"
	"testing"
)

func TestExtract_Endpoints(t *testing.T) {
	js := `
		fetch("/api/v1/users", {method: "POST"});
		axios.get("/api/v1/products");
		$.ajax({url: "/api/v1/login"});
		axios.post("/api/v1/orders", {data: {id: 1}});
	`
	ext := New()
	result := ext.Extract(js, "https://example.com/app.js")

	if len(result.Endpoints) < 3 {
		t.Errorf("expected at least 3 endpoints, got %d", len(result.Endpoints))
	}

	paths := make(map[string]bool)
	for _, ep := range result.Endpoints {
		paths[ep.Path] = true
	}
	if !paths["/api/v1/users"] {
		t.Error("expected /api/v1/users")
	}
	if !paths["/api/v1/products"] {
		t.Error("expected /api/v1/products")
	}
	if !paths["/api/v1/login"] {
		t.Error("expected /api/v1/login")
	}
}

func TestExtract_Secrets(t *testing.T) {
	js := `
		var apiKey = "ak_TESTKEY12345678";
		var token = "bearer_TESTTOKEN123456";
		var awsKey = "AKIAFAKEFAKEFAKEFAKE";
	`
	ext := New()
	result := ext.Extract(js, "https://example.com/app.js")

	if len(result.Secrets) == 0 {
		t.Fatal("expected at least 1 secret")
	}

	types := make(map[string]bool)
	for _, s := range result.Secrets {
		types[s.Type] = true
	}
	if !types["aws_access_key"] {
		t.Error("expected aws_access_key secret")
	}
}

func TestExtract_PrivateKey(t *testing.T) {
	js := `var key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";`
	ext := New()
	result := ext.Extract(js, "inline")

	found := false
	for _, s := range result.Secrets {
		if s.Type == "private_key" {
			found = true
		}
	}
	if !found {
		t.Error("expected private_key secret")
	}
}

func TestExtract_JWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	js := `var token = "` + jwt + `";`
	ext := New()
	result := ext.Extract(js, "inline")

	found := false
	for _, s := range result.Secrets {
		if s.Type == "jwt" {
			found = true
		}
	}
	if !found {
		t.Error("expected JWT secret")
	}
}

func TestExtract_TokenSecrets(t *testing.T) {
	// Use string concat to avoid triggering GitHub push protection
	stripeVal := "sk_" + "live_FAKEFAKEFAKEFAKEFAKEFAKE"
	githubVal := "gh" + "p_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
	slackVal := "xo" + "xb-FAKETOKEN1234"
	googleVal := "AI" + "zaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK"
	gitlabVal := "gl" + "pat-FAKEFAKEFAKEFAKEFAKE"
	js := `
		var stripeKey = "` + stripeVal + `";
		var githubToken = "` + githubVal + `";
		var slackToken = "` + slackVal + `";
		var googleKey = "` + googleVal + `";
		var gitlabToken = "` + gitlabVal + `";
	`
	ext := New()
	result := ext.Extract(js, "https://example.com/app.js")

	foundTypes := make(map[string]bool)
	for _, s := range result.Secrets {
		foundTypes[s.Type] = true
	}

	expected := []string{"stripe_key", "github_token", "slack_token", "google_api", "gitlab_token"}
	for _, exp := range expected {
		if !foundTypes[exp] {
			t.Errorf("expected %s secret, found types: %v", exp, foundTypes)
		}
	}
}

func TestExtract_Params(t *testing.T) {
	js := `
		$.post("/api/login", {username: "admin", password: "test"});
		var config = {apiEndpoint: "/api/v2", debug: true};
	`
	ext := New()
	result := ext.Extract(js, "https://example.com/app.js")

	if len(result.Params) == 0 {
		t.Fatal("expected at least 1 param")
	}

	found := false
	for _, p := range result.Params {
		if strings.EqualFold(p, "username") || strings.EqualFold(p, "password") {
			found = true
		}
	}
	if !found {
		t.Error("expected username or password param")
	}
}

func TestExtract_NoFalsePositives(t *testing.T) {
	js := `
		var x = 1;
		console.log("hello world");
	`
	ext := New()
	result := ext.Extract(js, "inline")

	if len(result.Endpoints) > 0 {
		t.Errorf("expected 0 endpoints from non-API JS, got %d", len(result.Endpoints))
	}
	if len(result.Secrets) > 0 {
		t.Errorf("expected 0 secrets from non-API JS, got %d", len(result.Secrets))
	}
}

func TestIsValidPath(t *testing.T) {
	valid := []string{"/api/v1/users", "/api/login", "/admin/config"}
	invalid := []string{"/a", "/style.css", "/image.png", "/x"}

	for _, p := range valid {
		if !isValidPath(p) {
			t.Errorf("expected %q to be valid", p)
		}
	}
	for _, p := range invalid {
		if isValidPath(p) {
			t.Errorf("expected %q to be invalid", p)
		}
	}
}

func TestSummary(t *testing.T) {
	r := ExtractionResult{
		Endpoints: []Endpoint{{Path: "/api/test"}},
		Secrets:   []Secret{{Type: "api_key"}},
		Params:    []string{"id"},
	}
	s := r.Summary()
	if !strings.Contains(s, "1 endpoints") || !strings.Contains(s, "1 secrets") || !strings.Contains(s, "1 params") {
		t.Errorf("unexpected summary: %s", s)
	}
}
