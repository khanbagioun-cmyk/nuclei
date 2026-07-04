package authscan

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// parseLoginForm fetches the login page, finds the first form with a password field,
// and extracts form field names and the form action URL.
func parseLoginForm(resp *http.Response, loginURL string, usernameField, passwordField string) (url.Values, string, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read login page: %w", err)
	}

	// Parse HTML
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse HTML: %w", err)
	}

	// Find the first form containing a password-type input
	form := findLoginForm(doc)
	if form == nil {
		return nil, "", fmt.Errorf("no login form found on page")
	}

	formData := url.Values{}
	var action string

	// Get form action
	for _, attr := range form.Attr {
		if attr.Key == "action" {
			action = attr.Val
			break
		}
	}

	// Resolve relative action URL
	if action != "" {
		base, err := url.Parse(loginURL)
		if err == nil {
			ref, err := url.Parse(action)
			if err == nil {
				action = base.ResolveReference(ref).String()
			}
		}
	}

	// Extract all input fields from the form
	userField := usernameField
	passField := passwordField
	if userField == "" {
		userField = "" // will be auto-detected
	}
	if passField == "" {
		passField = "" // will be auto-detected
	}

	extractFormInputs(form, formData, &userField, &passField)

	// Store the field names for later use
	if userField != "" {
		formData.Set("__username_field__", userField)
	}
	if passField != "" {
		formData.Set("__password_field__", passField)
	}

	return formData, action, nil
}

// findLoginForm finds the first form element that contains a password input
func findLoginForm(n *html.Node) *html.Node {
	if n.Type == html.ElementNode && n.Data == "form" {
		if hasPasswordInput(n) {
			return n
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if form := findLoginForm(c); form != nil {
			return form
		}
	}
	return nil
}

// hasPasswordInput checks if a form contains a password-type input
func hasPasswordInput(n *html.Node) bool {
	if n.Type == html.ElementNode && n.Data == "input" {
		inputType := getAttr(n, "type")
		if strings.EqualFold(inputType, "password") {
			return true
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if hasPasswordInput(c) {
			return true
		}
	}
	return false
}

// extractFormInputs extracts all input/textarea/select fields from a form
func extractFormInputs(form *html.Node, formData url.Values, userField, passField *string) {
	walkInputs(form, func(input *html.Node) {
		name := getAttr(input, "name")
		if name == "" {
			return
		}
		inputType := getAttr(input, "type")
		value := getAttr(input, "value")

		// Auto-detect username field
		if *userField == "" {
			lname := strings.ToLower(name)
			ltype := strings.ToLower(inputType)
			if strings.Contains(lname, "user") || strings.Contains(lname, "email") ||
				strings.Contains(lname, "login") || strings.Contains(lname, "account") ||
				ltype == "email" {
				*userField = name
			}
		}

		// Auto-detect password field
		if *passField == "" && strings.EqualFold(inputType, "password") {
			*passField = name
		}

		// Set default value if present (hidden fields, CSRF tokens)
		if value != "" {
			formData.Set(name, value)
		}
	})
}

// walkInputs walks all descendant elements and calls fn for each input/textarea/select
func walkInputs(n *html.Node, fn func(*html.Node)) {
	if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "textarea" || n.Data == "select") {
		fn(n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walkInputs(c, fn)
	}
}

// getAttr gets an attribute value from an HTML node
func getAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

// parseOAuth2TokenResponse parses an OAuth2 token response JSON
func parseOAuth2TokenResponse(resp *http.Response) (string, time.Time, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, err
	}

	// Simple JSON parsing without importing encoding/json to keep it light
	// Look for "access_token" and "expires_in"
	tokenRe := regexp.MustCompile(`"access_token"\s*:\s*"([^"]+)"`)
	expiresRe := regexp.MustCompile(`"expires_in"\s*:\s*(\d+)`)
	expiryRe := regexp.MustCompile(`"expiry"\s*:\s*"([^"]+)"`)

	tokenMatch := tokenRe.FindSubmatch(body)
	if len(tokenMatch) < 2 {
		return "", time.Time{}, fmt.Errorf("no access_token in response")
	}
	token := string(tokenMatch[1])

	var expiry time.Time
	if expMatch := expiryRe.FindSubmatch(body); len(expMatch) >= 2 {
		// Google-style "expiry" field (RFC3339 timestamp)
		if t, err := time.Parse(time.RFC3339, string(expMatch[1])); err == nil {
			expiry = t
		}
	}
	if expiry.IsZero() {
		if expiresMatch := expiresRe.FindSubmatch(body); len(expiresMatch) >= 2 {
			seconds := 0
			fmt.Sscanf(string(expiresMatch[1]), "%d", &seconds)
			if seconds > 0 {
				expiry = time.Now().Add(time.Duration(seconds) * time.Second)
			}
		}
	}
	if expiry.IsZero() {
		// Default to 1 hour
		expiry = time.Now().Add(time.Hour)
	}

	return token, expiry, nil
}
