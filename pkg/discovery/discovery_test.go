package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Threads <= 0 {
		t.Error("threads should be positive")
	}
	if cfg.Timeout <= 0 {
		t.Error("timeout should be positive")
	}
	if len(cfg.Ports) == 0 {
		t.Error("default ports should not be empty")
	}
}

func TestResolverResolveA(t *testing.T) {
	r := NewResolver("", 5*time.Second)
	ips, err := r.ResolveA("example.com")
	if err != nil {
		t.Skipf("network not available: %v", err)
	}
	if len(ips) == 0 {
		t.Error("expected at least 1 IP for example.com")
	}
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			t.Errorf("invalid IP: %s", ip)
		}
	}
}

func TestResolverQueryMX(t *testing.T) {
	r := NewResolver("", 5*time.Second)
	answers, err := r.Query("example.com", 15) // dns.TypeMX = 15
	if err != nil {
		t.Skipf("network not available: %v", err)
	}
	// example.com may or may not have MX records, just verify no panic
	_ = answers
}

func TestCheckWildcard(t *testing.T) {
	r := NewResolver("", 5*time.Second)
	// example.com should not have wildcard
	result := r.CheckWildcard("example.com")
	// Just verify it doesn't panic — result depends on DNS
	_ = result
}

func TestPortServiceMap(t *testing.T) {
	tests := []struct {
		port    int
		service string
	}{
		{22, "ssh"},
		{80, "http"},
		{443, "https"},
		{3306, "mysql"},
		{6379, "redis"},
		{27017, "mongodb"},
		{99999, ""},
	}
	for _, tt := range tests {
		got := PortServiceMap[tt.port]
		if got != tt.service {
			t.Errorf("PortServiceMap[%d] = %q, want %q", tt.port, got, tt.service)
		}
	}
}

func TestExpandCIDR(t *testing.T) {
	ips := expandCIDR("192.168.1.0/30")
	if len(ips) != 2 {
		t.Errorf("expected 2 usable IPs for /30, got %d", len(ips))
	}
	if len(ips) > 0 && ips[0] != "192.168.1.1" {
		t.Errorf("first IP = %s, want 192.168.1.1", ips[0])
	}

	ips = expandCIDR("invalid-cidr")
	if len(ips) != 0 {
		t.Error("expected 0 IPs for invalid CIDR")
	}
}

func TestSanitizeBucketName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://example.com/", "example-com"},
		{"https://sub.example.com:443/path", "sub-example-com"},
		{"example.com", "example-com"},
		{"EXAMPLE.COM", "example-com"},
		{"a.b", "a-b"},
		{"", ""},
		{"/", ""},
	}
	for _, tt := range tests {
		got := sanitizeBucketName(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeBucketName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGenerateBucketNames(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Domains = []string{"example.com"}
	d := New(cfg)
	names := d.generateBucketNames()
	if len(names) == 0 {
		t.Fatal("expected bucket names")
	}
	found := false
	for _, n := range names {
		if n == "example-com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'example-com' in bucket names")
	}

	hasBackup := false
	for _, n := range names {
		if n == "example-com-backup" {
			hasBackup = true
			break
		}
	}
	if !hasBackup {
		t.Error("expected 'example-com-backup' in bucket names")
	}
}

func TestDetectTech(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "nginx/1.21.0")
	headers.Set("X-Powered-By", "PHP/8.1.0")
	body := []byte(`<html><head><title>Test</title><script src="/jquery.min.js"></script></head></html>`)

	techs := detectTech(headers, body)

	techSet := make(map[string]bool)
	for _, t := range techs {
		techSet[t] = true
	}

	if !techSet["Nginx"] {
		t.Error("expected Nginx in detected tech")
	}
	if !techSet["PHP"] {
		t.Error("expected PHP in detected tech")
	}
	if !techSet["jQuery"] {
		t.Error("expected jQuery in detected tech")
	}
}

func TestExtractLinks(t *testing.T) {
	body := []byte(`<a href="/page1">Page 1</a><a href="https://example.com/page2">Page 2</a><a href="#anchor">Anchor</a><a href="javascript:void(0)">JS</a>`)
	links := extractLinks("https://example.com", body)

	if len(links) != 2 {
		t.Fatalf("expected 2 links, got %d: %v", len(links), links)
	}

	foundPage1 := false
	foundPage2 := false
	for _, l := range links {
		if l == "https://example.com/page1" {
			foundPage1 = true
		}
		if l == "https://example.com/page2" {
			foundPage2 = true
		}
	}
	if !foundPage1 {
		t.Error("expected /page1 to be resolved to absolute URL")
	}
	if !foundPage2 {
		t.Error("expected page2 to be found")
	}
}

func TestExtractJSFiles(t *testing.T) {
	body := []byte(`<script src="/app.js"></script><script src="https://cdn.example.com/lib.js"></script><script>inline code</script>`)
	jsFiles := extractJSFiles("https://example.com", body)

	if len(jsFiles) != 2 {
		t.Fatalf("expected 2 JS files, got %d", len(jsFiles))
	}
}

func TestExtractForms(t *testing.T) {
	body := []byte(`<form action="/login" method="post"><input type="text" name="username"><input type="password" name="pass"></form>`)
	forms := extractForms(body)

	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	if forms[0].Action != "/login" {
		t.Errorf("action = %s, want /login", forms[0].Action)
	}
	if forms[0].Method != "POST" {
		t.Errorf("method = %s, want POST", forms[0].Method)
	}
	if len(forms[0].Inputs) != 2 {
		t.Fatalf("expected 2 inputs, got %d", len(forms[0].Inputs))
	}
	if forms[0].Inputs[0].Name != "username" {
		t.Errorf("input[0] name = %s, want username", forms[0].Inputs[0].Name)
	}
	if forms[0].Inputs[1].Type != "password" {
		t.Errorf("input[1] type = %s, want password", forms[0].Inputs[1].Type)
	}
}

func TestCrawlSingleURL(t *testing.T) {
	html := `<html><head><title>Test Page</title></head><body>
		<form action="/login" method="post"><input name="user" type="text"></form>
		<a href="/about">About</a>
		<script src="/app.js"></script>
		</body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("X-Powered-By", "PHP/8.1")
		w.Write([]byte(html))
	}))
	defer server.Close()

	cfg := DefaultConfig()
	d := New(cfg)

	result := d.CrawlSingleURL(context.Background(), server.URL)

	if result.Status != 200 {
		t.Errorf("status = %d, want 200", result.Status)
	}
	if result.Title != "Test Page" {
		t.Errorf("title = %s, want 'Test Page'", result.Title)
	}
	if len(result.Forms) != 1 {
		t.Errorf("expected 1 form, got %d", len(result.Forms))
	}
	if len(result.Links) == 0 {
		t.Error("expected at least 1 link")
	}
	if len(result.JSFiles) == 0 {
		t.Error("expected at least 1 JS file")
	}

	techSet := make(map[string]bool)
	for _, t := range result.Tech {
		techSet[t] = true
	}
	if !techSet["Nginx"] {
		t.Error("expected Nginx in detected tech")
	}
	if !techSet["PHP"] {
		t.Error("expected PHP in detected tech")
	}
}

func TestScanHostOnClosedPorts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = 500 * time.Millisecond
	cfg.Threads = 5
	d := New(cfg)

	result := d.ScanSingleHost("127.0.0.1", []int{1, 2, 3})
	// These ports should be closed — just verify no panic and no open ports
	if len(result.OpenPorts) > 0 {
		t.Logf("unexpected open ports on 127.0.0.1:1-3: %v", result.OpenPorts)
	}
}

func TestScanHostWithOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	cfg := DefaultConfig()
	cfg.Timeout = 2 * time.Second
	cfg.Threads = 5
	d := New(cfg)

	result := d.ScanSingleHost(host, []int{port})
	if len(result.OpenPorts) != 1 {
		t.Fatalf("expected 1 open port, got %d", len(result.OpenPorts))
	}
	if result.OpenPorts[0].Port != port {
		t.Errorf("port = %d, want %d", result.OpenPorts[0].Port, port)
	}
}

func TestResolveHost(t *testing.T) {
	cfg := DefaultConfig()
	d := New(cfg)

	ips := d.resolveHost("127.0.0.1")
	if len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Errorf("resolveHost(127.0.0.1) = %v, want [127.0.0.1]", ips)
	}

	ips = d.resolveHost("invalid-host-that-does-not-exist-99999.com")
	if len(ips) != 0 {
		t.Errorf("expected 0 IPs for invalid host, got %v", ips)
	}
}

func TestFormatHost(t *testing.T) {
	h := HostResult{
		Host: "example.com",
		IP:   "1.2.3.4",
		OpenPorts: []PortResult{
			{Port: 80, Service: "http", Banner: "nginx"},
			{Port: 22, Service: "ssh", Banner: "OpenSSH"},
		},
	}
	out := FormatHost(h)
	if !strings.Contains(out, "example.com") {
		t.Error("missing host in output")
	}
	if !strings.Contains(out, "80") {
		t.Error("missing port 80 in output")
	}
	if !strings.Contains(out, "ssh") {
		t.Error("missing ssh in output")
	}
}

func TestCloudEndpoints(t *testing.T) {
	tests := []struct {
		provider string
		bucket   string
		want     string
	}{
		{ProviderS3, "test", "https://test.s3.amazonaws.com"},
		{ProviderGCS, "test", "https://storage.googleapis.com/test"},
		{ProviderAzure, "test", "https://test.blob.core.windows.net"},
	}
	for _, tt := range tests {
		pattern := CloudEndpoints[tt.provider]
		got := fmt.Sprintf(pattern, tt.bucket)
		if got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.provider, got, tt.want)
		}
	}
}

func TestCheckSingleBucketS3(t *testing.T) {
	cfg := DefaultConfig()
	d := New(cfg)

	result := d.CheckSingleBucket(context.Background(), ProviderS3, "amazon-public-test-bucket-nonexist-99999")
	// This bucket should not exist — just verify no panic
	if result.Provider != ProviderS3 {
		t.Errorf("provider = %s, want %s", result.Provider, ProviderS3)
	}
}

func TestDiscoveryRunEmptyConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SkipDNS = true
	cfg.SkipPortScan = true
	cfg.SkipWebCrawl = true
	cfg.SkipCloud = true
	d := New(cfg)

	result, err := d.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
}

func TestDiscoveryResultJSON(t *testing.T) {
	r := &Result{
		Domains: []DomainResult{
			{Domain: "example.com", Subdomains: []string{"www.example.com"}, HasWildcard: false},
		},
		Hosts: []HostResult{
			{Host: "example.com", IP: "1.2.3.4", OpenPorts: []PortResult{{Port: 80, Service: "http"}}},
		},
		Services: []ServiceResult{
			{Host: "example.com", Port: 80, Service: "http", Protocol: "tcp"},
		},
		WebApps: []WebAppResult{
			{URL: "http://example.com", Title: "Example", Status: 200, Tech: []string{"Nginx"}},
		},
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var back Result
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if len(back.Domains) != 1 {
		t.Error("expected 1 domain")
	}
	if back.Domains[0].Domain != "example.com" {
		t.Errorf("domain = %s", back.Domains[0].Domain)
	}
	if len(back.WebApps) != 1 || back.WebApps[0].Title != "Example" {
		t.Error("web app not deserialized correctly")
	}
}

func TestResolveURL(t *testing.T) {
	base, _ := url.Parse("https://example.com/path/")
	tests := []struct {
		link string
		want string
	}{
		{"/page", "https://example.com/page"},
		{"page2", "https://example.com/path/page2"},
		{"https://other.com/x", "https://other.com/x"},
		{"#anchor", ""},
		{"javascript:void(0)", ""},
		{"mailto:test@test.com", ""},
	}
	for _, tt := range tests {
		got := resolveURL(base, tt.link)
		if got != tt.want {
			t.Errorf("resolveURL(%q) = %q, want %q", tt.link, got, tt.want)
		}
	}
}

func TestSameHost(t *testing.T) {
	base, _ := url.Parse("https://example.com/path")
	tests := []struct {
		url  string
		want bool
	}{
		{"https://example.com/other", true},
		{"https://sub.example.com/other", false},
		{"https://other.com/other", false},
		{"invalid-url", false},
	}
	for _, tt := range tests {
		got := sameHost(base, tt.url)
		if got != tt.want {
			t.Errorf("sameHost(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}
