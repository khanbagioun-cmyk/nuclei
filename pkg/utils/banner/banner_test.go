package banner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGrabSSH(t *testing.T) {
	g := Default()
	result, err := g.Grab(context.Background(), "scanme.sh:22", "")
	if err != nil {
		t.Skipf("could not connect to scanme.sh:22: %v", err)
	}
	if result.Banner == "" {
		t.Skip("no banner received (service may be down)")
	}
	t.Logf("Banner: %s", result.Banner)
	t.Logf("Protocol: %s", result.Protocol)
	t.Logf("Service: %s", result.Service)
	if result.Protocol != "ssh" {
		t.Errorf("expected protocol ssh, got %s", result.Protocol)
	}
}

func TestGrabLocalHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.0")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	addr := fmt.Sprintf("%s:%s", host, port)

	g := Default()
	g.Timeout = 5 * time.Second
	result, err := g.Grab(context.Background(), addr, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	if err != nil {
		t.Fatalf("grab failed: %v", err)
	}
	if result.Banner == "" {
		t.Fatal("no banner received")
	}
	t.Logf("Banner (first 200): %s", truncate(result.Banner, 200))
	t.Logf("Protocol: %s", result.Protocol)
}

func TestGrabLocalTCPServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-TestServer_1.0\r\n"))
		time.Sleep(100 * time.Millisecond)
	}()

	addr := ln.Addr().String()
	g := Default()
	g.Timeout = 3 * time.Second
	result, err := g.Grab(context.Background(), addr, "")
	if err != nil {
		t.Fatalf("grab failed: %v", err)
	}
	if result.Banner == "" {
		t.Fatal("no banner received")
	}
	if result.Protocol != "ssh" {
		t.Errorf("expected protocol ssh, got %s (banner: %s)", result.Protocol, result.Banner)
	}
	t.Logf("Banner: %s", result.Banner)
}

func TestGrabRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()

	g := Default()
	g.Timeout = 2 * time.Second
	result, err := g.Grab(context.Background(), addr, "")
	if err == nil {
		t.Error("expected error for closed port")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on error")
	}
	t.Logf("got expected error: %v", err)
}

func TestGrabBatchLocal(t *testing.T) {
	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln1.Close()
	defer ln2.Close()

	go func() {
		conn, _ := ln1.Accept()
		if conn != nil {
			defer conn.Close()
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
			time.Sleep(100 * time.Millisecond)
		}
	}()
	go func() {
		conn, _ := ln2.Accept()
		if conn != nil {
			defer conn.Close()
			_, _ = conn.Write([]byte("220 (vsFTPd 3.0.5)\r\n"))
			time.Sleep(100 * time.Millisecond)
		}
	}()

	g := Default()
	g.Timeout = 3 * time.Second
	results := g.GrabBatch(context.Background(), []string{ln1.Addr().String(), ln2.Addr().String()}, "")

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	protos := make(map[string]int)
	for _, r := range results {
		if r.Banner != "" {
			protos[r.Protocol]++
		}
	}
	if len(protos) < 2 {
		t.Errorf("expected at least 2 protocols, got %d: %v", len(protos), protos)
	}
	t.Logf("protocols: %v", protos)
}

func TestDetectProtocol(t *testing.T) {
	tests := []struct {
		banner   string
		expected string
	}{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", "ssh"},
		{"220 (vsFTPd 3.0.5)", "ftp"},
		{"220 mail.example.com ESMTP Postfix", "smtp"},
		{"+OK Ready", "pop3"},
		{"* OK IMAP4rev1", "imap"},
		{"redis_version:7.0.0", "redis"},
		{"5.7.0-log MySQL Community Server", "mysql"},
		{"RFB 003.008", "vnc"},
		{"random garbage", "unknown"},
	}

	for _, tt := range tests {
		got := DetectProtocol(tt.banner)
		if got != tt.expected {
			t.Errorf("DetectProtocol(%q) = %q, want %q", tt.banner, got, tt.expected)
		}
	}
}

func TestProtocolToService(t *testing.T) {
	tests := []struct {
		protocol string
		expected string
	}{
		{"ssh", "SSH Server"},
		{"ftp", "FTP Server"},
		{"smtp", "SMTP Mail Server"},
		{"unknown", "Unknown Service"},
	}
	for _, tt := range tests {
		got := ProtocolToService(tt.protocol)
		if got != tt.expected {
			t.Errorf("ProtocolToService(%q) = %q, want %q", tt.protocol, got, tt.expected)
		}
	}
}

func TestTLSGrab(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("secure hello"))
	}))
	defer srv.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	addr := fmt.Sprintf("%s:%s", host, port)

	g := Default()
	g.TLSEnabled = true
	g.TLSSkipVerify = true
	g.Timeout = 5 * time.Second
	result, err := g.Grab(context.Background(), addr, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	if err != nil {
		t.Fatalf("TLS grab failed: %v", err)
	}
	if result.Banner == "" {
		t.Fatal("no banner received")
	}
	if !result.TLS {
		t.Error("expected TLS=true")
	}
	t.Logf("TLS Banner: %s", truncate(result.Banner, 200))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
