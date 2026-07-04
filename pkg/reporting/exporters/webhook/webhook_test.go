package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func makeTestEvent(sev string) *output.ResultEvent {
	s := severity.Severities{}
	_ = s.Set(sev)

	return &output.ResultEvent{
		TemplateID: "test-template",
		TemplatePath: "/tmp/test.yaml",
		Info: model.Info{
			Name:        "Test Template",
			Description: "A test template",
			Authors:     stringslice.StringSlice{Value: "tester"},
			SeverityHolder: severity.Holder{
				Severity: s[0],
			},
		},
		Type:    "http",
		Host:    "example.com",
		Matched: "https://example.com/test",
	}
}

func TestWebhookExport(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload findingPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("failed to unmarshal payload: %v", err)
		}
		if payload.TemplateID != "test-template" {
			t.Errorf("expected template_id 'test-template', got '%s'", payload.TemplateID)
		}
		if payload.Host != "example.com" {
			t.Errorf("expected host 'example.com', got '%s'", payload.Host)
		}
		atomic.AddInt32(&received, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := &Options{
		URL:     srv.URL,
		Timeout: 5,
	}
	exporter, err := New(opts)
	if err != nil {
		t.Fatalf("create exporter: %v", err)
	}
	defer exporter.Close()

	event := makeTestEvent("high")
	if err := exporter.Export(event); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected 1 webhook call, got %d", received)
	}
}

func TestWebhookSeverityFilter(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := &Options{
		URL:            srv.URL,
		Timeout:        5,
		SeverityFilter: []string{"critical", "high"},
	}
	exporter, err := New(opts)
	if err != nil {
		t.Fatalf("create exporter: %v", err)
	}
	defer exporter.Close()

	// Low severity should be filtered out
	lowEvent := makeTestEvent("low")
	if err := exporter.Export(lowEvent); err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if atomic.LoadInt32(&received) != 0 {
		t.Errorf("expected 0 calls for low severity, got %d", received)
	}

	// High severity should pass
	highEvent := makeTestEvent("high")
	if err := exporter.Export(highEvent); err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected 1 call for high severity, got %d", received)
	}
}

func TestWebhookOmitRaw(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload findingPayload
		_ = json.Unmarshal(body, &payload)
		if payload.RawRequest != "" {
			t.Error("expected empty raw_request when omit-raw is true")
		}
		if payload.RawResponse != "" {
			t.Error("expected empty raw_response when omit-raw is true")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := &Options{
		URL:     srv.URL,
		Timeout: 5,
		OmitRaw: true,
	}
	exporter, err := New(opts)
	if err != nil {
		t.Fatalf("create exporter: %v", err)
	}
	defer exporter.Close()

	event := makeTestEvent("high")
	event.Request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	event.Response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	if err := exporter.Export(event); err != nil {
		t.Fatalf("export failed: %v", err)
	}
}

func TestWebhookCustomHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom-Header") != "test-value" {
			t.Error("expected custom header 'X-Custom-Header: test-value'")
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("expected Authorization header")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := &Options{
		URL:     srv.URL,
		Timeout: 5,
		Headers: map[string]string{
			"X-Custom-Header": "test-value",
			"Authorization":   "Bearer test-token",
		},
	}
	exporter, err := New(opts)
	if err != nil {
		t.Fatalf("create exporter: %v", err)
	}
	defer exporter.Close()

	event := makeTestEvent("medium")
	if err := exporter.Export(event); err != nil {
		t.Fatalf("export failed: %v", err)
	}
}

func TestWebhookNoURL(t *testing.T) {
	opts := &Options{URL: ""}
	_, err := New(opts)
	if err == nil {
		t.Error("expected error for empty URL")
	}
}
