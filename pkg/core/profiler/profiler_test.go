package profiler

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

func TestProfilerRecordAndSnapshot(t *testing.T) {
	p := New(Config{
		Enabled:    true,
		ListenAddr: "127.0.0.1:0",
		AutoTune:   false,
	})

	// Record several template executions
	p.RecordTemplateExecution("cve-2021-1234", "/path/to/cve-2021-1234.yaml", "http", 50*time.Millisecond, true, false)
	p.RecordTemplateExecution("cve-2021-1234", "/path/to/cve-2021-1234.yaml", "http", 100*time.Millisecond, false, false)
	p.RecordTemplateExecution("tech-detect", "/path/to/tech-detect.yaml", "http", 10*time.Millisecond, true, false)
	p.RecordTemplateExecution("error-template", "/path/to/error.yaml", "dns", 5*time.Millisecond, false, true)

	// Record host executions
	p.RecordHostExecution("example.com", 50*time.Millisecond, true, false)
	p.RecordHostExecution("example.com", 30*time.Millisecond, false, false)
	p.RecordHostExecution("test.com", 200*time.Millisecond, false, true)

	snap := p.GetSnapshot()

	if snap.TotalReqs != 4 {
		t.Errorf("expected 4 total requests, got %d", snap.TotalReqs)
	}
	if snap.TotalMatch != 2 {
		t.Errorf("expected 2 matches, got %d", snap.TotalMatch)
	}
	if snap.TotalErrors != 1 {
		t.Errorf("expected 1 error, got %d", snap.TotalErrors)
	}

	if len(snap.Templates) != 3 {
		t.Errorf("expected 3 templates, got %d", len(snap.Templates))
	}
	if len(snap.Hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(snap.Hosts))
	}
	if len(snap.Protocols) != 2 {
		t.Errorf("expected 2 protocols, got %d", len(snap.Protocols))
	}

	// Verify template stats
	cveStats := snap.Templates[0]
	if cveStats.ID != "cve-2021-1234" {
		t.Errorf("expected first template to be cve-2021-1234 (sorted by duration), got %s", cveStats.ID)
	}

	// Verify JSON marshaling works
	data, err := json.Marshal(cveStats)
	if err != nil {
		t.Fatalf("failed to marshal TemplateStats: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded["id"] != "cve-2021-1234" {
		t.Errorf("expected id cve-2021-1234, got %v", decoded["id"])
	}
}

func TestProfilerConcurrent(t *testing.T) {
	p := New(Config{
		Enabled:    true,
		ListenAddr: "127.0.0.1:0",
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			p.RecordTemplateExecution("concurrent-tmpl", "/path.yaml", "http", time.Duration(n)*time.Millisecond, n%2 == 0, n%10 == 0)
			p.RecordHostExecution("host.example.com", time.Duration(n)*time.Millisecond, n%2 == 0, n%10 == 0)
		}(i)
	}
	wg.Wait()

	snap := p.GetSnapshot()
	if snap.TotalReqs != 100 {
		t.Errorf("expected 100 requests, got %d", snap.TotalReqs)
	}
	if len(snap.Templates) != 1 {
		t.Errorf("expected 1 template, got %d", len(snap.Templates))
	}
	if len(snap.Hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(snap.Hosts))
	}
}

func TestProfilerAutoTune(t *testing.T) {
	// High error rate -> decrease
	p2 := New(Config{
		Enabled:           true,
		ListenAddr:        "127.0.0.1:0",
		AutoTune:          true,
		AutoTuneMinRPS:    1,
		AutoTuneMaxErrors: 10,
	})

	for i := 0; i < 20; i++ {
		p2.RecordTemplateExecution("err-tmpl", "/path.yaml", "http", 5*time.Millisecond, false, true)
	}

	rec2 := p2.GetAutoTuneRecommendation(150, 25)
	if rec2.Action != "decrease" {
		t.Errorf("expected decrease, got %s (err%%=%.1f)", rec2.Action, rec2.ErrorPercent)
	}
	if rec2.SuggestedRL >= 150 {
		t.Errorf("expected suggested RL < 150, got %d", rec2.SuggestedRL)
	}

	// Maintain case: decent RPS, low errors
	p3 := New(Config{
		Enabled:           true,
		ListenAddr:        "127.0.0.1:0",
		AutoTune:          true,
		AutoTuneMinRPS:    1,
		AutoTuneMaxErrors: 50,
	})

	for i := 0; i < 10; i++ {
		p3.RecordTemplateExecution("ok-tmpl", "/path.yaml", "http", 10*time.Millisecond, false, false)
	}

	rec3 := p3.GetAutoTuneRecommendation(150, 25)
	if rec3.Action != "maintain" {
		t.Errorf("expected maintain, got %s", rec3.Action)
	}
}

func TestProfilerHTTPServer(t *testing.T) {
	p := New(Config{
		Enabled:    true,
		ListenAddr: "127.0.0.1:19091",
	})

	if err := p.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer p.Stop()

	// Record some data
	p.RecordTemplateExecution("http-tmpl", "/path.yaml", "http", 50*time.Millisecond, true, false)
	p.RecordHostExecution("example.com", 30*time.Millisecond, true, false)

	time.Sleep(100 * time.Millisecond)

	// Test /metrics
	resp, err := http.Get("http://127.0.0.1:19091/metrics")
	if err != nil {
		t.Fatalf("failed to get /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var snap Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		t.Fatalf("failed to decode metrics: %v", err)
	}
	if snap.TotalReqs != 1 {
		t.Errorf("expected 1 request, got %d", snap.TotalReqs)
	}

	// Test /metrics/prometheus
	resp2, err := http.Get("http://127.0.0.1:19091/metrics/prometheus")
	if err != nil {
		t.Fatalf("failed to get /metrics/prometheus: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}

	// Test /profile/templates
	resp3, err := http.Get("http://127.0.0.1:19091/profile/templates")
	if err != nil {
		t.Fatalf("failed to get /profile/templates: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp3.StatusCode)
	}

	// Test /health
	resp4, err := http.Get("http://127.0.0.1:19091/health")
	if err != nil {
		t.Fatalf("failed to get /health: %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp4.StatusCode)
	}

	// Test /autotune
	resp5, err := http.Get("http://127.0.0.1:19091/autotune")
	if err != nil {
		t.Fatalf("failed to get /autotune: %v", err)
	}
	defer resp5.Body.Close()
	if resp5.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp5.StatusCode)
	}
}

func TestProfilerWriteReport(t *testing.T) {
	tmpFile := "/tmp/nuclei-profiler-test-report.json"
	defer func() { _ = os.Remove(tmpFile) }()

	p := New(Config{
		Enabled:    true,
		ListenAddr: "127.0.0.1:0",
		OutputFile: tmpFile,
	})

	p.RecordTemplateExecution("report-tmpl", "/path.yaml", "http", 50*time.Millisecond, true, false)
	p.RecordHostExecution("report.com", 30*time.Millisecond, true, false)

	p.Stop()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("report is empty")
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("failed to parse report: %v", err)
	}
	if snap.TotalReqs != 1 {
		t.Errorf("expected 1 request, got %d", snap.TotalReqs)
	}
}

func TestProfilerDisabled(t *testing.T) {
	p := New(Config{
		Enabled:    false,
		ListenAddr: "127.0.0.1:0",
	})

	p.RecordTemplateExecution("test", "/path", "http", 10*time.Millisecond, true, false)
	p.RecordHostExecution("test.com", 10*time.Millisecond, true, false)

	snap := p.GetSnapshot()
	if snap.TotalReqs != 0 {
		t.Errorf("expected 0 requests when disabled, got %d", snap.TotalReqs)
	}
}

func TestMemStats(t *testing.T) {
	m := MemStats()
	if m.Alloc == 0 {
		t.Error("expected non-zero Alloc")
	}
}
