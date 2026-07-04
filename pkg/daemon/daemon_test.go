package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stringReader(s string) *strings.Reader {
	return strings.NewReader(s)
}

func TestParseSchedule(t *testing.T) {
	tests := []struct {
		expr   string
		valid  bool
	}{
		{"every:1h", true},
		{"every:30m", true},
		{"every:24h", true},
		{"hourly", true},
		{"daily", true},
		{"weekly", true},
		{"cron:0 3 * * *", true},
		{"invalid", false},
		{"every:abc", false},
		{"cron:1 2", false},
	}
	for _, tt := range tests {
		_, err := parseSchedule(tt.expr)
		if tt.valid && err != nil {
			t.Errorf("parseSchedule(%q) unexpected error: %v", tt.expr, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("parseSchedule(%q) expected error but got none", tt.expr)
		}
	}
}

func TestScheduleNextAfter(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	s, _ := parseSchedule("every:1h")
	next := s.nextAfter(now)
	if next.Sub(now) != time.Hour {
		t.Errorf("every:1h nextAfter = %v, want %v", next.Sub(now), time.Hour)
	}

	s, _ = parseSchedule("every:30m")
	next = s.nextAfter(now)
	if next.Sub(now) != 30*time.Minute {
		t.Errorf("every:30m nextAfter = %v, want %v", next.Sub(now), 30*time.Minute)
	}
}

func TestDaemonSubmitAndListJobs(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		ListenAddr:    "127.0.0.1:0",
		NucleiBin:     "/bin/echo",
		ResultsDir:    tmpDir,
		MaxConcurrent: 1,
		DBPath:        filepath.Join(tmpDir, "state.json"),
	}
	d := New(cfg)

	job := &ScanJob{
		Name:    "test-scan",
		Targets: []string{"http://example.com"},
	}
	if err := d.SubmitJob(job); err != nil {
		t.Fatalf("SubmitJob failed: %v", err)
	}
	if job.ID == "" {
		t.Fatal("job ID should be set")
	}

	jobs := d.ListJobs()
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}

	got, ok := d.GetJob(job.ID)
	if !ok {
		t.Fatal("job not found")
	}
	if got.Name != "test-scan" {
		t.Errorf("job name = %s, want test-scan", got.Name)
	}
}

func TestDaemonDeleteJob(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		ListenAddr:    "127.0.0.1:0",
		NucleiBin:     "/bin/echo",
		ResultsDir:    tmpDir,
		MaxConcurrent: 1,
		DBPath:        filepath.Join(tmpDir, "state.json"),
	}
	d := New(cfg)

	job := &ScanJob{Targets: []string{"http://example.com"}}
	d.SubmitJob(job)

	if !d.DeleteJob(job.ID) {
		t.Fatal("DeleteJob returned false")
	}
	if _, ok := d.GetJob(job.ID); ok {
		t.Fatal("job should be deleted")
	}
}

func TestDaemonStatePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "state.json")
	cfg := Config{
		ListenAddr:    "127.0.0.1:0",
		NucleiBin:     "/bin/echo",
		ResultsDir:    tmpDir,
		MaxConcurrent: 1,
		DBPath:        dbPath,
	}
	d := New(cfg)

	job := &ScanJob{Name: "persist-test", Targets: []string{"http://example.com"}, Schedule: "daily"}
	d.SubmitJob(job)
	d.saveState()

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("state file not created: %v", err)
	}

	d2 := New(cfg)
	got, ok := d2.GetJob(job.ID)
	if !ok {
		t.Fatal("job not loaded from state")
	}
	if got.Name != "persist-test" {
		t.Errorf("loaded job name = %s, want persist-test", got.Name)
	}
	if got.Schedule != "daily" {
		t.Errorf("loaded job schedule = %s, want daily", got.Schedule)
	}
}

func TestDaemonHTTPAPI(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		ListenAddr:    "127.0.0.1:0",
		NucleiBin:     "/bin/echo",
		ResultsDir:    tmpDir,
		MaxConcurrent: 1,
		DBPath:        filepath.Join(tmpDir, "state.json"),
	}
	d := New(cfg)

	mux := http.NewServeMux()
	d.registerHandlers(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("health status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	jobJSON := `{"name":"api-test","targets":["http://example.com"]}`
	resp, err = http.Post(server.URL+"/api/jobs", "application/json", stringReader(jobJSON))
	if err != nil {
		t.Fatalf("submit job failed: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("submit status = %d, want 201", resp.StatusCode)
	}
	var created map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	jobID := created["id"].(string)
	if jobID == "" {
		t.Fatal("submitted job has no ID")
	}

	resp, err = http.Get(server.URL + "/api/jobs")
	if err != nil {
		t.Fatalf("list jobs failed: %v", err)
	}
	var jobs []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&jobs)
	resp.Body.Close()
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}

	resp, err = http.Get(server.URL + "/api/jobs/" + jobID)
	if err != nil {
		t.Fatalf("get job failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("get job status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	req, _ := http.NewRequest("DELETE", server.URL+"/api/jobs/"+jobID, nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete job failed: %v", err)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("delete status = %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestDiffResults(t *testing.T) {
	tmpDir := t.TempDir()
	jobID := "test-diff-job"

	run1 := filepath.Join(tmpDir, jobID+"-20260101-120000.jsonl")
	run2 := filepath.Join(tmpDir, jobID+"-20260102-120000.jsonl")

	os.WriteFile(run1, []byte(`{"template-id":"CVE-2024-001","host":"example.com","matched-at":"http://example.com/vuln","info":{"severity":"high"}}
`), 0644)

	os.WriteFile(run2, []byte(`{"template-id":"CVE-2024-001","host":"example.com","matched-at":"http://example.com/vuln","info":{"severity":"high"}}
{"template-id":"CVE-2024-002","host":"example.com","matched-at":"http://example.com/new","info":{"severity":"critical"}}
`), 0644)

	cfg := Config{
		ListenAddr:    "127.0.0.1:0",
		NucleiBin:     "/bin/echo",
		ResultsDir:    tmpDir,
		MaxConcurrent: 1,
		DBPath:        filepath.Join(tmpDir, "state.json"),
	}
	d := New(cfg)
	d.jobs[jobID] = &ScanJob{ID: jobID, Targets: []string{"http://example.com"}}

	diff, err := d.GetDiff(jobID)
	if err != nil {
		t.Fatalf("GetDiff failed: %v", err)
	}
	if len(diff.NewFindings) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(diff.NewFindings))
	}
	if len(diff.GoneFindings) != 0 {
		t.Errorf("expected 0 gone findings, got %d", len(diff.GoneFindings))
	}
	if diff.NewFindings[0].TemplateID != "CVE-2024-002" {
		t.Errorf("new finding template = %s, want CVE-2024-002", diff.NewFindings[0].TemplateID)
	}
}

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()
	if id1 == id2 {
		t.Error("generateID should produce unique IDs")
	}
	if len(id1) < 10 {
		t.Errorf("ID too short: %s", id1)
	}
}

func TestJobToMap(t *testing.T) {
	now := time.Now()
	job := &ScanJob{
		ID:        "test-123",
		Name:      "test",
		Targets:   []string{"http://example.com"},
		Status:    StatusPending,
		CreatedAt: now,
	}
	m := jobToMap(job)
	if m["id"] != "test-123" {
		t.Errorf("map id = %v, want test-123", m["id"])
	}
	if m["status"] != StatusPending {
		t.Errorf("map status = %v, want %s", m["status"], StatusPending)
	}
}
