package distributed

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

func TestCoordinatorSubmitJob(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := CoordinatorConfig{
		ListenAddr: "127.0.0.1:0",
		ResultsDir: tmpDir,
		NucleiBin:  "/bin/echo",
		ChunkSize:  5,
	}
	c := NewCoordinator(cfg)

	job := &Job{
		Name:    "test-dist",
		Targets: []string{"http://a.com", "http://b.com", "http://c.com"},
	}
	if err := c.SubmitJob(job); err != nil {
		t.Fatalf("SubmitJob failed: %v", err)
	}
	if job.ID == "" {
		t.Fatal("job ID should be set")
	}
	if len(job.WorkItems) != 3 {
		t.Fatalf("expected 3 work items, got %d", len(job.WorkItems))
	}

	got, ok := c.GetJob(job.ID)
	if !ok {
		t.Fatal("job not found")
	}
	if got.Name != "test-dist" {
		t.Errorf("job name = %s, want test-dist", got.Name)
	}
}

func TestCoordinatorGetNextWork(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := CoordinatorConfig{
		ListenAddr: "127.0.0.1:0",
		ResultsDir: tmpDir,
		NucleiBin:  "/bin/echo",
		ChunkSize:  1,
	}
	c := NewCoordinator(cfg)

	job := &Job{
		Targets: []string{"http://a.com"},
	}
	c.SubmitJob(job)

	item := c.GetNextWork()
	if item == nil {
		t.Fatal("expected work item")
	}
	if item.Target != "http://a.com" {
		t.Errorf("work target = %s, want http://a.com", item.Target)
	}
	if item.JobID != job.ID {
		t.Errorf("work job ID = %s, want %s", item.JobID, job.ID)
	}
}

func TestCoordinatorWorkerRegistration(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := CoordinatorConfig{
		ListenAddr: "127.0.0.1:0",
		ResultsDir: tmpDir,
		NucleiBin:  "/bin/echo",
	}
	c := NewCoordinator(cfg)

	info := &WorkerInfo{
		ID:           "test-worker-1",
		Addr:         "127.0.0.1:9999",
		Capabilities: []string{"http", "dns"},
	}
	c.RegisterWorker(info)

	workers := c.ListWorkers()
	if len(workers) != 1 {
		t.Fatalf("expected 1 worker, got %d", len(workers))
	}
	if workers[0].ID != "test-worker-1" {
		t.Errorf("worker ID = %s, want test-worker-1", workers[0].ID)
	}
	if !c.Heartbeat("test-worker-1") {
		t.Error("heartbeat failed")
	}
}

func TestCoordinatorResultProcessing(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := CoordinatorConfig{
		ListenAddr: "127.0.0.1:0",
		ResultsDir: tmpDir,
		NucleiBin:  "/bin/echo",
	}
	c := NewCoordinator(cfg)
	go c.processResults()

	job := &Job{Targets: []string{"http://a.com"}}
	c.SubmitJob(job)

	result := &WorkResult{
		WorkID:     job.WorkItems[0].ID,
		WorkerID:   "test-worker",
		Status:     "completed",
		ResultFile: filepath.Join(tmpDir, "result.jsonl"),
		MatchCount: 5,
	}
	os.WriteFile(result.ResultFile, []byte(`{"matcher-status":true}`+"\n"), 0644)
	c.SubmitResult(result)

	time.Sleep(200 * time.Millisecond)

	got, _ := c.GetJob(job.ID)
	got.mu.Lock()
	defer got.mu.Unlock()
	if len(got.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got.Results))
	}
	if got.Results[0].MatchCount != 5 {
		t.Errorf("match count = %d, want 5", got.Results[0].MatchCount)
	}
}

func TestCoordinatorMergeResults(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := CoordinatorConfig{
		ListenAddr: "127.0.0.1:0",
		ResultsDir: tmpDir,
		NucleiBin:  "/bin/echo",
	}
	c := NewCoordinator(cfg)

	job := &Job{Targets: []string{"http://a.com", "http://b.com"}}
	c.SubmitJob(job)

	r1Path := filepath.Join(tmpDir, "r1.jsonl")
	r2Path := filepath.Join(tmpDir, "r2.jsonl")
	os.WriteFile(r1Path, []byte(`{"template-id":"t1","host":"a.com"}`+"\n"), 0644)
	os.WriteFile(r2Path, []byte(`{"template-id":"t2","host":"b.com"}`+"\n"), 0644)

	job.mu.Lock()
	job.Results = append(job.Results, &WorkResult{WorkID: "w1", Status: "completed", ResultFile: r1Path})
	job.Results = append(job.Results, &WorkResult{WorkID: "w2", Status: "completed", ResultFile: r2Path})
	job.mu.Unlock()

	merged, err := c.MergeResults(job.ID)
	if err != nil {
		t.Fatalf("MergeResults failed: %v", err)
	}
	data, err := os.ReadFile(merged)
	if err != nil {
		t.Fatalf("read merged failed: %v", err)
	}
	if !strings.Contains(string(data), "t1") || !strings.Contains(string(data), "t2") {
		t.Errorf("merged file missing results: %s", string(data))
	}
}

func TestCoordinatorHTTPAPI(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := CoordinatorConfig{
		ListenAddr: "127.0.0.1:0",
		ResultsDir: tmpDir,
		NucleiBin:  "/bin/echo",
	}
	c := NewCoordinator(cfg)

	mux := http.NewServeMux()
	c.registerHandlers(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	infoJSON := `{"id":"api-worker","addr":"127.0.0.1:8888"}`
	resp, err = http.Post(server.URL+"/api/register", "application/json", strings.NewReader(infoJSON))
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	resp.Body.Close()

	resp, err = http.Get(server.URL + "/api/workers")
	if err != nil {
		t.Fatalf("list workers failed: %v", err)
	}
	var workers []*WorkerInfo
	json.NewDecoder(resp.Body).Decode(&workers)
	resp.Body.Close()
	if len(workers) != 1 {
		t.Fatalf("expected 1 worker, got %d", len(workers))
	}

	jobJSON := `{"name":"api-test","targets":["http://x.com","http://y.com"]}`
	resp, err = http.Post(server.URL+"/api/jobs", "application/json", strings.NewReader(jobJSON))
	if err != nil {
		t.Fatalf("submit job failed: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("submit status = %d", resp.StatusCode)
	}
	var created map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	jobID := created["id"].(string)

	resp, err = http.Get(server.URL + "/api/jobs/" + jobID)
	if err != nil {
		t.Fatalf("get job failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("get job status = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestWorkerConfig(t *testing.T) {
	cfg := DefaultWorkerConfig()
	if cfg.CoordinatorAddr == "" {
		t.Error("default coordinator addr should not be empty")
	}
	if cfg.WorkerID == "" {
		t.Error("default worker ID should not be empty")
	}
	if cfg.NucleiBin == "" {
		t.Error("default nuclei binary should not be empty")
	}
}

func TestJobIDFromWorkID(t *testing.T) {
	c := NewCoordinator(CoordinatorConfig{ResultsDir: t.TempDir()})
	tests := []struct {
		workID  string
		want    string
	}{
		{"dist-123-w0", "dist-123"},
		{"dist-123-456-w7", "dist-123-456"},
		{"no-w-suffix", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := c.jobIDFromWorkID(tt.workID)
		if got != tt.want {
			t.Errorf("jobIDFromWorkID(%q) = %q, want %q", tt.workID, got, tt.want)
		}
	}
}
