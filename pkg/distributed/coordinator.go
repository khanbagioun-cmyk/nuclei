package distributed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// WorkItem represents a unit of work to be distributed to workers
type WorkItem struct {
	ID         string            `json:"id"`
	JobID      string            `json:"job_id"`
	Target     string            `json:"target"`
	Templates  []string          `json:"templates,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
	ExtraArgs  []string          `json:"extra_args,omitempty"`
	NucleiBin  string            `json:"nuclei_bin,omitempty"`
}

// WorkResult represents the result of a completed work item
type WorkResult struct {
	WorkID     string `json:"work_id"`
	WorkerID   string `json:"worker_id"`
	Status     string `json:"status"`
	ResultFile string `json:"result_file,omitempty"`
	MatchCount int    `json:"match_count"`
	ErrorCount int    `json:"error_count"`
	Error      string `json:"error,omitempty"`
	Duration   string `json:"duration"`
}

// WorkerInfo describes a registered worker
type WorkerInfo struct {
	ID           string     `json:"id"`
	Addr         string     `json:"addr"`
	Capabilities []string   `json:"capabilities"`
	LastSeen     time.Time  `json:"last_seen"`
	CurrentWork  string     `json:"current_work,omitempty"`
}

// Job represents a distributed scan job
type Job struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Targets   []string    `json:"targets"`
	Templates []string    `json:"templates,omitempty"`
	Tags      []string    `json:"tags,omitempty"`
	ExtraArgs []string    `json:"extra_args,omitempty"`
	Status    string      `json:"status"`
	CreatedAt time.Time   `json:"created_at"`
	WorkItems []*WorkItem `json:"work_items"`
	Results   []*WorkResult `json:"results"`
	mu        sync.Mutex
}

// CoordinatorConfig configures the distributed coordinator
type CoordinatorConfig struct {
	ListenAddr  string
	ResultsDir  string
	NucleiBin   string
	ChunkSize   int
}

// DefaultCoordinatorConfig returns sensible defaults
func DefaultCoordinatorConfig() CoordinatorConfig {
	home, _ := os.UserHomeDir()
	return CoordinatorConfig{
		ListenAddr: "127.0.0.1:19093",
		ResultsDir: filepath.Join(home, ".cache", "nuclei-dev", "distributed-results"),
		NucleiBin:  filepath.Join(home, ".local", "bin", "nuclei-dev"),
		ChunkSize:  10,
	}
}

// Coordinator manages work distribution across worker processes
type Coordinator struct {
	config    CoordinatorConfig
	jobs      map[string]*Job
	jobsMu    sync.RWMutex
	workers   map[string]*WorkerInfo
	workersMu sync.RWMutex
	workQueue chan *WorkItem
	results   chan *WorkResult
	stopChan  chan struct{}
	server    *http.Server
	idCounter int64
	mu        sync.Mutex
}

// NewCoordinator creates a new coordinator
func NewCoordinator(cfg CoordinatorConfig) *Coordinator {
	os.MkdirAll(cfg.ResultsDir, 0755)
	return &Coordinator{
		config:    cfg,
		jobs:      make(map[string]*Job),
		workers:   make(map[string]*WorkerInfo),
		workQueue: make(chan *WorkItem, 1000),
		results:   make(chan *WorkResult, 1000),
		stopChan:  make(chan struct{}),
	}
}

// Start begins the coordinator HTTP server
func (c *Coordinator) Start() error {
	mux := http.NewServeMux()
	c.registerHandlers(mux)
	c.server = &http.Server{Addr: c.config.ListenAddr, Handler: mux}
	go c.processResults()
	return c.server.ListenAndServe()
}

// Stop shuts down the coordinator
func (c *Coordinator) Stop() {
	close(c.stopChan)
	if c.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = c.server.Shutdown(ctx)
	}
}

// SubmitJob creates a distributed job by splitting targets into work items
func (c *Coordinator) SubmitJob(job *Job) error {
	if job.ID == "" {
		c.mu.Lock()
		c.idCounter++
		job.ID = fmt.Sprintf("dist-%d-%d", time.Now().Unix(), c.idCounter)
		c.mu.Unlock()
	}
	if job.Name == "" {
		job.Name = fmt.Sprintf("dist-scan-%s", job.ID[:8])
	}
	job.Status = "pending"
	job.CreatedAt = time.Now()

	chunkSize := c.config.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 10
	}

	for i, target := range job.Targets {
		workID := fmt.Sprintf("%s-w%d", job.ID, i)
		item := &WorkItem{
			ID:        workID,
			JobID:     job.ID,
			Target:    target,
			Templates: job.Templates,
			Tags:      job.Tags,
			ExtraArgs: job.ExtraArgs,
			NucleiBin: c.config.NucleiBin,
		}
		job.WorkItems = append(job.WorkItems, item)
	}

	c.jobsMu.Lock()
	c.jobs[job.ID] = job
	c.jobsMu.Unlock()

	for _, item := range job.WorkItems {
		c.workQueue <- item
	}

	job.mu.Lock()
	job.Status = "queued"
	job.mu.Unlock()

	return nil
}

// GetJob returns a job by ID
func (c *Coordinator) GetJob(id string) (*Job, bool) {
	c.jobsMu.RLock()
	defer c.jobsMu.RUnlock()
	job, ok := c.jobs[id]
	return job, ok
}

// ListJobs returns all jobs
func (c *Coordinator) ListJobs() []*Job {
	c.jobsMu.RLock()
	defer c.jobsMu.RUnlock()
	jobs := make([]*Job, 0, len(c.jobs))
	for _, j := range c.jobs {
		jobs = append(jobs, j)
	}
	return jobs
}

// GetNextWork returns the next work item for a worker (blocking up to timeout)
func (c *Coordinator) GetNextWork() *WorkItem {
	select {
	case item := <-c.workQueue:
		return item
	case <-time.After(30 * time.Second):
		return nil
	case <-c.stopChan:
		return nil
	}
}

// SubmitResult accepts a work result from a worker
func (c *Coordinator) SubmitResult(result *WorkResult) {
	c.results <- result
}

// RegisterWorker registers a new worker
func (c *Coordinator) RegisterWorker(w *WorkerInfo) {
	c.workersMu.Lock()
	defer c.workersMu.Unlock()
	w.LastSeen = time.Now()
	c.workers[w.ID] = w
}

// Heartbeat updates worker last-seen time
func (c *Coordinator) Heartbeat(workerID string) bool {
	c.workersMu.Lock()
	defer c.workersMu.Unlock()
	w, ok := c.workers[workerID]
	if !ok {
		return false
	}
	w.LastSeen = time.Now()
	return true
}

// ListWorkers returns all registered workers
func (c *Coordinator) ListWorkers() []*WorkerInfo {
	c.workersMu.RLock()
	defer c.workersMu.RUnlock()
	workers := make([]*WorkerInfo, 0, len(c.workers))
	for _, w := range c.workers {
		workers = append(workers, w)
	}
	return workers
}

func (c *Coordinator) processResults() {
	for {
		select {
		case <-c.stopChan:
			return
		case result := <-c.results:
			jobID := c.jobIDFromWorkID(result.WorkID)
			if jobID == "" {
				continue
			}
			c.jobsMu.RLock()
			job, ok := c.jobs[jobID]
			c.jobsMu.RUnlock()
			if !ok {
				continue
			}
			job.mu.Lock()
			job.Results = append(job.Results, result)
			allDone := len(job.Results) == len(job.WorkItems)
			if allDone {
				job.Status = "completed"
			}
			job.mu.Unlock()

			c.workersMu.Lock()
			if w, ok := c.workers[result.WorkerID]; ok {
				w.CurrentWork = ""
			}
			c.workersMu.Unlock()
		}
	}
}

func (c *Coordinator) jobIDFromWorkID(workID string) string {
	idx := strings.LastIndex(workID, "-w")
	if idx < 0 || idx+2 >= len(workID) {
		return ""
	}
	suffix := workID[idx+2:]
	for _, ch := range suffix {
		if ch < '0' || ch > '9' {
			return ""
		}
	}
	return workID[:idx]
}

// MergeResults merges all result files from a distributed job into one
func (c *Coordinator) MergeResults(jobID string) (string, error) {
	c.jobsMu.RLock()
	job, ok := c.jobs[jobID]
	c.jobsMu.RUnlock()
	if !ok {
		return "", fmt.Errorf("job not found")
	}
	job.mu.Lock()
	defer job.mu.Unlock()

	mergedPath := filepath.Join(c.config.ResultsDir, jobID+"-merged.jsonl")
	out, err := os.Create(mergedPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	for _, result := range job.Results {
		if result.ResultFile == "" || result.Status != "completed" {
			continue
		}
		data, err := os.ReadFile(result.ResultFile)
		if err != nil {
			continue
		}
		out.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			out.Write([]byte("\n"))
		}
	}
	return mergedPath, nil
}

// --- HTTP Handlers ---

func (c *Coordinator) registerHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/api/work", c.handleGetWork)
	mux.HandleFunc("/api/result", c.handleSubmitResult)
	mux.HandleFunc("/api/register", c.handleRegister)
	mux.HandleFunc("/api/heartbeat", c.handleHeartbeat)
	mux.HandleFunc("/api/jobs", c.handleJobs)
	mux.HandleFunc("/api/jobs/", c.handleJobByID)
	mux.HandleFunc("/api/workers", c.handleWorkers)
	mux.HandleFunc("/api/merge/", c.handleMerge)
	mux.HandleFunc("/health", c.handleHealth)
}

func (c *Coordinator) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.workersMu.RLock()
	activeWorkers := 0
	for _, w := range c.workers {
		if time.Since(w.LastSeen) < 2*time.Minute {
			activeWorkers++
		}
	}
	c.workersMu.RUnlock()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"total_jobs":    len(c.jobs),
		"queue_length":  len(c.workQueue),
		"active_workers": activeWorkers,
		"total_workers": len(c.workers),
	})
}

func (c *Coordinator) handleGetWork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	item := c.GetNextWork()
	if item == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	workerID := r.URL.Query().Get("worker")
	if workerID != "" {
		c.workersMu.Lock()
		if w, ok := c.workers[workerID]; ok {
			w.CurrentWork = item.ID
		}
		c.workersMu.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(item)
}

func (c *Coordinator) handleSubmitResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var result WorkResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.SubmitResult(&result)
	w.WriteHeader(http.StatusAccepted)
}

func (c *Coordinator) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var info WorkerInfo
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if info.ID == "" {
		info.ID = fmt.Sprintf("worker-%d", time.Now().UnixNano())
	}
	c.RegisterWorker(&info)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func (c *Coordinator) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	workerID := r.URL.Query().Get("worker")
	if workerID == "" {
		http.Error(w, "worker param required", http.StatusBadRequest)
		return
	}
	if !c.Heartbeat(workerID) {
		http.Error(w, "worker not registered", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) handleJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c.ListJobs())
	case http.MethodPost:
		var job Job
		if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(job.Targets) == 0 {
			http.Error(w, "targets required", http.StatusBadRequest)
			return
		}
		if err := c.SubmitJob(&job); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": job.ID, "status": job.Status})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *Coordinator) handleJobByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	job, ok := c.GetJob(id)
	if !ok {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	job.mu.Lock()
	export := struct {
		ID        string        `json:"id"`
		Name      string        `json:"name"`
		Targets   []string      `json:"targets"`
		Templates []string      `json:"templates"`
		Status    string        `json:"status"`
		CreatedAt time.Time     `json:"created_at"`
		WorkCount int           `json:"work_count"`
		Results   []*WorkResult `json:"results"`
	}{
		ID: job.ID, Name: job.Name, Targets: job.Targets, Templates: job.Templates,
		Status: job.Status, CreatedAt: job.CreatedAt,
		WorkCount: len(job.WorkItems), Results: job.Results,
	}
	job.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(export)
}

func (c *Coordinator) handleWorkers(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(c.ListWorkers())
}

func (c *Coordinator) handleMerge(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/merge/")
	merged, err := c.MergeResults(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	data, _ := os.ReadFile(merged)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"job_id":    id,
		"file":      merged,
		"size":      len(data),
		"results":   strings.Count(string(data), "\n") + 1,
	})
}

// ReadAll reads all from r
func ReadAll(r io.Reader) []byte {
	data, _ := io.ReadAll(r)
	return data
}
