package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ScanStatus represents the current state of a scan job
type ScanStatus string

const (
	StatusPending   ScanStatus = "pending"
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
	StatusCancelled ScanStatus = "cancelled"
)

// ScanJob represents a single scan configuration submitted to the daemon
type ScanJob struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Targets      []string          `json:"targets"`
	Templates    []string          `json:"templates,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Profile      string            `json:"profile,omitempty"`
	ExtraArgs    []string          `json:"extra_args,omitempty"`
	Schedule     string            `json:"schedule,omitempty"`
	Status       ScanStatus        `json:"status"`
	CreatedAt    time.Time         `json:"created_at"`
	StartedAt    *time.Time        `json:"started_at,omitempty"`
	FinishedAt   *time.Time        `json:"finished_at,omitempty"`
	ResultsPath  string            `json:"results_path,omitempty"`
	ResultCount  int               `json:"result_count"`
	ErrorCount   int               `json:"error_count"`
	Error        string            `json:"error,omitempty"`
	PID          int               `json:"pid,omitempty"`
	LastRunAt    *time.Time        `json:"last_run_at,omitempty"`
	NextRunAt    *time.Time        `json:"next_run_at,omitempty"`
	mu           sync.Mutex
	cancel       context.CancelFunc
}

// DiffResult represents changes between two scan runs
type DiffResult struct {
	JobID       string         `json:"job_id"`
	PreviousRun *time.Time     `json:"previous_run,omitempty"`
	CurrentRun  *time.Time     `json:"current_run"`
	NewFindings []Finding       `json:"new_findings"`
	GoneFindings []Finding      `json:"gone_findings"`
	Summary     string         `json:"summary"`
}

// Finding represents a single vulnerability finding for diffing
type Finding struct {
	TemplateID string `json:"template_id"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched_at"`
	Severity   string `json:"severity"`
}

// Config configures the daemon
type Config struct {
	ListenAddr   string
	NucleiBin    string
	ResultsDir   string
	MaxConcurrent int
	DBPath       string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	home, _ := os.UserHomeDir()
	return Config{
		ListenAddr:    "127.0.0.1:19091",
		NucleiBin:     filepath.Join(home, ".local", "bin", "nuclei-dev"),
		ResultsDir:    filepath.Join(home, ".cache", "nuclei-dev", "daemon-results"),
		MaxConcurrent: 3,
		DBPath:        filepath.Join(home, ".config", "nuclei-dev", "daemon-state.json"),
	}
}

// Daemon is the continuous scan daemon
type Daemon struct {
	config    Config
	jobs      map[string]*ScanJob
	jobsMu    sync.RWMutex
	queue     chan string
	sem       chan struct{}
	server    *http.Server
	stopChan  chan struct{}
	scheduler *Scheduler
}

// New creates a new Daemon instance
func New(cfg Config) *Daemon {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 3
	}
	os.MkdirAll(cfg.ResultsDir, 0755)
	os.MkdirAll(filepath.Dir(cfg.DBPath), 0755)

	d := &Daemon{
		config:    cfg,
		jobs:      make(map[string]*ScanJob),
		queue:     make(chan string, 100),
		sem:       make(chan struct{}, cfg.MaxConcurrent),
		stopChan:  make(chan struct{}),
	}
	d.scheduler = NewScheduler(d)

	d.loadState()
	return d
}

// Start begins the daemon: REST API + worker + scheduler
func (d *Daemon) Start() error {
	mux := http.NewServeMux()
	d.registerHandlers(mux)

	d.server = &http.Server{Addr: d.config.ListenAddr, Handler: mux}

	go d.worker()
	go d.scheduler.Start()

	return d.server.ListenAndServe()
}

// Stop shuts down the daemon
func (d *Daemon) Stop() {
	close(d.stopChan)
	d.scheduler.Stop()
	if d.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = d.server.Shutdown(ctx)
	}
	d.saveState()
}

// --- Job Management ---

// SubmitJob creates a new scan job and enqueues it
func (d *Daemon) SubmitJob(job *ScanJob) error {
	if job.ID == "" {
		job.ID = generateID()
	}
	if job.Name == "" {
		job.Name = fmt.Sprintf("scan-%s", job.ID[:8])
	}
	job.Status = StatusPending
	job.CreatedAt = time.Now()

	d.jobsMu.Lock()
	d.jobs[job.ID] = job
	d.jobsMu.Unlock()

	d.saveState()

	if job.Schedule != "" {
		return d.scheduler.Add(job.ID, job.Schedule)
	}

	d.queue <- job.ID
	return nil
}

// GetJob returns a job by ID
func (d *Daemon) GetJob(id string) (*ScanJob, bool) {
	d.jobsMu.RLock()
	defer d.jobsMu.RUnlock()
	job, ok := d.jobs[id]
	return job, ok
}

// ListJobs returns all jobs
func (d *Daemon) ListJobs() []*ScanJob {
	d.jobsMu.RLock()
	defer d.jobsMu.RUnlock()
	jobs := make([]*ScanJob, 0, len(d.jobs))
	for _, j := range d.jobs {
		jobs = append(jobs, j)
	}
	return jobs
}

// CancelJob cancels a running or pending job
func (d *Daemon) CancelJob(id string) bool {
	d.jobsMu.Lock()
	job, ok := d.jobs[id]
	d.jobsMu.Unlock()
	if !ok {
		return false
	}
	job.mu.Lock()
	if job.Status == StatusRunning && job.cancel != nil {
		job.cancel()
	}
	job.Status = StatusCancelled
	now := time.Now()
	job.FinishedAt = &now
	job.mu.Unlock()
	d.saveState()
	return true
}

// DeleteJob removes a job from the daemon
func (d *Daemon) DeleteJob(id string) bool {
	d.jobsMu.Lock()
	if _, ok := d.jobs[id]; !ok {
		d.jobsMu.Unlock()
		return false
	}
	delete(d.jobs, id)
	d.jobsMu.Unlock()
	d.saveState()
	return true
}

// GetDiff compares the latest two runs of a job
func (d *Daemon) GetDiff(jobID string) (*DiffResult, error) {
	d.jobsMu.RLock()
	_, ok := d.jobs[jobID]
	d.jobsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("job not found")
	}

	runs := d.findResultRuns(jobID)
	if len(runs) < 1 {
		return nil, fmt.Errorf("no results found for job")
	}

	currentRun := runs[len(runs)-1]
	currentFindings := d.parseResults(currentRun)
	var currentTime *time.Time
	if fi, err := os.Stat(currentRun); err == nil {
		t := fi.ModTime()
		currentTime = &t
	}

	var prevFindings []Finding
	var prevTime *time.Time
	if len(runs) >= 2 {
		prevRun := runs[len(runs)-2]
		prevFindings = d.parseResults(prevRun)
		fi, _ := os.Stat(prevRun)
		t := fi.ModTime()
		prevTime = &t
	}

	diff := &DiffResult{
		JobID:       jobID,
		PreviousRun: prevTime,
		CurrentRun:  currentTime,
	}

	currentSet := findingSet(currentFindings)
	prevSet := findingSet(prevFindings)

	for f := range currentSet {
		if _, exists := prevSet[f]; !exists {
			diff.NewFindings = append(diff.NewFindings, f)
		}
	}
	for f := range prevSet {
		if _, exists := currentSet[f]; !exists {
			diff.GoneFindings = append(diff.GoneFindings, f)
		}
	}

	diff.Summary = fmt.Sprintf("%d new findings, %d gone findings",
		len(diff.NewFindings), len(diff.GoneFindings))

	return diff, nil
}

// --- Worker ---

func (d *Daemon) worker() {
	for {
		select {
		case <-d.stopChan:
			return
		case jobID := <-d.queue:
			d.sem <- struct{}{}
			go func(id string) {
				defer func() { <-d.sem }()
				d.executeJob(id)
			}(jobID)
		}
	}
}

func (d *Daemon) executeJob(jobID string) {
	d.jobsMu.RLock()
	job, ok := d.jobs[jobID]
	d.jobsMu.RUnlock()
	if !ok {
		return
	}

	job.mu.Lock()
	if job.Status == StatusCancelled {
		job.mu.Unlock()
		return
	}
	now := time.Now()
	job.Status = StatusRunning
	job.StartedAt = &now
	job.Error = ""
	job.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	job.mu.Lock()
	job.cancel = cancel
	job.mu.Unlock()
	defer cancel()

	resultFile := filepath.Join(d.config.ResultsDir, fmt.Sprintf("%s-%s.jsonl", jobID, now.Format("20060102-150405")))

	args := d.buildArgs(job, resultFile)
	cmd := exec.CommandContext(ctx, d.config.NucleiBin, args...)
	cmd.Stderr = os.Stderr

	job.mu.Lock()
	if cmd.Process != nil {
		job.PID = cmd.Process.Pid
	}
	job.mu.Unlock()

	err := cmd.Run()

	finished := time.Now()
	job.mu.Lock()
	job.FinishedAt = &finished
	job.LastRunAt = &finished
	job.ResultsPath = resultFile
	if err != nil {
		job.Status = StatusFailed
		job.Error = err.Error()
	} else {
		job.Status = StatusCompleted
	}
	job.PID = 0
	job.cancel = nil
	job.mu.Unlock()

	d.countResults(job)
	d.saveState()

	if job.Schedule != "" {
		d.scheduler.UpdateNextRun(jobID)
	}
}

func (d *Daemon) buildArgs(job *ScanJob, resultFile string) []string {
	args := []string{"-jsonl", "-o", resultFile, "-nc"}

	for _, t := range job.Targets {
		args = append(args, "-u", t)
	}
	for _, t := range job.Templates {
		args = append(args, "-t", t)
	}
	if len(job.Tags) > 0 {
		args = append(args, "-tags", strings.Join(job.Tags, ","))
	}
	if job.Profile != "" {
		switch job.Profile {
		case "web":
			args = append(args, "-tp", filepath.Join(os.Getenv("HOME"), ".config/nuclei-dev/profiles/web.txt"))
		case "network":
			args = append(args, "-tp", filepath.Join(os.Getenv("HOME"), ".config/nuclei-dev/profiles/network.txt"))
		case "critical":
			args = append(args, "-tp", filepath.Join(os.Getenv("HOME"), ".config/nuclei-dev/profiles/critical.txt"))
		}
	}
	args = append(args, job.ExtraArgs...)
	return args
}

func (d *Daemon) countResults(job *ScanJob) {
	if job.ResultsPath == "" {
		return
	}
	data, err := os.ReadFile(job.ResultsPath)
	if err != nil {
		return
	}
	count := 0
	errors := 0
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]interface{}
		if json.Unmarshal([]byte(line), &entry) == nil {
			if ms, ok := entry["matcher-status"].(bool); ok && ms {
				count++
			}
			if _, ok := entry["error"]; ok {
				errors++
			}
		}
	}
	job.mu.Lock()
	job.ResultCount = count
	job.ErrorCount = errors
	job.mu.Unlock()
}

func (d *Daemon) parseResults(path string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var findings []Finding
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			TemplateID string `json:"template-id"`
			Host       string `json:"host"`
			MatchedAt  string `json:"matched-at"`
			Info       struct {
				Severity string `json:"severity"`
			} `json:"info"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.TemplateID != "" {
			findings = append(findings, Finding{
				TemplateID: entry.TemplateID,
				Host:       entry.Host,
				MatchedAt:  entry.MatchedAt,
				Severity:   entry.Info.Severity,
			})
		}
	}
	return findings
}

func (d *Daemon) findResultRuns(jobID string) []string {
	entries, err := os.ReadDir(d.config.ResultsDir)
	if err != nil {
		return nil
	}
	var runs []string
	prefix := jobID + "-"
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ".jsonl") {
			runs = append(runs, filepath.Join(d.config.ResultsDir, e.Name()))
		}
	}
	return runs
}

// --- State Persistence ---

func (d *Daemon) saveState() {
	d.jobsMu.RLock()
	defer d.jobsMu.RUnlock()

	type jobExport struct {
		ID          string     `json:"id"`
		Name        string     `json:"name"`
		Targets     []string   `json:"targets"`
		Templates   []string   `json:"templates"`
		Tags        []string   `json:"tags"`
		Profile     string     `json:"profile"`
		ExtraArgs   []string   `json:"extra_args"`
		Schedule    string     `json:"schedule"`
		Status      ScanStatus `json:"status"`
		CreatedAt   time.Time  `json:"created_at"`
		StartedAt   *time.Time `json:"started_at,omitempty"`
		FinishedAt  *time.Time `json:"finished_at,omitempty"`
		ResultsPath string     `json:"results_path"`
		ResultCount int        `json:"result_count"`
		ErrorCount  int        `json:"error_count"`
		LastRunAt   *time.Time `json:"last_run_at,omitempty"`
	}

	export := make([]jobExport, 0, len(d.jobs))
	for _, j := range d.jobs {
		j.mu.Lock()
		export = append(export, jobExport{
			ID: j.ID, Name: j.Name, Targets: j.Targets, Templates: j.Templates,
			Tags: j.Tags, Profile: j.Profile, ExtraArgs: j.ExtraArgs,
			Schedule: j.Schedule, Status: j.Status, CreatedAt: j.CreatedAt,
			StartedAt: j.StartedAt, FinishedAt: j.FinishedAt,
			ResultsPath: j.ResultsPath, ResultCount: j.ResultCount,
			ErrorCount: j.ErrorCount, LastRunAt: j.LastRunAt,
		})
		j.mu.Unlock()
	}

	data, _ := json.MarshalIndent(export, "", "  ")
	_ = os.WriteFile(d.config.DBPath, data, 0644)
}

func (d *Daemon) loadState() {
	data, err := os.ReadFile(d.config.DBPath)
	if err != nil {
		return
	}
	var export []struct {
		ID          string     `json:"id"`
		Name        string     `json:"name"`
		Targets     []string   `json:"targets"`
		Templates   []string   `json:"templates"`
		Tags        []string   `json:"tags"`
		Profile     string     `json:"profile"`
		ExtraArgs   []string   `json:"extra_args"`
		Schedule    string     `json:"schedule"`
		Status      ScanStatus `json:"status"`
		CreatedAt   time.Time  `json:"created_at"`
		StartedAt   *time.Time `json:"started_at,omitempty"`
		FinishedAt  *time.Time `json:"finished_at,omitempty"`
		ResultsPath string     `json:"results_path"`
		ResultCount int        `json:"result_count"`
		ErrorCount  int        `json:"error_count"`
		LastRunAt   *time.Time `json:"last_run_at,omitempty"`
	}
	if json.Unmarshal(data, &export) != nil {
		return
	}

	for _, e := range export {
		job := &ScanJob{
			ID: e.ID, Name: e.Name, Targets: e.Targets, Templates: e.Templates,
			Tags: e.Tags, Profile: e.Profile, ExtraArgs: e.ExtraArgs,
			Schedule: e.Schedule, Status: e.Status, CreatedAt: e.CreatedAt,
			StartedAt: e.StartedAt, FinishedAt: e.FinishedAt,
			ResultsPath: e.ResultsPath, ResultCount: e.ResultCount,
			ErrorCount: e.ErrorCount, LastRunAt: e.LastRunAt,
		}
		if job.Status == StatusRunning {
			job.Status = StatusFailed
			job.Error = "daemon restarted during execution"
		}
		d.jobs[e.ID] = job
		if job.Schedule != "" {
			_ = d.scheduler.Add(job.ID, job.Schedule)
		}
	}
}

// --- Helpers ---

func findingSet(findings []Finding) map[Finding]struct{} {
	set := make(map[Finding]struct{})
	for _, f := range findings {
		set[f] = struct{}{}
	}
	return set
}

var idCounter atomic.Int64

func generateID() string {
	return fmt.Sprintf("job-%d-%d", time.Now().Unix(), idCounter.Add(1))
}
