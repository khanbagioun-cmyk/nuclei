package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// registerHandlers sets up all REST API routes
func (d *Daemon) registerHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/api/jobs", d.handleJobs)
	mux.HandleFunc("/api/jobs/", d.handleJobByID)
	mux.HandleFunc("/api/schedules", d.handleSchedules)
	mux.HandleFunc("/api/diff/", d.handleDiff)
	mux.HandleFunc("/api/results/", d.handleResults)
	mux.HandleFunc("/health", d.handleHealth)
}

func (d *Daemon) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	d.jobsMu.RLock()
	running := 0
	for _, j := range d.jobs {
		j.mu.Lock()
		if j.Status == StatusRunning {
			running++
		}
		j.mu.Unlock()
	}
	d.jobsMu.RUnlock()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "ok",
		"total_jobs":      len(d.jobs),
		"running_jobs":    running,
		"queue_length":    len(d.queue),
		"max_concurrent":  d.config.MaxConcurrent,
	})
}

func (d *Daemon) handleJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		d.jobsMu.RLock()
		jobs := make([]map[string]interface{}, 0, len(d.jobs))
		for _, j := range d.jobs {
			jobs = append(jobs, jobToMap(j))
		}
		d.jobsMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jobs)

	case http.MethodPost:
		var job ScanJob
		if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(job.Targets) == 0 {
			http.Error(w, "targets is required", http.StatusBadRequest)
			return
		}
		if err := d.SubmitJob(&job); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":        job.ID,
			"name":      job.Name,
			"status":    job.Status,
			"targets":   job.Targets,
			"schedule":  job.Schedule,
			"created_at": job.CreatedAt,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (d *Daemon) handleJobByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	if id == "" {
		http.Error(w, "job id required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		job, ok := d.GetJob(id)
		if !ok {
			http.Error(w, "job not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(job)

	case http.MethodDelete:
		if !d.DeleteJob(id) {
			http.Error(w, "job not found", http.StatusNotFound)
			return
		}
		d.scheduler.Remove(id)
		w.WriteHeader(http.StatusNoContent)

	case http.MethodPut:
		// Cancel job
		if !d.CancelJob(id) {
			http.Error(w, "job not found", http.StatusNotFound)
			return
		}
		job, _ := d.GetJob(id)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jobToMap(job))

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (d *Daemon) handleSchedules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(d.scheduler.ListSchedules())
}

func (d *Daemon) handleDiff(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/diff/")
	if id == "" {
		http.Error(w, "job id required", http.StatusBadRequest)
		return
	}
	diff, err := d.GetDiff(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(diff)
}

func (d *Daemon) handleResults(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/results/")
	if id == "" {
		http.Error(w, "job id required", http.StatusBadRequest)
		return
	}
	runs := d.findResultRuns(id)
	if len(runs) == 0 {
		http.Error(w, "no results found", http.StatusNotFound)
		return
	}
	// Return the latest run's findings
	findings := d.parseResults(runs[len(runs)-1])
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"job_id":   id,
		"run_file": runs[len(runs)-1],
		"count":    len(findings),
		"findings": findings,
	})
}

// CLIHelp returns usage text for the daemon CLI

func jobToMap(j *ScanJob) map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	return map[string]interface{}{
		"id":           j.ID,
		"name":         j.Name,
		"targets":      j.Targets,
		"templates":    j.Templates,
		"tags":         j.Tags,
		"profile":      j.Profile,
		"extra_args":   j.ExtraArgs,
		"schedule":     j.Schedule,
		"status":       j.Status,
		"created_at":   j.CreatedAt,
		"started_at":   j.StartedAt,
		"finished_at":  j.FinishedAt,
		"results_path": j.ResultsPath,
		"result_count": j.ResultCount,
		"error_count":  j.ErrorCount,
		"error":        j.Error,
		"pid":          j.PID,
		"last_run_at":  j.LastRunAt,
		"next_run_at":  j.NextRunAt,
	}
}

func CLIHelp() string {
	return fmt.Sprintf(`nuclei-daemon — Continuous scan daemon

Usage:
  nuclei-daemon [options]

Options:
  -addr <addr>     Listen address (default 127.0.0.1:19091)
  -bin <path>      Path to nuclei binary (default ~/.local/bin/nuclei-dev)
  -results <dir>   Results directory (default ~/.cache/nuclei-dev/daemon-results)
  -max <n>         Max concurrent scans (default 3)
  -db <path>       State DB path (default ~/.config/nuclei-dev/daemon-state.json)

API Endpoints:
  GET    /health                 — daemon health
  GET    /api/jobs               — list all jobs
  POST   /api/jobs               — submit new job
  GET    /api/jobs/<id>          — get job status
  DELETE /api/jobs/<id>          — delete job
  PUT    /api/jobs/<id>          — cancel running job
  GET    /api/schedules          — list scheduled jobs
  GET    /api/diff/<id>          — diff latest two runs
  GET    /api/results/<id>       — latest results for job

Job JSON format (POST /api/jobs):
  {
    "name": "daily-web-scan",
    "targets": ["http://example.com", "http://test.com"],
    "templates": ["~/.config/nuclei-dev/custom-templates/"],
    "tags": ["cve", "exposure"],
    "profile": "web",
    "schedule": "daily",
    "extra_args": ["-rl", "50"]
  }

Schedule formats:
  "every:1h"       — every hour
  "every:30m"      — every 30 minutes
  "hourly"         — every hour
  "daily"          — every 24 hours
  "weekly"         — every 7 days
  "cron:0 3 * * *" — cron (minute hour dom month dow)
`)
}
