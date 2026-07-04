package distributed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// WorkerConfig configures a distributed worker
type WorkerConfig struct {
	CoordinatorAddr string
	WorkerID        string
	NucleiBin       string
	ResultsDir      string
	PollInterval    time.Duration
	HeartbeatInterval time.Duration
}

// DefaultWorkerConfig returns sensible defaults
func DefaultWorkerConfig() WorkerConfig {
	home, _ := os.UserHomeDir()
	return WorkerConfig{
		CoordinatorAddr:   "127.0.0.1:19093",
		WorkerID:          fmt.Sprintf("worker-%d", time.Now().UnixNano()%100000),
		NucleiBin:         filepath.Join(home, ".local", "bin", "nuclei-dev"),
		ResultsDir:        filepath.Join(home, ".cache", "nuclei-dev", "worker-results"),
		PollInterval:      5 * time.Second,
		HeartbeatInterval: 30 * time.Second,
	}
}

// Worker pulls work from the coordinator and executes scans
type Worker struct {
	config   WorkerConfig
	client   *http.Client
	stopChan chan struct{}
}

// NewWorker creates a new worker
func NewWorker(cfg WorkerConfig) *Worker {
	os.MkdirAll(cfg.ResultsDir, 0755)
	return &Worker{
		config:   cfg,
		client:   &http.Client{Timeout: 60 * time.Second},
		stopChan: make(chan struct{}),
	}
}

// Register registers the worker with the coordinator
func (w *Worker) Register() error {
	info := WorkerInfo{
		ID:   w.config.WorkerID,
		Addr: w.config.CoordinatorAddr,
	}
	data, _ := json.Marshal(info)
	resp, err := w.client.Post(
		fmt.Sprintf("http://%s/api/register", w.config.CoordinatorAddr),
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed: %s", resp.Status)
	}
	return nil
}

// Start begins the worker loop: poll for work, execute, report results
func (w *Worker) Start() error {
	if err := w.Register(); err != nil {
		return err
	}

	// Start heartbeat goroutine
	go w.heartbeatLoop()

	// Main work loop
	for {
		select {
		case <-w.stopChan:
			return nil
		default:
		}

		item := w.fetchWork()
		if item == nil {
			time.Sleep(w.config.PollInterval)
			continue
		}

		result := w.executeWork(item)
		w.reportResult(result)
	}
}

// Stop signals the worker to stop
func (w *Worker) Stop() {
	close(w.stopChan)
}

func (w *Worker) fetchWork() *WorkItem {
	url := fmt.Sprintf("http://%s/api/work?worker=%s", w.config.CoordinatorAddr, w.config.WorkerID)
	resp, err := w.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var item WorkItem
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return nil
	}
	return &item
}

func (w *Worker) executeWork(item *WorkItem) *WorkResult {
	start := time.Now()
	result := &WorkResult{
		WorkID:   item.ID,
		WorkerID: w.config.WorkerID,
	}

	resultFile := filepath.Join(w.config.ResultsDir, item.ID+".jsonl")

	nucleiBin := item.NucleiBin
	if nucleiBin == "" {
		nucleiBin = w.config.NucleiBin
	}

	args := []string{"-jsonl", "-o", resultFile, "-nc", "-u", item.Target}
	for _, t := range item.Templates {
		args = append(args, "-t", t)
	}
	if len(item.Tags) > 0 {
		args = append(args, "-tags", strings.Join(item.Tags, ","))
	}
	args = append(args, item.ExtraArgs...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, nucleiBin, args...)
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		result.Status = "failed"
		result.Error = err.Error()
	} else {
		result.Status = "completed"
		result.ResultFile = resultFile
	}

	result.Duration = time.Since(start).String()
	w.countResults(resultFile, result)
	return result
}

func (w *Worker) countResults(path string, result *WorkResult) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]interface{}
		if json.Unmarshal([]byte(line), &entry) == nil {
			if ms, ok := entry["matcher-status"].(bool); ok && ms {
				result.MatchCount++
			}
			if _, ok := entry["error"]; ok {
				result.ErrorCount++
			}
		}
	}
}

func (w *Worker) reportResult(result *WorkResult) {
	data, _ := json.Marshal(result)
	resp, err := w.client.Post(
		fmt.Sprintf("http://%s/api/result", w.config.CoordinatorAddr),
		"application/json",
		bytes.NewReader(data),
	)
	if err == nil {
		resp.Body.Close()
	}
}

func (w *Worker) heartbeatLoop() {
	ticker := time.NewTicker(w.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopChan:
			return
		case <-ticker.C:
			url := fmt.Sprintf("http://%s/api/heartbeat?worker=%s", w.config.CoordinatorAddr, w.config.WorkerID)
			resp, err := w.client.Get(url)
			if err == nil {
				resp.Body.Close()
			}
		}
	}
}
