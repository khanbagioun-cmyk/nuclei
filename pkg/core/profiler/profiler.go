package profiler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Profiler collects per-template, per-host, and per-protocol timing metrics
// during a nuclei scan. It is designed as a non-blocking, thread-safe
// collector that can be queried via HTTP (Prometheus + JSON) or exported
// to a file at scan completion.
type Profiler struct {
	config     Config
	templates  sync.Map // map[string]*TemplateStats
	hosts      sync.Map // map[string]*HostStats
	protocols  sync.Map // map[string]*ProtocolStats
	startTime  time.Time
	totalReqs  atomic.Uint64
	totalMatch atomic.Uint64
	totalErrs  atomic.Uint64
	mu         sync.RWMutex
	stopChan   chan struct{}
	httpServer *http.Server
}

// Config controls profiler behavior
type Config struct {
	// Enabled turns on profiling collection
	Enabled bool
	// ListenAddr is the HTTP server address (default 127.0.0.1:19090)
	ListenAddr string
	// OutputFile is the path to write final JSON report (empty = no file)
	OutputFile string
	// AutoTune enables automatic concurrency/rate-limit adjustment
	AutoTune bool
	// AutoTuneMinRPS is the minimum RPS before auto-tune triggers
	AutoTuneMinRPS float64
	// AutoTuneMaxErrors is the error percentage threshold for auto-tune
	AutoTuneMaxErrors float64
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		ListenAddr:        "127.0.0.1:19090",
		AutoTune:          false,
		AutoTuneMinRPS:    10,
		AutoTuneMaxErrors: 30,
	}
}

// TemplateStats holds per-template performance metrics
type TemplateStats struct {
	ID         string        `json:"id"`
	Path       string        `json:"path"`
	Protocol   string        `json:"protocol"`
	Count      atomic.Uint64 `json:"-"`
	Matches    atomic.Uint64 `json:"-"`
	Errors     atomic.Uint64 `json:"-"`
	TotalDur   atomic.Uint64 `json:"-"` // nanoseconds
	MaxDur     atomic.Uint64 `json:"-"` // nanoseconds
	MinDur     atomic.Uint64 `json:"-"` // nanoseconds
}

// MarshalJSON implements json.Marshaler for TemplateStats
func (t *TemplateStats) MarshalJSON() ([]byte, error) {
	count := t.Count.Load()
	totalDur := t.TotalDur.Load()
	var avgDur float64
	if count > 0 {
		avgDur = float64(totalDur) / float64(count) / 1e6 // ms
	}
	maxDur := float64(t.MaxDur.Load()) / 1e6
	minDur := float64(t.MinDur.Load()) / 1e6
	return json.Marshal(struct {
		ID         string  `json:"id"`
		Path       string  `json:"path"`
		Protocol   string  `json:"protocol"`
		Executions uint64  `json:"executions"`
		Matches    uint64  `json:"matches"`
		Errors     uint64  `json:"errors"`
		AvgDurMS   float64 `json:"avg_dur_ms"`
		MaxDurMS   float64 `json:"max_dur_ms"`
		MinDurMS   float64 `json:"min_dur_ms"`
		TotalDurMS float64 `json:"total_dur_ms"`
	}{
		ID: t.ID, Path: t.Path, Protocol: t.Protocol,
		Executions: count, Matches: t.Matches.Load(), Errors: t.Errors.Load(),
		AvgDurMS: avgDur, MaxDurMS: maxDur, MinDurMS: minDur,
		TotalDurMS: float64(totalDur) / 1e6,
	})
}

// HostStats holds per-host performance metrics
type HostStats struct {
	Host     string        `json:"host"`
	Count    atomic.Uint64 `json:"-"`
	Matches  atomic.Uint64 `json:"-"`
	Errors   atomic.Uint64 `json:"-"`
	TotalDur atomic.Uint64 `json:"-"`
}

// MarshalJSON implements json.Marshaler for HostStats
func (h *HostStats) MarshalJSON() ([]byte, error) {
	count := h.Count.Load()
	totalDur := h.TotalDur.Load()
	var avgDur float64
	if count > 0 {
		avgDur = float64(totalDur) / float64(count) / 1e6
	}
	return json.Marshal(struct {
		Host       string  `json:"host"`
		Executions uint64  `json:"executions"`
		Matches    uint64  `json:"matches"`
		Errors     uint64  `json:"errors"`
		AvgDurMS   float64 `json:"avg_dur_ms"`
		TotalDurMS float64 `json:"total_dur_ms"`
	}{
		Host: h.Host, Executions: count, Matches: h.Matches.Load(),
		Errors: h.Errors.Load(), AvgDurMS: avgDur,
		TotalDurMS: float64(totalDur) / 1e6,
	})
}

// ProtocolStats holds per-protocol aggregate metrics
type ProtocolStats struct {
	Protocol string        `json:"protocol"`
	Count    atomic.Uint64 `json:"-"`
	Matches  atomic.Uint64 `json:"-"`
	Errors   atomic.Uint64 `json:"-"`
	TotalDur atomic.Uint64 `json:"-"`
}

// MarshalJSON implements json.Marshaler for ProtocolStats
func (p *ProtocolStats) MarshalJSON() ([]byte, error) {
	count := p.Count.Load()
	totalDur := p.TotalDur.Load()
	var avgDur float64
	if count > 0 {
		avgDur = float64(totalDur) / float64(count) / 1e6
	}
	return json.Marshal(struct {
		Protocol   string  `json:"protocol"`
		Executions uint64  `json:"executions"`
		Matches    uint64  `json:"matches"`
		Errors     uint64  `json:"errors"`
		AvgDurMS   float64 `json:"avg_dur_ms"`
		TotalDurMS float64 `json:"total_dur_ms"`
	}{
		Protocol: p.Protocol, Executions: count, Matches: p.Matches.Load(),
		Errors: p.Errors.Load(), AvgDurMS: avgDur,
		TotalDurMS: float64(totalDur) / 1e6,
	})
}

// New creates a new Profiler with the given config
func New(cfg Config) *Profiler {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:19090"
	}
	return &Profiler{
		config:    cfg,
		startTime: time.Now(),
		stopChan:  make(chan struct{}),
	}
}

// Start begins the HTTP metrics server if enabled
func (p *Profiler) Start() error {
	if !p.config.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", p.handleMetricsJSON)
	mux.HandleFunc("/metrics/prometheus", p.handleMetricsPrometheus)
	mux.HandleFunc("/profile/templates", p.handleTemplateProfile)
	mux.HandleFunc("/profile/hosts", p.handleHostProfile)
	mux.HandleFunc("/profile/protocols", p.handleProtocolProfile)
	mux.HandleFunc("/autotune", p.handleAutoTune)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	p.httpServer = &http.Server{Addr: p.config.ListenAddr, Handler: mux}

	go func() {
		if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "[profiler] http server error: %v\n", err)
		}
	}()

	return nil
}

// Stop shuts down the HTTP server and writes the final report if configured
func (p *Profiler) Stop() {
	close(p.stopChan)
	if p.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.httpServer.Shutdown(ctx)
	}
	if p.config.OutputFile != "" {
		_ = p.WriteReport(p.config.OutputFile)
	}
}

// RecordTemplateExecution records a single template execution timing
func (p *Profiler) RecordTemplateExecution(templateID, templatePath, protocol string, duration time.Duration, matched bool, errored bool) {
	if !p.config.Enabled {
		return
	}

	p.totalReqs.Add(1)
	if matched {
		p.totalMatch.Add(1)
	}
	if errored {
		p.totalErrs.Add(1)
	}

	// Template stats
	val, _ := p.templates.LoadOrStore(templateID, &TemplateStats{
		ID:       templateID,
		Path:     templatePath,
		Protocol: protocol,
	})
	ts := val.(*TemplateStats)
	ts.Count.Add(1)
	if matched {
		ts.Matches.Add(1)
	}
	if errored {
		ts.Errors.Add(1)
	}
	durNs := uint64(duration.Nanoseconds())
	ts.TotalDur.Add(durNs)
	for {
		current := ts.MaxDur.Load()
		if durNs <= current {
			break
		}
		if ts.MaxDur.CompareAndSwap(current, durNs) {
			break
		}
	}
	for {
		current := ts.MinDur.Load()
		if current > 0 && durNs >= current {
			break
		}
		if ts.MinDur.CompareAndSwap(current, durNs) {
			break
		}
	}

	// Protocol stats
	pval, _ := p.protocols.LoadOrStore(protocol, &ProtocolStats{Protocol: protocol})
	ps := pval.(*ProtocolStats)
	ps.Count.Add(1)
	if matched {
		ps.Matches.Add(1)
	}
	if errored {
		ps.Errors.Add(1)
	}
	ps.TotalDur.Add(durNs)
}

// RecordHostExecution records a single host execution timing
func (p *Profiler) RecordHostExecution(host string, duration time.Duration, matched bool, errored bool) {
	if !p.config.Enabled {
		return
	}

	val, _ := p.hosts.LoadOrStore(host, &HostStats{Host: host})
	hs := val.(*HostStats)
	hs.Count.Add(1)
	if matched {
		hs.Matches.Add(1)
	}
	if errored {
		hs.Errors.Add(1)
	}
	hs.TotalDur.Add(uint64(duration.Nanoseconds()))
}

// GetSnapshot returns a point-in-time snapshot of all metrics
func (p *Profiler) GetSnapshot() Snapshot {
	duration := time.Since(p.startTime)

	snap := Snapshot{
		Timestamp:   time.Now(),
		Duration:    duration.String(),
		TotalReqs:   p.totalReqs.Load(),
		TotalMatch:  p.totalMatch.Load(),
		TotalErrors: p.totalErrs.Load(),
		RPS:         float64(p.totalReqs.Load()) / duration.Seconds(),
	}

	p.templates.Range(func(key, val any) bool {
		snap.Templates = append(snap.Templates, val.(*TemplateStats))
		return true
	})

	p.hosts.Range(func(key, val any) bool {
		snap.Hosts = append(snap.Hosts, val.(*HostStats))
		return true
	})

	p.protocols.Range(func(key, val any) bool {
		snap.Protocols = append(snap.Protocols, val.(*ProtocolStats))
		return true
	})

	// Sort templates by total duration (slowest first)
	sort.Slice(snap.Templates, func(i, j int) bool {
		return snap.Templates[i].TotalDur.Load() > snap.Templates[j].TotalDur.Load()
	})

	// Sort hosts by total duration (slowest first)
	sort.Slice(snap.Hosts, func(i, j int) bool {
		return snap.Hosts[i].TotalDur.Load() > snap.Hosts[j].TotalDur.Load()
	})

	return snap
}

// Snapshot is a point-in-time view of all profiler metrics
type Snapshot struct {
	Timestamp   time.Time       `json:"timestamp"`
	Duration    string          `json:"duration"`
	TotalReqs   uint64          `json:"total_requests"`
	TotalMatch  uint64          `json:"total_matched"`
	TotalErrors uint64          `json:"total_errors"`
	RPS         float64         `json:"rps"`
	Templates   []*TemplateStats `json:"templates"`
	Hosts       []*HostStats     `json:"hosts"`
	Protocols   []*ProtocolStats `json:"protocols"`
}

// WriteReport writes the full profiler report to a JSON file
func (p *Profiler) WriteReport(path string) error {
	snap := p.GetSnapshot()
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// AutoTuneRecommendation calculates recommended concurrency/rate-limit adjustments
type AutoTuneRecommendation struct {
	CurrentRPS      float64 `json:"current_rps"`
	CurrentErrors   uint64  `json:"current_errors"`
	ErrorPercent    float64 `json:"error_percent"`
	Action          string  `json:"action"` // "increase", "decrease", "maintain"
	SuggestedRL     int     `json:"suggested_rate_limit"`
	SuggestedConc   int     `json:"suggested_concurrency"`
	Reason          string  `json:"reason"`
}

// GetAutoTuneRecommendation analyzes current metrics and returns tuning advice
func (p *Profiler) GetAutoTuneRecommendation(currentRL, currentConc int) AutoTuneRecommendation {
	snap := p.GetSnapshot()
	rec := AutoTuneRecommendation{
		CurrentRPS:    snap.RPS,
		CurrentErrors: snap.TotalErrors,
	}

	if snap.TotalReqs > 0 {
		rec.ErrorPercent = (float64(snap.TotalErrors) / float64(snap.TotalReqs)) * 100
	}

	switch {
	case rec.ErrorPercent > p.config.AutoTuneMaxErrors:
		rec.Action = "decrease"
		rec.SuggestedRL = max(currentRL/2, 10)
		rec.SuggestedConc = max(currentConc/2, 5)
		rec.Reason = fmt.Sprintf("error rate %.1f%% exceeds threshold %.1f%%", rec.ErrorPercent, p.config.AutoTuneMaxErrors)
	case snap.RPS < p.config.AutoTuneMinRPS && rec.ErrorPercent < 5:
		rec.Action = "increase"
		rec.SuggestedRL = currentRL + (currentRL / 4)
		rec.SuggestedConc = currentConc + (currentConc / 4)
		rec.Reason = fmt.Sprintf("RPS %.1f below threshold %.1f with low error rate", snap.RPS, p.config.AutoTuneMinRPS)
	default:
		rec.Action = "maintain"
		rec.SuggestedRL = currentRL
		rec.SuggestedConc = currentConc
		rec.Reason = "metrics within acceptable bounds"
	}

	return rec
}

// --- HTTP Handlers ---

func (p *Profiler) handleMetricsJSON(w http.ResponseWriter, _ *http.Request) {
	snap := p.GetSnapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

func (p *Profiler) handleMetricsPrometheus(w http.ResponseWriter, _ *http.Request) {
	snap := p.GetSnapshot()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	fmt.Fprintf(w, "# HELP nuclei_total_requests Total requests sent\n")
	fmt.Fprintf(w, "# TYPE nuclei_total_requests counter\n")
	fmt.Fprintf(w, "nuclei_total_requests %d\n", snap.TotalReqs)

	fmt.Fprintf(w, "# HELP nuclei_total_matched Total matches found\n")
	fmt.Fprintf(w, "# TYPE nuclei_total_matched counter\n")
	fmt.Fprintf(w, "nuclei_total_matched %d\n", snap.TotalMatch)

	fmt.Fprintf(w, "# HELP nuclei_total_errors Total errors encountered\n")
	fmt.Fprintf(w, "# TYPE nuclei_total_errors counter\n")
	fmt.Fprintf(w, "nuclei_total_errors %d\n", snap.TotalErrors)

	fmt.Fprintf(w, "# HELP nuclei_rps Current requests per second\n")
	fmt.Fprintf(w, "# TYPE nuclei_rps gauge\n")
	fmt.Fprintf(w, "nuclei_rps %.2f\n", snap.RPS)

	for _, t := range snap.Templates {
		count := t.Count.Load()
		dur := t.TotalDur.Load()
		fmt.Fprintf(w, "nuclei_template_executions{template=%q,protocol=%q} %d\n", t.ID, t.Protocol, count)
		fmt.Fprintf(w, "nuclei_template_duration_ms{template=%q,protocol=%q} %.2f\n", t.ID, t.Protocol, float64(dur)/1e6)
	}

	for _, proto := range snap.Protocols {
		count := proto.Count.Load()
		dur := proto.TotalDur.Load()
		fmt.Fprintf(w, "nuclei_protocol_executions{protocol=%q} %d\n", proto.Protocol, count)
		fmt.Fprintf(w, "nuclei_protocol_duration_ms{protocol=%q} %.2f\n", proto.Protocol, float64(dur)/1e6)
	}
}

func (p *Profiler) handleTemplateProfile(w http.ResponseWriter, _ *http.Request) {
	snap := p.GetSnapshot()
	w.Header().Set("Content-Type", "application/json")

	top := snap.Templates
	if len(top) > 20 {
		top = top[:20]
	}
	_ = json.NewEncoder(w).Encode(top)
}

func (p *Profiler) handleHostProfile(w http.ResponseWriter, _ *http.Request) {
	snap := p.GetSnapshot()
	w.Header().Set("Content-Type", "application/json")

	top := snap.Hosts
	if len(top) > 20 {
		top = top[:20]
	}
	_ = json.NewEncoder(w).Encode(top)
}

func (p *Profiler) handleProtocolProfile(w http.ResponseWriter, _ *http.Request) {
	snap := p.GetSnapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap.Protocols)
}

func (p *Profiler) handleAutoTune(w http.ResponseWriter, _ *http.Request) {
	rec := p.GetAutoTuneRecommendation(150, 25)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rec)
}

// --- Helpers ---

// MemStats returns current Go runtime memory stats
func MemStats() runtime.MemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}
