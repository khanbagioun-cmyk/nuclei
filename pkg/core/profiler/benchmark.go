package profiler

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"
)

// PrintReport prints a human-readable profiler report to the given writer
func PrintReport(snap Snapshot) string {
	var buf string

	buf += fmt.Sprintf("\n═══ Nuclei Performance Report ═══\n")
	buf += fmt.Sprintf("Duration:    %s\n", snap.Duration)
	buf += fmt.Sprintf("Requests:    %d\n", snap.TotalReqs)
	buf += fmt.Sprintf("Matches:     %d\n", snap.TotalMatch)
	buf += fmt.Sprintf("Errors:      %d\n", snap.TotalErrors)
	buf += fmt.Sprintf("RPS:         %.2f\n\n", snap.RPS)

	// Protocol summary
	if len(snap.Protocols) > 0 {
		sort.Slice(snap.Protocols, func(i, j int) bool {
			return snap.Protocols[i].TotalDur.Load() > snap.Protocols[j].TotalDur.Load()
		})
		buf += "── Protocol Summary ──\n"
		w := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
		for _, p := range snap.Protocols {
			count := p.Count.Load()
			dur := p.TotalDur.Load()
			avg := 0.0
			if count > 0 {
				avg = float64(dur) / float64(count) / 1e6
			}
			fmt.Fprintf(w, "  %s\t%d execs\t%.2f ms avg\t%.2f ms total\n", p.Protocol, count, avg, float64(dur)/1e6)
		}
	}

	// Top 10 slowest templates
	if len(snap.Templates) > 0 {
		buf += "\n── Top 10 Slowest Templates ──\n"
		top := snap.Templates
		if len(top) > 10 {
			top = top[:10]
		}
		for i, t := range top {
			count := t.Count.Load()
			dur := t.TotalDur.Load()
			avg := 0.0
			if count > 0 {
				avg = float64(dur) / float64(count) / 1e6
			}
			buf += fmt.Sprintf("  %2d. %s (%s)\n", i+1, t.ID, t.Protocol)
			buf += fmt.Sprintf("      %d execs | %.2f ms avg | %.2f ms max | %d matches | %d errors\n",
				count, avg, float64(t.MaxDur.Load())/1e6, t.Matches.Load(), t.Errors.Load())
		}
	}

	// Top 10 slowest hosts
	if len(snap.Hosts) > 0 {
		buf += "\n── Top 10 Slowest Hosts ──\n"
		top := snap.Hosts
		if len(top) > 10 {
			top = top[:10]
		}
		for i, h := range top {
			count := h.Count.Load()
			dur := h.TotalDur.Load()
			avg := 0.0
			if count > 0 {
				avg = float64(dur) / float64(count) / 1e6
			}
			buf += fmt.Sprintf("  %2d. %s — %d execs | %.2f ms avg | %d matches | %d errors\n",
				i+1, h.Host, count, avg, h.Matches.Load(), h.Errors.Load())
		}
	}

	buf += "\n═══ End Report ═══\n"
	return buf
}

// BenchmarkConfig defines benchmark parameters
type BenchmarkConfig struct {
	TemplateSet    string        // name of template set
	TargetCount    int           // number of targets
	Iterations     int           // iterations to run
	WarmupTime     time.Duration // warmup before measurement
	OutputFile     string        // JSON output path
	CompareFile    string        // previous benchmark JSON to compare against
}

// BenchmarkResult captures a single benchmark run
type BenchmarkResult struct {
	TemplateSet  string  `json:"template_set"`
	TargetCount  int     `json:"target_count"`
	Iterations   int     `json:"iterations"`
	TotalReqs    uint64  `json:"total_requests"`
	TotalMatch   uint64  `json:"total_matched"`
	TotalErrors  uint64  `json:"total_errors"`
	Duration     string  `json:"duration"`
	RPS          float64 `json:"rps"`
	AvgLatencyMS float64 `json:"avg_latency_ms"`
	P95LatencyMS float64 `json:"p95_latency_ms"`
	P99LatencyMS float64 `json:"p99_latency_ms"`
	Timestamp    string  `json:"timestamp"`
}

// CompareResults compares two benchmark results
func CompareResults(prev, curr BenchmarkResult) string {
	var buf string
	buf += fmt.Sprintf("\n═══ Benchmark Comparison ═══\n")
	buf += fmt.Sprintf("Template Set: %s\n\n", curr.TemplateSet)

	rpsDelta := curr.RPS - prev.RPS
	rpsPct := 0.0
	if prev.RPS > 0 {
		rpsPct = (rpsDelta / prev.RPS) * 100
	}

	latencyDelta := curr.AvgLatencyMS - prev.AvgLatencyMS
	latencyPct := 0.0
	if prev.AvgLatencyMS > 0 {
		latencyPct = (latencyDelta / prev.AvgLatencyMS) * 100
	}

	rpsIcon := "↑"
	if rpsDelta < 0 {
		rpsIcon = "↓"
	}
	latIcon := "↑"
	if latencyDelta < 0 {
		latIcon = "↓"
	}

	buf += fmt.Sprintf("RPS:          %.2f → %.2f (%s%.2f, %.1f%%)\n", prev.RPS, curr.RPS, rpsIcon, rpsDelta, rpsPct)
	buf += fmt.Sprintf("Avg Latency:  %.2f ms → %.2f ms (%s%.2f ms, %.1f%%)\n", prev.AvgLatencyMS, curr.AvgLatencyMS, latIcon, latencyDelta, latencyPct)
	buf += fmt.Sprintf("Requests:     %d → %d\n", prev.TotalReqs, curr.TotalReqs)
	buf += fmt.Sprintf("Errors:       %d → %d\n", prev.TotalErrors, curr.TotalErrors)
	buf += "\n═══ End Comparison ═══\n"

	return buf
}

// WriteBenchmarkResult writes a benchmark result to JSON file
func WriteBenchmarkResult(result BenchmarkResult, path string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadBenchmarkResult reads a benchmark result from JSON file
func LoadBenchmarkResult(path string) (BenchmarkResult, error) {
	var result BenchmarkResult
	data, err := os.ReadFile(path)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result)
	return result, err
}
