// Package orchestrator provides a high-level scanning orchestrator
// that wraps the nuclei SDK with multi-stage scanning pipelines,
// profiling, and integration with custom utilities (banner grab,
// WAF evasion, webhook export).
//
// It is designed for embedding nuclei as a library in security
// automation platforms, CI/CD pipelines, and continuous scanning
// workflows.
package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/banner"
)

// ScanStage represents a phase in a multi-stage scan.
type ScanStage int

const (
	StageRecon ScanStage = iota
	StageBannerGrab
	StageVulnScan
	StageDeepScan
)

// StageName returns a human-readable name for a scan stage.
func (s ScanStage) StageName() string {
	switch s {
	case StageRecon:
		return "recon"
	case StageBannerGrab:
		return "banner-grab"
	case StageVulnScan:
		return "vulnerability-scan"
	case StageDeepScan:
		return "deep-scan"
	default:
		return "unknown"
	}
}

// ScanConfig defines the configuration for a scan orchestrated by the Orchestrator.
type ScanConfig struct {
	// Targets is the list of URLs, IPs, or hostnames to scan
	Targets []string
	// TemplateFilters filters which templates to run
	TemplateFilters nuclei.TemplateFilters
	// TemplateSources specifies custom template paths
	TemplateSources nuclei.TemplateSources
	// Stages defines which stages to run (default: all)
	Stages []ScanStage
	// RateLimit is requests per second (default: 150)
	RateLimit int
	// Concurrency is the number of concurrent templates (default: 25)
	Concurrency int
	// Timeout is the overall scan timeout (default: 30m)
	Timeout time.Duration
	// ProbeNonHttp enables httpx probing for non-HTTP targets
	ProbeNonHttp bool
	// EnableStats enables the metrics server
	EnableStats bool
	// StatsPort is the metrics server port (default: 9092)
	StatsPort int
	// BannerGrabTimeout is the timeout for banner grabbing (default: 5s)
	BannerGrabTimeout time.Duration
	// BannerPorts is the list of ports to grab banners from
	BannerPorts []int
}

// ScanResult contains the results of an orchestrated scan.
type ScanResult struct {
	// Findings is the list of all vulnerability findings
	Findings []*output.ResultEvent
	// Banners is the list of grabbed banners
	Banners []*banner.Result
	// Duration is the total scan time
	Duration time.Duration
	// StageDurations maps stage names to their durations
	StageDurations map[string]time.Duration
	// Errors is a list of errors encountered during the scan
	Errors []error
	// TargetsScanned is the number of targets that were processed
	TargetsScanned int
}

// Orchestrator coordinates multi-stage nuclei scans.
type Orchestrator struct {
	config *ScanConfig
	mu     sync.Mutex
}

// New creates a new Orchestrator with the given config.
func New(config *ScanConfig) *Orchestrator {
	if config == nil {
		config = DefaultConfig()
	}
	return &Orchestrator{config: config}
}

// DefaultConfig returns a ScanConfig with sensible defaults.
func DefaultConfig() *ScanConfig {
	return &ScanConfig{
		Targets:           []string{},
		Stages:            []ScanStage{StageRecon, StageVulnScan},
		RateLimit:         150,
		Concurrency:       25,
		Timeout:           30 * time.Minute,
		ProbeNonHttp:      false,
		EnableStats:       false,
		StatsPort:         9092,
		BannerGrabTimeout: 5 * time.Second,
		BannerPorts:       []int{22, 21, 25, 80, 443, 3306, 6379, 8080, 8443},
	}
}

// Run executes the orchestrated scan and returns results.
func (o *Orchestrator) Run(ctx context.Context) (*ScanResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	startTime := time.Now()
	result := &ScanResult{
		StageDurations: make(map[string]time.Duration),
		Errors:         []error{},
	}

	// Apply timeout
	if o.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.config.Timeout)
		defer cancel()
	}

	// Determine stages to run
	stages := o.config.Stages
	if len(stages) == 0 {
		stages = []ScanStage{StageRecon, StageVulnScan}
	}

	for _, stage := range stages {
		stageStart := time.Now()

		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, ctx.Err())
			result.Duration = time.Since(startTime)
			return result, ctx.Err()
		default:
		}

		var err error
		switch stage {
		case StageBannerGrab:
			err = o.runBannerGrab(ctx, result)
		case StageRecon, StageVulnScan, StageDeepScan:
			err = o.runNucleiScan(ctx, result, stage)
		}

		result.StageDurations[stage.StageName()] = time.Since(stageStart)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("%s: %w", stage.StageName(), err))
			gologger.Warning().Msgf("stage %s failed: %v", stage.StageName(), err)
		}
	}

	result.Duration = time.Since(startTime)
	result.TargetsScanned = len(o.config.Targets)
	return result, nil
}

// runBannerGrab grabs banners from target ports.
func (o *Orchestrator) runBannerGrab(ctx context.Context, result *ScanResult) error {
	grabber := banner.Default()
	grabber.Timeout = o.config.BannerGrabTimeout

	var addresses []string
	for _, target := range o.config.Targets {
		for _, port := range o.config.BannerPorts {
			addresses = append(addresses, fmt.Sprintf("%s:%d", target, port))
		}
	}

	banners := grabber.GrabBatch(ctx, addresses, "")
	result.Banners = banners

	found := 0
	for _, b := range banners {
		if b.Banner != "" && b.Error == nil {
			found++
		}
	}
	gologger.Info().Msgf("banner grab: %d/%d services responded", found, len(addresses))
	return nil
}

// runNucleiScan runs a nuclei scan with the given stage configuration.
func (o *Orchestrator) runNucleiScan(ctx context.Context, result *ScanResult, stage ScanStage) error {
	// Build SDK options
	var sdkOpts []nuclei.NucleiSDKOptions

	// Template filters
	if o.config.TemplateFilters.Tags != nil || o.config.TemplateFilters.Severity != "" {
		sdkOpts = append(sdkOpts, nuclei.WithTemplateFilters(o.config.TemplateFilters))
	}

	// Template sources
	if len(o.config.TemplateSources.Templates) > 0 || len(o.config.TemplateSources.Workflows) > 0 {
		sdkOpts = append(sdkOpts, nuclei.WithTemplatesOrWorkflows(o.config.TemplateSources))
	}

	// Stats
	if o.config.EnableStats {
		sdkOpts = append(sdkOpts, nuclei.EnableStatsWithOpts(nuclei.StatsOptions{
			MetricServerPort: o.config.StatsPort,
		}))
	}

	// Rate limit
	if o.config.RateLimit > 0 {
		sdkOpts = append(sdkOpts, func(e *nuclei.NucleiEngine) error {
			e.Options().RateLimit = o.config.RateLimit
			e.Options().BulkSize = o.config.Concurrency
			e.Options().TemplateThreads = o.config.Concurrency
			return nil
		})
	}

	// Stage-specific filters
	switch stage {
	case StageRecon:
		sdkOpts = append(sdkOpts, func(e *nuclei.NucleiEngine) error {
			e.Options().Tags = append(e.Options().Tags, "recon", "discovery")
			return nil
		})
	case StageDeepScan:
		sdkOpts = append(sdkOpts, func(e *nuclei.NucleiEngine) error {
			e.Options().Tags = append(e.Options().Tags, "fuzz", "dast")
			return nil
		})
	}

	// Create engine
	ne, err := nuclei.NewNucleiEngineCtx(ctx, sdkOpts...)
	if err != nil {
		return fmt.Errorf("create engine: %w", err)
	}
	defer ne.Close()

	// Load targets
	ne.LoadTargets(o.config.Targets, o.config.ProbeNonHttp)

	// Set up result callback
	callback := func(event *output.ResultEvent) {
		result.Findings = append(result.Findings, event)
	}

	// Execute scan
	if err := ne.ExecuteCallbackWithCtx(ctx, callback); err != nil {
		return fmt.Errorf("execute scan: %w", err)
	}

	gologger.Info().Msgf("%s: %d findings", stage.StageName(), len(result.Findings))
	return nil
}

// Profile generates a performance profile of the scan.
// It returns timing data per stage and throughput metrics.
func (r *ScanResult) Profile() string {
	var profile string
	profile += fmt.Sprintf("Total Duration: %s\n", r.Duration)
	profile += fmt.Sprintf("Targets Scanned: %d\n", r.TargetsScanned)
	profile += fmt.Sprintf("Total Findings: %d\n", len(r.Findings))
	profile += fmt.Sprintf("Total Banners: %d\n", len(r.Banners))
	profile += fmt.Sprintf("Errors: %d\n", len(r.Errors))
	profile += "\nStage Breakdown:\n"
	for stage, duration := range r.StageDurations {
		profile += fmt.Sprintf("  %s: %s\n", stage, duration)
	}
	if r.Duration > 0 && r.TargetsScanned > 0 {
		throughput := float64(r.TargetsScanned) / r.Duration.Seconds()
		profile += fmt.Sprintf("\nThroughput: %.2f targets/sec\n", throughput)
	}
	return profile
}

// FindingsBySeverity groups findings by severity level.
func (r *ScanResult) FindingsBySeverity() map[string][]*output.ResultEvent {
	grouped := make(map[string][]*output.ResultEvent)
	for _, f := range r.Findings {
		sev := f.Info.SeverityHolder.Severity.String()
		grouped[sev] = append(grouped[sev], f)
	}
	return grouped
}

// FindingsByTemplate groups findings by template ID.
func (r *ScanResult) FindingsByTemplate() map[string][]*output.ResultEvent {
	grouped := make(map[string][]*output.ResultEvent)
	for _, f := range r.Findings {
		grouped[f.TemplateID] = append(grouped[f.TemplateID], f)
	}
	return grouped
}

// BannersByProtocol groups banners by detected protocol.
func (r *ScanResult) BannersByProtocol() map[string][]*banner.Result {
	grouped := make(map[string][]*banner.Result)
	for _, b := range r.Banners {
		grouped[b.Protocol] = append(grouped[b.Protocol], b)
	}
	return grouped
}

// Summary returns a concise text summary of the scan results.
func (r *ScanResult) Summary() string {
	bySev := r.FindingsBySeverity()
	byProto := r.BannersByProtocol()

	summary := fmt.Sprintf("Scan completed in %s\n", r.Duration)
	summary += fmt.Sprintf("Targets: %d | Findings: %d | Banners: %d | Errors: %d\n",
		r.TargetsScanned, len(r.Findings), len(r.Banners), len(r.Errors))

	if len(bySev) > 0 {
		summary += "\nFindings by Severity:\n"
		for sev, findings := range bySev {
			summary += fmt.Sprintf("  %s: %d\n", sev, len(findings))
		}
	}

	if len(byProto) > 0 {
		summary += "\nBanners by Protocol:\n"
		for proto, banners := range byProto {
			summary += fmt.Sprintf("  %s: %d\n", proto, len(banners))
		}
	}

	return summary
}

// Validate checks that the scan config is valid.
func (c *ScanConfig) Validate() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("no targets specified")
	}
	if c.RateLimit < 0 {
		return fmt.Errorf("rate limit cannot be negative")
	}
	if c.Concurrency < 0 {
		return fmt.Errorf("concurrency cannot be negative")
	}
	return nil
}

// SetTargets sets the scan targets.
func (c *ScanConfig) SetTargets(targets ...string) *ScanConfig {
	c.Targets = targets
	return c
}

// SetTemplateFilters sets the template filters.
func (c *ScanConfig) SetTemplateFilters(filters nuclei.TemplateFilters) *ScanConfig {
	c.TemplateFilters = filters
	return c
}

// SetStages sets which stages to run.
func (c *ScanConfig) SetStages(stages ...ScanStage) *ScanConfig {
	c.Stages = stages
	return c
}

// SetRateLimit sets the rate limit (requests per second).
func (c *ScanConfig) SetRateLimit(rps int) *ScanConfig {
	c.RateLimit = rps
	return c
}

// SetConcurrency sets the concurrency level.
func (c *ScanConfig) SetConcurrency(n int) *ScanConfig {
	c.Concurrency = n
	return c
}

// SetTimeout sets the overall scan timeout.
func (c *ScanConfig) SetTimeout(d time.Duration) *ScanConfig {
	c.Timeout = d
	return c
}
