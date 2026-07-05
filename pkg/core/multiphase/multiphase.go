package multiphase

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	lib "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// PhaseResult holds findings from a single phase.
type PhaseResult struct {
	Name     string
	Findings []*output.ResultEvent
	Duration time.Duration
	Error    error
}

// MultiPhaseEngine runs nuclei in-process with shared connection pools
// across multiple phases, eliminating the 4x startup tax of shell-out CLIs.
type MultiPhaseEngine struct {
	engine *lib.ThreadSafeNucleiEngine
	ctx    context.Context

	results     []*output.ResultEvent
	resultsMu   sync.Mutex
	techProfile *TechProfile

	templateDir string
	severity    string
	noInteractsh bool
	headless    bool
	dast        bool
}

// Config configures the multi-phase engine.
type Config struct {
	TemplateDir  string
	Severity     string // e.g. "critical,high,medium"
	NoInteractsh bool
	Headless     bool
	DAST         bool
	RateLimit    int
	Concurrency  int
}

// New creates a multi-phase engine with shared connection pools.
func New(ctx context.Context, cfg Config) (*MultiPhaseEngine, error) {
	opts := []lib.NucleiSDKOptions{
		lib.WithTemplatesOrWorkflows(lib.TemplateSources{
			Templates: []string{cfg.TemplateDir},
		}),
	}

	if cfg.Severity != "" {
		opts = append(opts, lib.WithTemplateFilters(lib.TemplateFilters{
			Severity: cfg.Severity,
		}))
	}

	if cfg.RateLimit > 0 {
		opts = append(opts, lib.WithGlobalRateLimit(cfg.RateLimit, time.Second))
	}

	if cfg.Concurrency > 0 {
		opts = append(opts, lib.WithConcurrency(lib.Concurrency{
			TemplateConcurrency: cfg.Concurrency,
			HostConcurrency:     cfg.Concurrency,
		}))
	}

	engine, err := lib.NewThreadSafeNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create engine: %w", err)
	}

	mpe := &MultiPhaseEngine{
		engine:      engine,
		ctx:         ctx,
		techProfile: NewTechProfile(),
		templateDir: cfg.TemplateDir,
		severity:    cfg.Severity,
		noInteractsh: cfg.NoInteractsh,
		headless:    cfg.Headless,
		dast:        cfg.DAST,
	}

	engine.GlobalResultCallback(func(event *output.ResultEvent) {
		mpe.resultsMu.Lock()
		mpe.results = append(mpe.results, event)
		mpe.resultsMu.Unlock()

		// Build tech profile from tech-detect / fingerprint findings
		if event.Info.Tags.ToSlice() != nil && len(event.Info.Tags.ToSlice()) > 0 {
			tags := event.Info.Tags.ToSlice()
			for _, tag := range tags {
				if IsTechTag(tag) {
					mpe.techProfile.Add(tag)
				}
			}
		}
	})
	// Use AddResultCallback for any additional callbacks (not replacing the one above)

	return mpe, nil
}

// Close releases all resources.
func (m *MultiPhaseEngine) Close() {
	if m.engine != nil {
		m.engine.Close()
	}
}

// Results returns all findings collected across all phases.
func (m *MultiPhaseEngine) Results() []*output.ResultEvent {
	m.resultsMu.Lock()
	defer m.resultsMu.Unlock()
	return m.results
}

// TechProfile returns the detected technology profile.
func (m *MultiPhaseEngine) TechProfile() *TechProfile {
	return m.techProfile
}

// RunPhase1TechDetect runs tech-detection templates to build a technology profile.
func (m *MultiPhaseEngine) RunPhase1TechDetect(ctx context.Context, targets []string) PhaseResult {
	start := time.Now()
	result := PhaseResult{Name: "phase1-techdetect", Findings: []*output.ResultEvent{}}

	before := len(m.Results())

	err := m.engine.ExecuteNucleiWithOptsCtx(ctx, targets,
		lib.WithTemplateFilters(lib.TemplateFilters{
			Tags: []string{"tech", "fingerprint", "detect"},
		}),
	)
	if err != nil {
		result.Error = fmt.Errorf("phase 1: %w", err)
	}

	result.Findings = m.Results()[before:]
	result.Duration = time.Since(start)
	return result
}

// RunPhase2VulnScan runs vulnerability templates filtered by detected tech.
func (m *MultiPhaseEngine) RunPhase2VulnScan(ctx context.Context, targets []string) PhaseResult {
	start := time.Now()
	result := PhaseResult{Name: "phase2-vulnscan", Findings: []*output.ResultEvent{}}

	before := len(m.Results())

	// Build tag filter from detected tech + always-include priority tags
	tags := m.buildPhase2Tags()
	filters := lib.TemplateFilters{}
	if len(tags) > 0 {
		filters.Tags = tags
	}
	if m.severity != "" {
		filters.Severity = m.severity
	}

	err := m.engine.ExecuteNucleiWithOptsCtx(ctx, targets,
		lib.WithTemplateFilters(filters),
	)
	if err != nil {
		result.Error = fmt.Errorf("phase 2: %w", err)
	}

	result.Findings = m.Results()[before:]
	result.Duration = time.Since(start)
	return result
}

// RunPhase3Workflows runs native workflows matching detected tech.
func (m *MultiPhaseEngine) RunPhase3Workflows(ctx context.Context, targets []string) PhaseResult {
	start := time.Now()
	result := PhaseResult{Name: "phase3-workflows", Findings: []*output.ResultEvent{}}

	before := len(m.Results())

	// Run all workflows — they have internal conditional logic
	err := m.engine.ExecuteNucleiWithOptsCtx(ctx, targets,
		lib.WithTemplatesOrWorkflows(lib.TemplateSources{
			Workflows: []string{m.templateDir + "/workflows/"},
		}),
	)
	if err != nil {
		result.Error = fmt.Errorf("phase 3: %w", err)
	}

	result.Findings = m.Results()[before:]
	result.Duration = time.Since(start)
	return result
}

// RunPhase4DAST runs DAST templates if enabled.
func (m *MultiPhaseEngine) RunPhase4DAST(ctx context.Context, targets []string) PhaseResult {
	start := time.Now()
	result := PhaseResult{Name: "phase4-dast", Findings: []*output.ResultEvent{}}

	if !m.dast {
		result.Duration = time.Since(start)
		return result
	}

	before := len(m.Results())

	dastPaths := []string{
		m.templateDir + "/dast/",
		m.templateDir + "/http/dast/",
	}
	err := m.engine.ExecuteNucleiWithOptsCtx(ctx, targets,
		lib.WithTemplatesOrWorkflows(lib.TemplateSources{
			Templates: dastPaths,
		}),
	)
	if err != nil {
		result.Error = fmt.Errorf("phase 4: %w", err)
	}

	result.Findings = m.Results()[before:]
	result.Duration = time.Since(start)
	return result
}

// buildPhase2Tags returns tags for phase 2 filtering based on detected tech + priority tags.
func (m *MultiPhaseEngine) buildPhase2Tags() []string {
	techTags := m.techProfile.All()

	// Always include priority tags (KEV, exploit, CVE)
	priorityTags := []string{"kev", "vkev", "exploit", "cve"}

	all := make([]string, 0, len(techTags)+len(priorityTags))
	all = append(all, techTags...)
	all = append(all, priorityTags...)

	return all
}

// RunAll executes all phases sequentially and returns combined results.
func (m *MultiPhaseEngine) RunAll(ctx context.Context, targets []string) ([]PhaseResult, error) {
	var phases []PhaseResult

	p1 := m.RunPhase1TechDetect(ctx, targets)
	phases = append(phases, p1)

	p2 := m.RunPhase2VulnScan(ctx, targets)
	phases = append(phases, p2)

	if m.dast {
		p4 := m.RunPhase4DAST(ctx, targets)
		phases = append(phases, p4)
	}

	p3 := m.RunPhase3Workflows(ctx, targets)
	phases = append(phases, p3)

	return phases, nil
}

// Summary returns a human-readable summary of all phases.
func (m *MultiPhaseEngine) Summary(phases []PhaseResult) string {
	var sb strings.Builder
	totalFindings := len(m.Results())
	sb.WriteString(fmt.Sprintf("Multi-phase scan complete: %d total findings\n", totalFindings))
	for _, p := range phases {
		status := "ok"
		if p.Error != nil {
			status = p.Error.Error()
		}
		sb.WriteString(fmt.Sprintf("  %s: %d findings in %s (%s)\n",
			p.Name, len(p.Findings), p.Duration.Round(time.Millisecond), status))
	}
	techs := m.techProfile.All()
	if len(techs) > 0 {
		sb.WriteString(fmt.Sprintf("  Detected tech: %s\n", strings.Join(techs, ", ")))
	}
	return sb.String()
}

// Options returns the underlying engine options for advanced configuration.
func (m *MultiPhaseEngine) Options() *types.Options {
	return nil // thread-safe engine doesn't expose Options directly
}
