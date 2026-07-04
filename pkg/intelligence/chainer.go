package intelligence

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Chainer orchestrates the two-phase smart scan:
// Phase 1: Run lightweight tech-detection templates → build TechProfile
// Phase 2: Filter vuln templates based on TechProfile → run only relevant ones
type Chainer struct {
	chainEngine  *ChainEngine
	profiler     *ResultProfiler
	profileStore *ProfileStore
	stats        ChainerStats
	mu           sync.Mutex
}

// ChainerStats holds statistics about the two-phase scan
type ChainerStats struct {
	Phase1Duration    time.Duration
	Phase2Duration    time.Duration
	TotalTemplates    int
	SelectedTemplates int
	SkippedTemplates  int
	ProfilesCreated   int
	TriggerTags       []string
	MatchedRules      int
	ReductionPercent  float64
}

// NewChainer creates a new Chainer
func NewChainer() *Chainer {
	store := NewProfileStore()
	return &Chainer{
		chainEngine:  NewChainEngine(nil),
		profiler:     NewResultProfiler(store),
		profileStore: store,
	}
}

// GetProfiler returns the result profiler (for processing *output.ResultEvent)
func (c *Chainer) GetProfiler() *ResultProfiler {
	return c.profiler
}

// FilterTemplatesForHost filters template tags based on the detected tech profile for a host
func (c *Chainer) FilterTemplatesForHost(host string, templateTagsList [][]string) ([]int, FilterStats) {
	profile := c.profileStore.Get(host)
	if profile == nil {
		allIndices := make([]int, len(templateTagsList))
		for i := range templateTagsList {
			allIndices[i] = i
		}
		return allIndices, FilterStats{
			TotalTemplates:    len(templateTagsList),
			SelectedTemplates: len(templateTagsList),
			SkippedTemplates:  0,
		}
	}

	selected, stats := c.chainEngine.FilterTemplates(templateTagsList, profile)
	return selected, stats
}

// GetTriggerTagsForHost returns the template tags that should be run for a host
func (c *Chainer) GetTriggerTagsForHost(host string) []string {
	profile := c.profileStore.Get(host)
	if profile == nil {
		return nil
	}
	return c.chainEngine.GetTriggerTags(profile)
}

// GetProfile returns the tech profile for a host
func (c *Chainer) GetProfile(host string) *TechProfile {
	return c.profileStore.Get(host)
}

// GetAllProfiles returns all detected tech profiles
func (c *Chainer) GetAllProfiles() []*TechProfile {
	return c.profileStore.All()
}

// HasProfile returns true if a profile exists for the host
func (c *Chainer) HasProfile(host string) bool {
	return c.profileStore.Get(host) != nil
}

// RecordPhase1Result records a phase 1 result for profiling.
// This is the lightweight method that doesn't require *output.ResultEvent.
// It directly builds the profile from raw fields.
func (c *Chainer) RecordPhase1Result(host string, templateTags []string, matcherName string,
	extractedResults []string, templateID string, port string, metadata map[string]interface{}) {

	if host == "" {
		return
	}

	profile := c.profileStore.GetOrCreate(host)

	// Process tags
	for _, tag := range templateTags {
		classifyTagDirect(profile, tag)
	}

	// Process matcher name
	if matcherName != "" {
		classifyMatcherDirect(profile, matcherName, extractedResults)
	}

	// Process template ID
	if templateID != "" {
		classifyTemplateIDDirect(profile, templateID)
	}

	// Process port
	if port != "" {
		classifyPortDirect(profile, port)
	}

	// Process metadata
	if metadata != nil {
		classifyMetadataDirect(profile, metadata)
	}
}

// FinalizePhase1 marks phase 1 as complete
func (c *Chainer) FinalizePhase1() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.ProfilesCreated = c.profileStore.Count()
}

// SetPhase1Stats records phase 1 timing
func (c *Chainer) SetPhase1Stats(duration time.Duration, profileCount int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Phase1Duration = duration
	c.stats.ProfilesCreated = profileCount
}

// SetPhase2Stats records phase 2 filtering stats
func (c *Chainer) SetPhase2Stats(duration time.Duration, total, selected int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Phase2Duration = duration
	c.stats.TotalTemplates = total
	c.stats.SelectedTemplates = selected
	c.stats.SkippedTemplates = total - selected
	if total > 0 {
		c.stats.ReductionPercent = float64(total-selected) / float64(total) * 100
	}

	tagSet := make(map[string]bool)
	for _, profile := range c.profileStore.All() {
		for _, tag := range c.chainEngine.GetTriggerTags(profile) {
			tagSet[tag] = true
		}
	}
	var tags []string
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	c.stats.TriggerTags = tags
	c.stats.MatchedRules = len(tagSet)
}

// GetStats returns the chainer statistics
func (c *Chainer) GetStats() ChainerStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// Summary returns a human-readable summary of the smart chain scan
func (c *Chainer) Summary() string {
	stats := c.GetStats()
	return fmt.Sprintf(
		"Smart Chain Summary:\n"+
			"  Phase 1 (profiling): %s — %d profiles created\n"+
			"  Phase 2 (scanning):  %s\n"+
			"  Templates: %d total → %d selected (%d skipped, %.1f%% reduction)\n"+
			"  Trigger tags: %v\n",
		stats.Phase1Duration, stats.ProfilesCreated,
		stats.Phase2Duration,
		stats.TotalTemplates, stats.SelectedTemplates, stats.SkippedTemplates, stats.ReductionPercent,
		stats.TriggerTags,
	)
}

// SmartScanConfig configures a two-phase smart scan
type SmartScanConfig struct {
	ProfileTimeout time.Duration
	ScanTimeout    time.Duration
	ProfileTags    []string
	AlwaysRunTags  []string
	MinReduction   float64
}

// DefaultSmartScanConfig returns sensible defaults
func DefaultSmartScanConfig() SmartScanConfig {
	return SmartScanConfig{
		ProfileTimeout: 30 * time.Second,
		ScanTimeout:    30 * time.Minute,
		ProfileTags:    []string{"tech-detect", "tech", "fingerprint"},
		AlwaysRunTags:  []string{"exposure", "misconfig", "config"},
		MinReduction:   20.0,
	}
}

// ShouldUseSmartScan decides if two-phase scanning is worthwhile
func ShouldUseSmartScan(stats FilterStats, minReduction float64) bool {
	if stats.TotalTemplates == 0 {
		return false
	}
	reduction := float64(stats.SkippedTemplates) / float64(stats.TotalTemplates) * 100
	return reduction >= minReduction
}

// Run executes the chainer in a blocking manner (for testing)
func (c *Chainer) Run(ctx context.Context, phase1Fn, phase2Fn func(context.Context) error) error {
	start := time.Now()
	if phase1Fn != nil {
		if err := phase1Fn(ctx); err != nil {
			return fmt.Errorf("phase 1 failed: %w", err)
		}
	}
	c.SetPhase1Stats(time.Since(start), c.profileStore.Count())
	c.FinalizePhase1()

	start = time.Now()
	if phase2Fn != nil {
		if err := phase2Fn(ctx); err != nil {
			return fmt.Errorf("phase 2 failed: %w", err)
		}
	}
	c.SetPhase2Stats(time.Since(start), 0, 0)

	return nil
}
