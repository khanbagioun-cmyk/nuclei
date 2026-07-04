package intelligence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ThreatWatchConfig configures the real-time threat intel pipeline
type ThreatWatchConfig struct {
	NVDAPIKey         string
	VulnCheckAPIToken string
	TemplateOutputDir string
	ValidateBinary    string
	PollInterval      time.Duration
	MinCVSSScore      float64
	MinConfidence     float64
	StateFile         string
	EnableKEVOnly     bool
	MaxPerPoll        int
	TemplatesDir      string // for building local VKEV index fallback
}

// DefaultThreatWatchConfig returns sensible defaults
func DefaultThreatWatchConfig() ThreatWatchConfig {
	home, _ := os.UserHomeDir()
	return ThreatWatchConfig{
		TemplateOutputDir: filepath.Join(home, ".local", "nuclei-templates-dev", "cvesync"),
		ValidateBinary:    filepath.Join(home, "nuclei-fork", "bin", "nuclei-dev"),
		PollInterval:      15 * time.Minute,
		MinCVSSScore:      7.0,
		MinConfidence:     0.3,
		StateFile:         filepath.Join(home, ".config", "nuclei-dev", "threatwatch-state.json"),
		MaxPerPoll:        50,
		TemplatesDir:      filepath.Join(home, ".local", "nuclei-templates-dev"),
	}
}

// ThreatWatchState tracks what has been processed to avoid reprocessing
type ThreatWatchState struct {
	LastNVDPoll            time.Time         `json:"last_nvd_poll"`
	LastKEVPoll            time.Time         `json:"last_kev_poll"`
	LastVulnCheckKEVPoll   time.Time         `json:"last_vulncheck_kev_poll"`
	ProcessedCVEs          map[string]bool   `json:"processed_cves"`
	GeneratedCount         int               `json:"generated_count"`
	SkippedCount           int               `json:"skipped_count"`
	KEVCount               int               `json:"kev_count"`
	VulnCheckKEVCount      int               `json:"vulncheck_kev_count"`
	mu                     sync.Mutex
}

// LoadState loads threat watch state from disk
func LoadState(path string) (*ThreatWatchState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ThreatWatchState{
				ProcessedCVEs: make(map[string]bool),
			}, nil
		}
		return nil, err
	}
	var s ThreatWatchState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.ProcessedCVEs == nil {
		s.ProcessedCVEs = make(map[string]bool)
	}
	return &s, nil
}

// Save persists state to disk
func (s *ThreatWatchState) Save(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// IsProcessed returns true if a CVE has already been processed
func (s *ThreatWatchState) IsProcessed(cveID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ProcessedCVEs[cveID]
}

// MarkProcessed records a CVE as processed
func (s *ThreatWatchState) MarkProcessed(cveID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ProcessedCVEs[cveID] = true
}

// ThreatWatchEvent represents a new vulnerability detected by the pipeline
type ThreatWatchEvent struct {
	CVEID        string    `json:"cve_id"`
	Source       string    `json:"source"`
	Severity     string    `json:"severity"`
	CVSSScore    float64   `json:"cvss_score"`
	IsKEV        bool      `json:"is_kev"`
	IsVulnCheckKEV bool    `json:"is_vulncheck_kev"`
	KEVDate      string    `json:"kev_date,omitempty"`
	TemplatePath string    `json:"template_path,omitempty"`
	Confidence   float64   `json:"confidence"`
	Timestamp    time.Time `json:"timestamp"`
	Error        string    `json:"error,omitempty"`
}

// ThreatWatch is the main pipeline orchestrator
type ThreatWatch struct {
	config           ThreatWatchConfig
	state            *ThreatWatchState
	synthesizer      *Synthesizer
	writer           *TemplateWriter
	kevCatalog       *CISAKEVCatalog
	vulncheckCatalog *VulnCheckKEVCatalog
	localVKEVIndex   *LocalVKEVIndex
	stopChan         chan struct{}
	eventChan        chan ThreatWatchEvent
}

// NewThreatWatch creates a new threat watch pipeline
func NewThreatWatch(cfg ThreatWatchConfig) (*ThreatWatch, error) {
	state, err := LoadState(cfg.StateFile)
	if err != nil {
		return nil, fmt.Errorf("loading state: %w", err)
	}

	tw := &ThreatWatch{
		config:      cfg,
		state:       state,
		synthesizer: NewSynthesizer(),
		writer:      NewTemplateWriter(cfg.TemplateOutputDir),
		stopChan:    make(chan struct{}),
		eventChan:   make(chan ThreatWatchEvent, 100),
	}

	// Build local VKEV index from templates dir (works without API token)
	if cfg.TemplatesDir != "" {
		if _, err := os.Stat(cfg.TemplatesDir); err == nil {
			idx, err := BuildLocalVKEVIndex(cfg.TemplatesDir)
			if err == nil && idx.Count() > 0 {
				tw.localVKEVIndex = idx
			}
		}
	}

	return tw, nil
}

// Events returns a channel of threat watch events
func (tw *ThreatWatch) Events() <-chan ThreatWatchEvent {
	return tw.eventChan
}

// Stop shuts down the threat watch
func (tw *ThreatWatch) Stop() {
	close(tw.stopChan)
}

// PollOnce performs a single poll cycle (NVD recent + CISA KEV + VulnCheck KEV)
func (tw *ThreatWatch) PollOnce() ([]ThreatWatchEvent, error) {
	var events []ThreatWatchEvent

	nvdEvents, err := tw.pollNVD()
	if err != nil {
		return nil, fmt.Errorf("NVD poll: %w", err)
	}
	events = append(events, nvdEvents...)

	kevEvents, err := tw.pollKEV()
	if err != nil {
		return events, fmt.Errorf("KEV poll: %w", err)
	}
	events = append(events, kevEvents...)

	vkevEvents, err := tw.pollVulnCheckKEV()
	if err != nil {
		return events, fmt.Errorf("VulnCheck KEV poll: %w", err)
	}
	events = append(events, vkevEvents...)

	tw.state.LastNVDPoll = time.Now()
	_ = tw.state.Save(tw.config.StateFile)

	return events, nil
}

// pollNVD fetches recent CVEs from NVD and synthesizes templates
func (tw *ThreatWatch) pollNVD() ([]ThreatWatchEvent, error) {
	since := tw.state.LastNVDPoll
	if since.IsZero() {
		since = time.Now().Add(-24 * time.Hour)
	}

	cfg := CVEFeedConfig{
		APIKey:         tw.config.NVDAPIKey,
		ResultsPerPage: tw.config.MaxPerPoll,
		PubStartDate:   since.Format("2006-01-02T15:04:05.000"),
		PubEndDate:     time.Now().Format("2006-01-02T15:04:05.000"),
		HTTPTimeout:    30 * time.Second,
	}

	cves, err := FetchCVEs(cfg)
	if err != nil {
		return nil, err
	}

	var events []ThreatWatchEvent
	for i := range cves {
		cve := &cves[i]

		if tw.state.IsProcessed(cve.ID) {
			continue
		}

		if cve.GetCVSSScore() < tw.config.MinCVSSScore {
			tw.state.MarkProcessed(cve.ID)
			continue
		}

		event := tw.processCVE(cve, "nvd")
		events = append(events, event)

		if len(events) >= tw.config.MaxPerPoll {
			break
		}
	}

	return events, nil
}

// pollKEV fetches CISA KEV catalog and processes any new entries
func (tw *ThreatWatch) pollKEV() ([]ThreatWatchEvent, error) {
	catalog, err := FetchCISAKEV()
	if err != nil {
		return nil, err
	}
	tw.kevCatalog = catalog

	var since time.Time
	if !tw.state.LastKEVPoll.IsZero() {
		since = tw.state.LastKEVPoll
	} else {
		since = time.Now().Add(-7 * 24 * time.Hour)
	}

	recentKEV := catalog.GetRecentKEV(since)

	var events []ThreatWatchEvent
	for _, kevEntry := range recentKEV {
		if tw.state.IsProcessed(kevEntry.CVEID) {
			continue
		}

		if tw.config.EnableKEVOnly && !kevEntry.KnownToBeRansomwareCampaignUse {
			continue
		}

		cve, err := FetchSingleCVE(kevEntry.CVEID, tw.config.NVDAPIKey)
		if err != nil {
			events = append(events, ThreatWatchEvent{
				CVEID:     kevEntry.CVEID,
				Source:    "cisa-kev",
				IsKEV:     true,
				KEVDate:   kevEntry.DateAdded,
				Timestamp: time.Now(),
				Error:     fmt.Sprintf("fetching CVE: %v", err),
			})
			tw.state.MarkProcessed(kevEntry.CVEID)
			continue
		}

		event := tw.processCVE(cve, "cisa-kev")
		event.IsKEV = true
		event.KEVDate = kevEntry.DateAdded
		events = append(events, event)
	}

	tw.state.LastKEVPoll = time.Now()
	return events, nil
}

// pollVulnCheckKEV fetches the VulnCheck KEV catalog and processes new entries.
// If no API token is configured, falls back to the local VKEV index built
// from 1,795 community templates tagged "vkev".
func (tw *ThreatWatch) pollVulnCheckKEV() ([]ThreatWatchEvent, error) {
	token := tw.config.VulnCheckAPIToken
	if token == "" {
		// No API token — use local VKEV index if available
		if tw.localVKEVIndex == nil {
			return nil, nil
		}
		return tw.pollLocalVKEV()
	}

	catalog, err := FetchVulnCheckKEVWithToken(token)
	if err != nil {
		// API failed — fall back to local index if available
		if tw.localVKEVIndex != nil {
			return tw.pollLocalVKEV()
		}
		return nil, err
	}
	tw.vulncheckCatalog = catalog

	// Merge with local index for maximum coverage
	if tw.localVKEVIndex != nil {
		tw.localVKEVIndex.MergeWithAPI(catalog)
	}

	var since time.Time
	if !tw.state.LastVulnCheckKEVPoll.IsZero() {
		since = tw.state.LastVulnCheckKEVPoll
	} else {
		since = time.Now().Add(-7 * 24 * time.Hour)
	}

	recentVKEV := catalog.GetRecentVulnCheckKEV(since)

	var events []ThreatWatchEvent
	for i := range recentVKEV {
		entry := &recentVKEV[i]

		for _, cveID := range entry.CVE {
			if tw.state.IsProcessed(cveID) {
				continue
			}

			cve, err := FetchSingleCVE(cveID, tw.config.NVDAPIKey)
			if err != nil {
				events = append(events, ThreatWatchEvent{
					CVEID:          cveID,
					Source:         "vulncheck-kev",
					IsKEV:          entry.IsInCISAKEV(),
					IsVulnCheckKEV: true,
					KEVDate:        entry.DateAdded.Format("2006-01-02"),
					Timestamp:      time.Now(),
					Error:          fmt.Sprintf("fetching CVE: %v", err),
				})
				tw.state.MarkProcessed(cveID)
				continue
			}

			event := tw.processCVE(cve, "vulncheck-kev")
			event.IsVulnCheckKEV = true
			if entry.IsInCISAKEV() {
				event.IsKEV = true
			}
			events = append(events, event)
		}
	}

	tw.state.LastVulnCheckKEVPoll = time.Now()
	return events, nil
}

// pollLocalVKEV uses the locally-built VKEV index (no API token required)
func (tw *ThreatWatch) pollLocalVKEV() ([]ThreatWatchEvent, error) {
	cveIDs := tw.localVKEVIndex.GetCVEIDs()

	var events []ThreatWatchEvent
	for _, cveID := range cveIDs {
		if tw.state.IsProcessed(cveID) {
			continue
		}

		cve, err := FetchSingleCVE(cveID, tw.config.NVDAPIKey)
		if err != nil {
			// Can't fetch CVE details — record as known VKEV without template
			events = append(events, ThreatWatchEvent{
				CVEID:          cveID,
				Source:         "local-vkev",
				IsVulnCheckKEV: true,
				Timestamp:      time.Now(),
				Error:          fmt.Sprintf("fetching CVE: %v", err),
			})
			tw.state.MarkProcessed(cveID)
			continue
		}

		event := tw.processCVE(cve, "local-vkev")
		event.IsVulnCheckKEV = true
		events = append(events, event)

		if len(events) >= tw.config.MaxPerPoll {
			break
		}
	}

	tw.state.LastVulnCheckKEVPoll = time.Now()
	return events, nil
}

// processCVE synthesizes and writes a template for a single CVE
func (tw *ThreatWatch) processCVE(cve *NVDCVE, source string) ThreatWatchEvent {
	event := ThreatWatchEvent{
		CVEID:     cve.ID,
		Source:    source,
		Severity:  cve.GetSeverity(),
		CVSSScore: cve.GetCVSSScore(),
		IsKEV:     cve.IsCISAKEV(),
		Timestamp: time.Now(),
	}

	tmpl, err := tw.synthesizer.Synthesize(cve)
	if err != nil {
		event.Error = fmt.Sprintf("synthesize: %v", err)
		tw.state.SkippedCount++
		tw.state.MarkProcessed(cve.ID)
		return event
	}

	if tmpl.Confidence < tw.config.MinConfidence {
		event.Error = fmt.Sprintf("confidence %.2f below threshold %.2f", tmpl.Confidence, tw.config.MinConfidence)
		tw.state.SkippedCount++
		tw.state.MarkProcessed(cve.ID)
		return event
	}

	path, err := tw.writer.Write(tmpl)
	if err != nil {
		event.Error = fmt.Sprintf("write: %v", err)
		tw.state.SkippedCount++
		tw.state.MarkProcessed(cve.ID)
		return event
	}

	event.TemplatePath = path
	event.Confidence = tmpl.Confidence
	tw.state.GeneratedCount++
	if cve.IsCISAKEV() {
		tw.state.KEVCount++
	}
	if tw.vulncheckCatalog != nil {
		if _, found := tw.vulncheckCatalog.GetVulnCheckKEVByCVE(cve.ID); found {
			tw.state.VulnCheckKEVCount++
		}
	}
	tw.state.MarkProcessed(cve.ID)

	return event
}

// Run starts the polling loop. Blocks until Stop() is called.
func (tw *ThreatWatch) Run() {
	ticker := time.NewTicker(tw.config.PollInterval)
	defer ticker.Stop()

	// Initial poll immediately
	tw.runPollCycle()

	for {
		select {
		case <-ticker.C:
			tw.runPollCycle()
		case <-tw.stopChan:
			return
		}
	}
}

// runPollCycle performs one poll and emits events
func (tw *ThreatWatch) runPollCycle() {
	events, err := tw.PollOnce()
	if err != nil {
		event := ThreatWatchEvent{
			Timestamp: time.Now(),
			Error:     fmt.Sprintf("poll error: %v", err),
		}
		select {
		case tw.eventChan <- event:
		default:
		}
		return
	}

	for _, event := range events {
		select {
		case tw.eventChan <- event:
		case <-tw.stopChan:
			return
		}
	}
}

// GetStats returns current pipeline statistics
func (tw *ThreatWatch) GetStats() map[string]interface{} {
	tw.state.mu.Lock()
	defer tw.state.mu.Unlock()

	stats := map[string]interface{}{
		"last_nvd_poll":         tw.state.LastNVDPoll,
		"last_kev_poll":         tw.state.LastKEVPoll,
		"last_vulncheck_poll":   tw.state.LastVulnCheckKEVPoll,
		"processed_count":       len(tw.state.ProcessedCVEs),
		"generated_count":       tw.state.GeneratedCount,
		"skipped_count":         tw.state.SkippedCount,
		"kev_count":             tw.state.KEVCount,
		"vulncheck_kev_count":   tw.state.VulnCheckKEVCount,
	}

	if tw.kevCatalog != nil {
		stats["kev_catalog_version"] = tw.kevCatalog.CatalogVersion
		stats["kev_total"] = tw.kevCatalog.Count
	}

	if tw.vulncheckCatalog != nil {
		stats["vulncheck_kev_total"] = len(tw.vulncheckCatalog.Data)
	}

	if tw.localVKEVIndex != nil {
		stats["local_vkev_count"] = tw.localVKEVIndex.Count()
	}

	return stats
}
