package templatelearn

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// NucleiJSONLFinding represents a nuclei JSONL output line
type NucleiJSONLFinding struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
	Type          string                 `json:"type"`
	Host          string                 `json:"host"`
	URL           string                 `json:"matched-at"`
	MatcherName   string                 `json:"matcher-name"`
	ExtractedResults []string            `json:"extracted-results"`
	Metadata      map[string]interface{} `json:"meta"`
	Raw           string                 `json:"-"`
}

// FilterResult holds the result of filtering a finding
type FilterResult struct {
	Suppressed bool
	Reason     string
	Finding    *NucleiJSONLFinding
}

// FilterJSONL reads nuclei JSONL, filters out suppressed findings, writes to output.
// Uses a streaming pipeline with bounded buffering to handle large result sets
// without unbounded memory growth. The pipeline:
//
//	reader → scan goroutine → buffered channel → filter goroutine → writer
//
// The channel has a bounded capacity (default 1000 lines). If the filter
// goroutine is slower than the scanner (e.g., expensive suppression checks),
// the scanner blocks naturally, providing backpressure to the reader.
func FilterJSONL(store *FeedbackStore, reader io.Reader, writer io.Writer) (int, int, error) {
	return FilterJSONLWithBuffer(store, reader, writer, defaultFilterBufferSize)
}

// defaultFilterBufferSize is the bounded channel capacity for streaming.
const defaultFilterBufferSize = 1000

// FilterJSONLWithBuffer is like FilterJSONL but with a custom buffer size.
// A buffer size of 0 makes the channel unbuffered (strict backpressure).
func FilterJSONLWithBuffer(store *FeedbackStore, reader io.Reader, writer io.Writer, bufferSize int) (int, int, error) {
	if bufferSize < 0 {
		bufferSize = 0
	}

	type scanResult struct {
		line   string
		err    error
	}

	lines := make(chan scanResult, bufferSize)
	done := make(chan struct{})

	// Scanner goroutine: reads from io.Reader, sends lines to channel
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024*10)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			select {
			case lines <- scanResult{line: line}:
			case <-done:
				return
			}
		}
		if err := scanner.Err(); err != nil {
			select {
			case lines <- scanResult{err: err}:
			case <-done:
			}
		}
	}()

	// Writer goroutine: receives filtered lines, writes to output
	type outResult struct {
		total     int
		suppressed int
		err       error
	}
	outCh := make(chan outResult, 1)

	go func() {
		bw := bufio.NewWriterSize(writer, 64*1024)

		total := 0
		suppressed := 0

		for sr := range lines {
			if sr.err != nil {
				bw.Flush()
				outCh <- outResult{total: total, suppressed: suppressed, err: sr.err}
				return
			}
			total++

			var finding NucleiJSONLFinding
			if err := json.Unmarshal([]byte(sr.line), &finding); err != nil {
				bw.WriteString(sr.line)
				bw.WriteByte('\n')
				continue
			}

			vulnType := inferVulnTypeFromTags(finding.Info.Tags, finding.TemplateID, finding.MatcherName)
			suppressedFlag, _ := store.ShouldSuppress(finding.TemplateID, finding.Host, finding.MatcherName, vulnType)
			if suppressedFlag {
				suppressed++
				continue
			}

			bw.WriteString(sr.line)
			bw.WriteByte('\n')
		}

		bw.Flush()
		outCh <- outResult{total: total, suppressed: suppressed}
	}()

	result := <-outCh
	close(done)
	return result.total, result.suppressed, result.err
}

// FilterResultJSONL reads nuclei JSONL and returns filter results (for reporting)
func FilterResultJSONL(store *FeedbackStore, reader io.Reader) ([]FilterResult, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024*10)

	var results []FilterResult

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var finding NucleiJSONLFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue
		}
		finding.Raw = line

		vulnType := inferVulnTypeFromTags(finding.Info.Tags, finding.TemplateID, finding.MatcherName)
		suppressed, reason := store.ShouldSuppress(finding.TemplateID, finding.Host, finding.MatcherName, vulnType)

		results = append(results, FilterResult{
			Suppressed: suppressed,
			Reason:     reason,
			Finding:    &finding,
		})
	}

	return results, scanner.Err()
}

// inferVulnTypeFromTags determines the vulnerability type
func inferVulnTypeFromTags(tags []string, templateID string, matcherName string) string {
	knownTypes := []string{
		"sqli", "xss", "ssrf", "lfi", "rce", "redirect", "xxe", "csrf",
		"auth-bypass", "default-login", "exposure", "config", "misconfig",
		"debug", "backup", "source-code", "git", "token", "api-key",
		"takeover", "subdomain", "cve", "panel", "admin",
	}

	tagSet := make(map[string]bool)
	for _, t := range tags {
		tagSet[strings.ToLower(t)] = true
	}
	for _, t := range knownTypes {
		if tagSet[t] {
			return t
		}
	}

	tid := strings.ToLower(templateID)
	for _, t := range knownTypes {
		if strings.Contains(tid, t) {
			return t
		}
	}

	if len(tags) > 0 {
		return tags[0]
	}
	return "unknown"
}

// FNDetector checks for false negatives by comparing expected vs actual findings
type FNDetector struct {
	store *FeedbackStore
}

// NewFNDetector creates a new false-negative detector
func NewFNDetector(store *FeedbackStore) *FNDetector {
	return &FNDetector{store: store}
}

// FNResult holds a false-negative detection result
type FNResult struct {
	TemplateID  string    `json:"template_id"`
	Host        string    `json:"host"`
	VulnType    string    `json:"vuln_type"`
	Reason      string    `json:"reason"`
	Confidence  float64   `json:"confidence"`
	Timestamp   time.Time `json:"timestamp"`
}

// TechStackIndex maps a host to the set of technologies detected on it.
// Used by FNDetector to avoid flagging false negatives when hosts run
// different software stacks.
type TechStackIndex struct {
	hostTech map[string]map[string]bool // host → set of tech tags
}

// NewTechStackIndex creates an index from nuclei findings. Findings with
// "tech" or "fingerprint" tags provide the technology profile per host.
// Only the matcher name (e.g., "nginx", "apache") is recorded as a tech
// tag — the template ID itself is NOT included to avoid false overlaps
// (e.g., both hosts having the same "tech-detect" template doesn't mean
// they share the same software).
func NewTechStackIndex(findings []*NucleiJSONLFinding) *TechStackIndex {
	idx := &TechStackIndex{hostTech: make(map[string]map[string]bool)}
	// Known generic tech-tag values that should NOT be treated as tech identifiers
	genericTags := map[string]bool{
		"tech": true, "fingerprint": true, "detect": true,
		"http": true, "network": true, "dns": true,
	}
	for _, f := range findings {
		host := strings.ToLower(f.Host)
		if idx.hostTech[host] == nil {
			idx.hostTech[host] = make(map[string]bool)
		}
		hasTechTag := false
		for _, tag := range f.Info.Tags {
			if tl := strings.ToLower(tag); tl == "tech" || tl == "fingerprint" {
				hasTechTag = true
				break
			}
		}
		// For tech/fingerprint findings, record the matcher name as the tech
		if hasTechTag && f.MatcherName != "" {
			idx.hostTech[host][strings.ToLower(f.MatcherName)] = true
		}
		// Also record non-generic tags as potential tech indicators
		// (e.g., a template tagged "nginx" directly)
		for _, tag := range f.Info.Tags {
			tl := strings.ToLower(tag)
			if !genericTags[tl] && tl != "" {
				idx.hostTech[host][tl] = true
			}
		}
	}
	return idx
}

// SharesTechStack returns true if both hosts have overlapping technology tags.
// If either host has no recorded tech profile, returns true (conservative:
// assume same stack since we can't prove otherwise).
func (idx *TechStackIndex) SharesTechStack(hostA, hostB string) bool {
	a := idx.hostTech[strings.ToLower(hostA)]
	b := idx.hostTech[strings.ToLower(hostB)]
	if len(a) == 0 || len(b) == 0 {
		return true // unknown = assume compatible
	}
	for tech := range a {
		if b[tech] {
			return true
		}
	}
	return false
}

// ComputeFNConfidence calculates a dynamic confidence score for a potential
// false negative based on multiple signals:
//   - Tech stack overlap between the TP host and the missed host (0.0–0.35)
//   - Number of TP confirmations for the template (0.0–0.25, more = higher)
//   - Whether the template is CVE-specific (CVE templates are more portable) (0.0–0.2)
//   - Severity of the vuln (critical/high = higher) (0.0–0.2)
func ComputeFNConfidence(fb *Feedback, tpCount int, sameTechStack bool) float64 {
	var conf float64

	// Tech stack signal
	if sameTechStack {
		conf += 0.35
	} else {
		conf += 0.05 // different stacks = unlikely same vuln
	}

	// TP count signal: more confirmations = more likely the template is reliable
	switch {
	case tpCount >= 5:
		conf += 0.25
	case tpCount >= 3:
		conf += 0.20
	case tpCount >= 2:
		conf += 0.15
	default:
		conf += 0.10
	}

	// CVE-specific templates are more portable (version-based, apply across hosts)
	if strings.Contains(strings.ToLower(fb.TemplateID), "cve") {
		conf += 0.20
	}

	// Severity signal
	switch strings.ToLower(fb.VulnType) {
	case "rce", "sqli", "ssrf", "lfi", "xxe", "auth-bypass":
		conf += 0.20
	case "xss", "redirect", "csrf", "default-login":
		conf += 0.15
	default:
		conf += 0.10
	}

	if conf > 1.0 {
		conf = 1.0
	}
	return conf
}

// CheckFalseNegatives compares scanned hosts against known TP feedback
// to find hosts that should have had a finding but didn't.
// Uses TechStackIndex to avoid flagging FNs across incompatible stacks,
// and computes dynamic confidence via ComputeFNConfidence.
func (d *FNDetector) CheckFalseNegatives(scannedHosts []string, actualFindings []*NucleiJSONLFinding) []FNResult {
	var results []FNResult

	// Build actual findings map: templateID+host → found
	actualMap := make(map[string]bool)
	for _, f := range actualFindings {
		key := fmt.Sprintf("%s|%s", strings.ToLower(f.TemplateID), strings.ToLower(f.Host))
		actualMap[key] = true
	}

	// Build tech stack index from findings
	techIdx := NewTechStackIndex(actualFindings)

	// Count TP confirmations per template
	tpCountPerTemplate := make(map[string]int)
	for _, fb := range d.store.GetAllFeedback() {
		if fb.Type == FeedbackTruePositive {
			tpCountPerTemplate[fb.TemplateID] += fb.Count
		}
	}

	// Check all TP feedback entries
	for _, fb := range d.store.GetAllFeedback() {
		if fb.Type != FeedbackTruePositive {
			continue
		}
		for _, host := range scannedHosts {
			if strings.EqualFold(fb.Host, host) {
				continue // same host where TP was found
			}
			key := fmt.Sprintf("%s|%s", strings.ToLower(fb.TemplateID), strings.ToLower(host))
			if actualMap[key] {
				continue // found on this host too, not a FN
			}

			sameStack := techIdx.SharesTechStack(fb.Host, host)
			confidence := ComputeFNConfidence(fb, tpCountPerTemplate[fb.TemplateID], sameStack)

			reason := fmt.Sprintf("Template %s found %s on %s but not on %s (possible FN",
				fb.TemplateID, fb.VulnType, fb.Host, host)
			if sameStack {
				reason += ", same tech stack"
			} else {
				reason += ", different tech stack"
			}
			reason += ")"

			results = append(results, FNResult{
				TemplateID: fb.TemplateID,
				Host:       host,
				VulnType:   fb.VulnType,
				Reason:     reason,
				Confidence: confidence,
				Timestamp:  time.Now(),
			})
		}
	}

	return results
}

// LearningReport generates a summary of what the system has learned
type LearningReport struct {
	Stats             FeedbackStats      `json:"stats"`
	TopFPTemplates    []TemplateFP       `json:"top_fp_templates"`
	SuppressionRules  []*SuppressionRule `json:"suppression_rules"`
	GeneratedAt       time.Time          `json:"generated_at"`
}

// TemplateFP holds FP stats per template
type TemplateFP struct {
	TemplateID string `json:"template_id"`
	FPCount    int    `json:"fp_count"`
	TPCount    int    `json:"tp_count"`
	FPRate     float64 `json:"fp_rate"`
}

// GenerateReport creates a learning report
func (s *FeedbackStore) GenerateReport() LearningReport {
	stats := s.Stats()

	// Aggregate FP/TP counts per template
	templateStats := make(map[string]*TemplateFP)
	for _, fb := range s.GetAllFeedback() {
		if _, ok := templateStats[fb.TemplateID]; !ok {
			templateStats[fb.TemplateID] = &TemplateFP{TemplateID: fb.TemplateID}
		}
		ts := templateStats[fb.TemplateID]
		switch fb.Type {
		case FeedbackFalsePositive:
			ts.FPCount += fb.Count
		case FeedbackTruePositive:
			ts.TPCount += fb.Count
		}
	}

	var topFPs []TemplateFP
	for _, ts := range templateStats {
		total := ts.FPCount + ts.TPCount
		if total > 0 {
			ts.FPRate = float64(ts.FPCount) / float64(total)
		}
		topFPs = append(topFPs, *ts)
	}

	// Sort by FP count descending
	for i := 0; i < len(topFPs); i++ {
		for j := i + 1; j < len(topFPs); j++ {
			if topFPs[j].FPCount > topFPs[i].FPCount {
				topFPs[i], topFPs[j] = topFPs[j], topFPs[i]
			}
		}
	}

	suppressions := s.GetAllSuppressions()

	return LearningReport{
		Stats:           stats,
		TopFPTemplates:  topFPs,
		SuppressionRules: suppressions,
		GeneratedAt:     time.Now(),
	}
}
