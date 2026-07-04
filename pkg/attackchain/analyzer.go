package attackchain

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// NucleiResult represents a nuclei JSONL output line
type NucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
	Type         string `json:"type"`
	Host         string `json:"host"`
	URL          string `json:"matched-at"`
	MatcherName  string `json:"matcher-name"`
	Port         string `json:"port"`
	ExtractedResults []string `json:"extracted-results"`
	Metadata     map[string]interface{} `json:"meta"`
	Raw          string `json:"-"`
}

// ParseJSONL reads nuclei JSONL output and returns findings
func ParseJSONL(reader io.Reader) ([]*Finding, error) {
	var findings []*Finding
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024*10) // 10MB buffer

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var nr NucleiResult
		if err := json.Unmarshal([]byte(line), &nr); err != nil {
			continue // skip invalid lines
		}
		nr.Raw = line

		finding := nucleiResultToFinding(&nr)
		findings = append(findings, finding)
	}

	if err := scanner.Err(); err != nil {
		return findings, err
	}
	return findings, nil
}

// ParseJSONLFile reads findings from a JSONL file
func ParseJSONLFile(path string) ([]*Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()
	return ParseJSONL(f)
}

// nucleiResultToFinding converts a nuclei JSON result to a Finding
func nucleiResultToFinding(nr *NucleiResult) *Finding {
	f := &Finding{
		TemplateID:    nr.TemplateID,
		Host:          nr.Host,
		URL:           nr.URL,
		Severity:      nr.Info.Severity,
		Tags:          nr.Info.Tags,
		MatcherName:   nr.MatcherName,
		ExtractedData: make(map[string]string),
		Metadata:      nr.Metadata,
		Port:          nr.Port,
		Raw:           nr.Raw,
	}

	if f.Severity == "" {
		f.Severity = SeverityInfo
	}
	if f.Host == "" && f.URL != "" {
		f.Host = extractHost(f.URL)
	}

	// Infer vuln type from tags
	f.VulnType = inferVulnType(f.Tags, f.TemplateID, f.MatcherName)

	// Process extracted results into key-value pairs
	if len(nr.ExtractedResults) > 0 {
		for i, val := range nr.ExtractedResults {
			key := fmt.Sprintf("extracted_%d", i)
			f.ExtractedData[key] = val
		}
	}

	// Generate stable ID
	f.ID = fmt.Sprintf("%s:%s:%s", f.TemplateID, f.Host, f.VulnType)
	if f.MatcherName != "" {
		f.ID = fmt.Sprintf("%s:%s:%s:%s", f.TemplateID, f.Host, f.VulnType, f.MatcherName)
	}

	return f
}

// inferVulnType determines the vulnerability type from tags, template ID, and matcher name
func inferVulnType(tags []string, templateID string, matcherName string) string {
	// Priority 1: Check tags for known vuln types
	knownTypes := []string{
		"sqli", "sql-injection", "xss", "cross-site-scripting",
		"ssrf", "lfi", "path-traversal", "rce", "code-execution",
		"command-injection", "redirect", "open-redirect",
		"xxe", "csrf", "ssrf", "auth-bypass", "default-login",
		"info-leak", "disclosure", "exposure", "config", "misconfig",
		"debug", "backup", "source-code", "git", "svn", "env",
		"token", "api-key", "secret", "jwt", "credential",
		"takeover", "subdomain", "dangling",
		"metadata", "cloud", "aws", "iam",
		"version", "fingerprint", "tech-detect", "tech",
		"panel", "admin", "dashboard", "console",
		"listing", "directory", "dir-listing",
		"database", "dump", "archive",
		"cve", "session", "cookie",
		"login", "auth", "brute", "weak-password",
		"trace", "verbose",
		"phishing",
		"file-read", "traversal",
	}

	tagSet := make(map[string]bool)
	for _, t := range tags {
		tagSet[strings.ToLower(t)] = true
	}

	for _, t := range knownTypes {
		if tagSet[t] {
			return normalizeVulnType(t)
		}
	}

	// Priority 2: Check template ID
	tid := strings.ToLower(templateID)
	for _, t := range knownTypes {
		if strings.Contains(tid, t) {
			return normalizeVulnType(t)
		}
	}

	// Priority 3: Check matcher name
	mn := strings.ToLower(matcherName)
	for _, t := range knownTypes {
		if strings.Contains(mn, t) {
			return normalizeVulnType(t)
		}
	}

	// Fallback: use first tag or "unknown"
	if len(tags) > 0 {
		return tags[0]
	}
	return "unknown"
}

// normalizeVulnType maps variant names to canonical names
func normalizeVulnType(t string) string {
	switch strings.ToLower(t) {
	case "sql-injection":
		return "sqli"
	case "cross-site-scripting":
		return "xss"
	case "code-execution", "command-injection":
		return "rce"
	case "open-redirect":
		return "redirect"
	case "path-traversal", "file-read", "traversal":
		return "lfi"
	case "dir-listing":
		return "listing"
	case "tech-detect", "tech":
		return "fingerprint"
	case "weak-password", "brute":
		return "default-login"
	case "disclosure", "info-leak":
		return "exposure"
	case "api-key", "jwt", "credential":
		return "token"
	case "dangling":
		return "takeover"
	default:
		return t
	}
}

// extractHost extracts hostname from URL
func extractHost(url string) string {
	url = strings.TrimSpace(url)
	if strings.HasPrefix(url, "http://") {
		url = strings.TrimPrefix(url, "http://")
	} else if strings.HasPrefix(url, "https://") {
		url = strings.TrimPrefix(url, "https://")
	}
	// Remove path
	if idx := strings.Index(url, "/"); idx > 0 {
		url = url[:idx]
	}
	// Remove port for host comparison but keep it separate
	return url
}

// Analyzer orchestrates the full analysis pipeline
type Analyzer struct {
	graph    *AttackGraph
	finder   *ChainFinder
	findings []*Finding
}

// AnalyzerConfig configures the analyzer
type AnalyzerConfig struct {
	MaxDepth       int
	MinConfidence  float64
	CustomRules    []ChainRule
}

// DefaultAnalyzerConfig returns sensible defaults
func DefaultAnalyzerConfig() AnalyzerConfig {
	return AnalyzerConfig{
		MaxDepth:      5,
		MinConfidence: 0.5,
	}
}

// NewAnalyzer creates a new analyzer
func NewAnalyzer(config AnalyzerConfig) *Analyzer {
	rules := config.CustomRules
	graph := NewAttackGraph(rules)
	finder := NewChainFinder(graph, config.MaxDepth, config.MinConfidence)
	return &Analyzer{
		graph:  graph,
		finder: finder,
	}
}

// LoadFindings loads findings from a JSONL reader
func (a *Analyzer) LoadFindings(reader io.Reader) (int, error) {
	findings, err := ParseJSONL(reader)
	if err != nil {
		return 0, err
	}
	a.findings = findings
	a.graph.AddFindings(findings)
	return len(findings), nil
}

// LoadFindingsFromFile loads findings from a JSONL file
func (a *Analyzer) LoadFindingsFromFile(path string) (int, error) {
	findings, err := ParseJSONLFile(path)
	if err != nil {
		return 0, err
	}
	a.findings = findings
	a.graph.AddFindings(findings)
	return len(findings), nil
}

// LoadFindingsDirect loads pre-built findings
func (a *Analyzer) LoadFindingsDirect(findings []*Finding) {
	a.findings = findings
	a.graph.AddFindings(findings)
}

// Analyze finds all attack chains
func (a *Analyzer) Analyze() []*AttackChain {
	return a.finder.FindAll()
}

// Graph returns the underlying attack graph
func (a *Analyzer) Graph() *AttackGraph {
	return a.graph
}

// Findings returns all loaded findings
func (a *Analyzer) Findings() []*Finding {
	return a.findings
}

// Report generates a JSON-serializable report
type Report struct {
	Summary  ChainSummary   `json:"summary"`
	Chains   []ChainReport  `json:"chains"`
	Findings []FindingReport `json:"findings"`
	GraphStats GraphStats   `json:"graph_stats"`
}

// ChainReport is a JSON-serializable attack chain
type ChainReport struct {
	Description    string         `json:"description"`
	MaxSeverity    string         `json:"max_severity"`
	FinalSeverity  string         `json:"final_severity"`
	Confidence     float64        `json:"confidence"`
	Score          float64        `json:"score"`
	RiskScore      float64        `json:"risk_score"`
	Length         int            `json:"length"`
	Steps          []ChainStepReport `json:"steps"`
}

// ChainStepReport is a JSON-serializable chain step
type ChainStepReport struct {
	From       string  `json:"from"`
	To         string  `json:"to"`
	Relation   string  `json:"relation"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	FromFinding FindingReport `json:"from_finding"`
	ToFinding   FindingReport `json:"to_finding"`
}

// FindingReport is a JSON-serializable finding
type FindingReport struct {
	ID           string   `json:"id"`
	TemplateID   string   `json:"template_id"`
	Host         string   `json:"host"`
	URL          string   `json:"url"`
	Severity     string   `json:"severity"`
	VulnType     string   `json:"vuln_type"`
	Tags         []string `json:"tags"`
	MatcherName  string   `json:"matcher_name"`
}

// GraphStats holds graph statistics
type GraphStats struct {
	Nodes int `json:"nodes"`
	Edges int `json:"edges"`
}

// GenerateReport creates a full JSON-serializable report
func (a *Analyzer) GenerateReport(chains []*AttackChain) Report {
	chainReports := make([]ChainReport, 0, len(chains))
	for _, c := range chains {
		cr := ChainReport{
			Description:   c.Description,
			MaxSeverity:   c.MaxSeverity,
			FinalSeverity: c.FinalSeverity,
			Confidence:    c.Confidence,
			Score:         c.Score,
			RiskScore:     c.RiskScore,
			Length:        len(c.Steps),
			Steps:         make([]ChainStepReport, 0, len(c.Steps)),
		}
		for _, edge := range c.Steps {
			step := ChainStepReport{
				From:       edge.From.VulnTypeOr(),
				To:         edge.To.VulnTypeOr(),
				Relation:   edge.Relation,
				Confidence: edge.Confidence,
				Reason:     edge.Reason,
				FromFinding: findingToReport(edge.From),
				ToFinding:   findingToReport(edge.To),
			}
			cr.Steps = append(cr.Steps, step)
		}
		chainReports = append(chainReports, cr)
	}

	findingReports := make([]FindingReport, 0, len(a.findings))
	for _, f := range a.findings {
		findingReports = append(findingReports, findingToReport(f))
	}

	return Report{
		Summary:  Summarize(chains),
		Chains:   chainReports,
		Findings: findingReports,
		GraphStats: GraphStats{
			Nodes: a.graph.NodeCount(),
			Edges: a.graph.EdgeCount(),
		},
	}
}

func findingToReport(f *Finding) FindingReport {
	return FindingReport{
		ID:          f.ID,
		TemplateID:  f.TemplateID,
		Host:        f.Host,
		URL:         f.URL,
		Severity:    f.Severity,
		VulnType:    f.VulnTypeOr(),
		Tags:        f.Tags,
		MatcherName: f.MatcherName,
	}
}
