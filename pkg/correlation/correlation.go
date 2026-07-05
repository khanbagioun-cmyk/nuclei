package correlation

import (
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// CorrelationRule defines a cross-phase correlation.
// If a finding matching Source conditions exists, boost/deduplicate findings matching Target.
type CorrelationRule struct {
	ID          string
	Name        string
	Description string
	Source      FindingMatch
	Target      FindingMatch
	Action      CorrelationAction
}

// FindingMatch defines criteria for matching a finding.
type FindingMatch struct {
	TemplateID  string // empty = any
	VulnType    string // empty = any (matched against info.tags)
	Tag         string // empty = any
	Host        string // empty = any
	Severity    string // empty = any
}

// CorrelationAction defines what to do when correlation fires.
type CorrelationAction int

const (
	ActionBoost    CorrelationAction = iota // increase severity/confidence
	ActionDedup                              // remove duplicate target finding
	ActionLink                               // add a link note to target finding
)

// CorrelationResult holds the result of running correlations.
type CorrelationResult struct {
	Links     []FindingLink
	Boosted   int
	Deduped   int
}

// FindingLink represents a cross-reference between two findings.
type FindingLink struct {
	SourceTemplateID string
	SourceHost       string
	TargetTemplateID string
	TargetHost       string
	RuleID           string
	Reason           string
}

// Engine correlates findings across phases.
type Engine struct {
	rules []CorrelationRule
	mu    sync.RWMutex
}

// NewEngine creates a correlation engine with default rules.
func NewEngine() *Engine {
	return &Engine{
		rules: defaultRules(),
	}
}

// AddRule adds a custom correlation rule.
func (e *Engine) AddRule(rule CorrelationRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// Correlate runs all rules against the given findings and returns links/actions.
func (e *Engine) Correlate(findings []*output.ResultEvent) CorrelationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := CorrelationResult{}

	for _, rule := range e.rules {
		sourceMatches := filterFindings(findings, rule.Source)
		targetMatches := filterFindings(findings, rule.Target)

		if len(sourceMatches) == 0 || len(targetMatches) == 0 {
			continue
		}

		for _, src := range sourceMatches {
			for _, tgt := range targetMatches {
				// Skip self-correlation
				if src == tgt {
					continue
				}
				// Only correlate on same host
				if src.Host != tgt.Host && src.Host != "" && tgt.Host != "" {
					continue
				}

				result.Links = append(result.Links, FindingLink{
					SourceTemplateID: getTemplateID(src),
					SourceHost:       src.Host,
					TargetTemplateID: getTemplateID(tgt),
					TargetHost:       tgt.Host,
					RuleID:           rule.ID,
					Reason:           rule.Description,
				})

				switch rule.Action {
				case ActionBoost:
					result.Boosted++
				case ActionDedup:
					result.Deduped++
				case ActionLink:
					// link recorded above
				}
			}
		}
	}

	return result
}

// filterFindings returns findings that match the given criteria.
func filterFindings(findings []*output.ResultEvent, m FindingMatch) []*output.ResultEvent {
	var result []*output.ResultEvent
	for _, f := range findings {
		if !matchFinding(f, m) {
			continue
		}
		result = append(result, f)
	}
	return result
}

// matchFinding checks if a finding matches the given criteria.
func matchFinding(f *output.ResultEvent, m FindingMatch) bool {
	if m.TemplateID != "" && !strings.EqualFold(getTemplateID(f), m.TemplateID) {
		return false
	}
	if m.Host != "" && !strings.EqualFold(f.Host, m.Host) {
		return false
	}
	if m.Severity != "" {
		sev := strings.ToLower(f.Info.SeverityHolder.Severity.String())
		if !strings.EqualFold(sev, m.Severity) {
			return false
		}
	}
	if m.Tag != "" || m.VulnType != "" {
		tags := getTags(f)
		if m.Tag != "" && !containsTag(tags, m.Tag) {
			return false
		}
		if m.VulnType != "" && !containsTag(tags, m.VulnType) {
			return false
		}
	}
	return true
}

func getTemplateID(f *output.ResultEvent) string {
	if f.TemplateID != "" {
		return f.TemplateID
	}
	return ""
}

func getTags(f *output.ResultEvent) []string {
	if f.Info.Tags.ToSlice() == nil {
		return nil
	}
	return f.Info.Tags.ToSlice()
}

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// defaultRules returns built-in correlation rules.
func defaultRules() []CorrelationRule {
	return []CorrelationRule{
		{
			ID:          "tech-to-cve",
			Name:        "Technology detection to CVE boost",
			Description: "Tech-detect found product → boost CVE findings for same product",
			Source:      FindingMatch{Tag: "tech"},
			Target:      FindingMatch{Tag: "cve"},
			Action:      ActionBoost,
		},
		{
			ID:          "exposure-to-exploit",
			Name:        "Exposure to exploit correlation",
			Description: "Sensitive exposure found → boost exploit templates on same host",
			Source:      FindingMatch{Tag: "exposure"},
			Target:      FindingMatch{Tag: "exploit"},
			Action:      ActionBoost,
		},
		{
			ID:          "default-login-to-auth-bypass",
			Name:        "Default credentials to auth bypass",
			Description: "Default login found → boost auth-bypass findings on same host",
			Source:      FindingMatch{Tag: "default-login"},
			Target:      FindingMatch{Tag: "auth"},
			Action:      ActionBoost,
		},
		{
			ID:          "misconfig-to-exposure",
			Name:        "Misconfiguration to exposure link",
			Description: "Misconfiguration found → link with exposure findings on same host",
			Source:      FindingMatch{Tag: "misconfig"},
			Target:      FindingMatch{Tag: "exposure"},
			Action:      ActionLink,
		},
	}
}

// Summary returns a human-readable correlation summary.
func (r CorrelationResult) Summary() string {
	return fmt.Sprintf("Correlations: %d links, %d boosted, %d deduped",
		len(r.Links), r.Boosted, r.Deduped)
}
