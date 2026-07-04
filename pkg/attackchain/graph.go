package attackchain

import (
	"fmt"
	"strings"
	"sync"
)

// Severity levels
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// severityOrder maps severity to numeric level for comparison
var severityOrder = map[string]int{
	SeverityInfo:     1,
	SeverityLow:      2,
	SeverityMedium:   3,
	SeverityHigh:     4,
	SeverityCritical: 5,
}

// SeverityValue returns numeric severity for comparison (higher = worse)
func SeverityValue(s string) int {
	return severityOrder[strings.ToLower(s)]
}

// CompareSeverity returns -1, 0, 1 comparing two severities
func CompareSeverity(a, b string) int {
	av := SeverityValue(a)
	bv := SeverityValue(b)
	if av < bv {
		return -1
	}
	if av > bv {
		return 1
	}
	return 0
}

// MaxSeverity returns the higher of two severities
func MaxSeverity(a, b string) string {
	if SeverityValue(a) >= SeverityValue(b) {
		return a
	}
	return b
}

// Finding represents a vulnerability finding from nuclei
type Finding struct {
	ID            string                 // unique ID (template-id:hash)
	TemplateID    string                 // nuclei template ID
	Host          string                 // target host
	URL           string                 // affected URL
	Severity      string                 // info, low, medium, high, critical
	Tags          []string               // template tags
	VulnType      string                 // inferred vuln type (sqli, xss, ssrf, etc.)
	MatcherName   string                 // matched matcher name
	ExtractedData map[string]string      // extracted data (e.g., usernames, versions)
	Metadata      map[string]interface{} // raw metadata from nuclei
	Port          string
	Raw           string // raw JSON line
}

// VulnType returns the inferred vulnerability type
func (f *Finding) VulnTypeOr() string {
	if f.VulnType != "" {
		return f.VulnType
	}
	if len(f.Tags) > 0 {
		return f.Tags[0]
	}
	return "unknown"
}

// HasTag checks if a finding has a specific tag
func (f *Finding) HasTag(tag string) bool {
	for _, t := range f.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// HasExtracted checks if a finding has an extracted value for a key
func (f *Finding) HasExtracted(key string) bool {
	_, ok := f.ExtractedData[key]
	return ok
}

// GetExtracted returns extracted value for a key, empty if not present
func (f *Finding) GetExtracted(key string) string {
	if v, ok := f.ExtractedData[key]; ok {
		return v
	}
	return ""
}

// ChainEdge represents a relationship between two findings
type ChainEdge struct {
	From       *Finding // source finding
	To         *Finding // target finding
	Relation   string   // relationship type (e.g., "enables", "leaks-info-for")
	Confidence float64  // 0.0 to 1.0
	Reason     string   // human-readable explanation
}

// ChainRule defines when one finding enables another
type ChainRule struct {
	Name        string   // rule name
	FromVuln    []string // source vuln types/tags (any match)
	ToVuln      []string // target vuln types/tags (any match)
	Relation    string   // relationship type
	Confidence  float64  // base confidence (0.0 to 1.0)
	Reason      string   // explanation template
	SeverityBoost string // severity boost on the target (e.g., "high" → "critical")
	RequiresSameHost bool // must be same host
	RequiresSamePort bool // must be same port
}

// DefaultChainRules defines common attack chain patterns
var DefaultChainRules = []ChainRule{
	// === Information disclosure → credential access ===
	{
		Name: "info-leak-to-cred-access",
		FromVuln: []string{"exposure", "info-leak", "disclosure", "config", "files",
			"backup", "source-code", "git", "svn", "env"},
		ToVuln:   []string{"login", "auth", "brute", "default-login", "weak-password"},
		Relation: "leaks-info-for",
		Confidence: 0.7,
		Reason: "Information disclosure may leak credentials needed for authentication",
		SeverityBoost: "",
		RequiresSameHost: true,
	},
	// === Default login → authenticated access ===
	{
		Name: "default-login-to-auth-access",
		FromVuln: []string{"default-login", "login", "weak-password", "brute"},
		ToVuln:   []string{"panel", "admin", "dashboard", "console"},
		Relation: "enables",
		Confidence: 0.85,
		Reason: "Default credentials provide authenticated access to admin panels",
		SeverityBoost: "critical",
		RequiresSameHost: true,
	},
	// === SSRF → cloud metadata ===
	{
		Name: "ssrf-to-metadata",
		FromVuln: []string{"ssrf"},
		ToVuln:   []string{"metadata", "cloud", "aws", "iam", "token"},
		Relation: "enables",
		Confidence: 0.9,
		Reason: "SSRF can access cloud metadata service to steal IAM credentials",
		SeverityBoost: "critical",
		RequiresSameHost: true,
	},
	// === LFI → RCE ===
	{
		Name: "lfi-to-rce",
		FromVuln: []string{"lfi", "path-traversal", "file-read", "traversal"},
		ToVuln:   []string{"rce", "code-execution", "command-injection"},
		Relation: "enables",
		Confidence: 0.75,
		Reason: "Local file inclusion can escalate to remote code execution via log poisoning or proc tricks",
		SeverityBoost: "critical",
		RequiresSameHost: true,
	},
	// === SQLi → data exfiltration ===
	{
		Name: "sqli-to-exfil",
		FromVuln: []string{"sqli", "sql-injection"},
		ToVuln:   []string{"exposure", "database", "dump", "info-leak"},
		Relation: "enables",
		Confidence: 0.85,
		Reason: "SQL injection enables database content exfiltration",
		SeverityBoost: "critical",
		RequiresSameHost: true,
	},
	// === XSS → session hijack ===
	{
		Name: "xss-to-session-hijack",
		FromVuln: []string{"xss", "cross-site-scripting"},
		ToVuln:   []string{"session", "cookie", "auth", "csrf"},
		Relation: "enables",
		Confidence: 0.7,
		Reason: "XSS can steal session tokens to hijack authentication",
		SeverityBoost: "high",
		RequiresSameHost: true,
	},
	// === Open redirect → SSRF ===
	{
		Name: "redirect-to-ssrf",
		FromVuln: []string{"redirect", "open-redirect"},
		ToVuln:   []string{"ssrf"},
		Relation: "enables",
		Confidence: 0.6,
		Reason: "Open redirect can be abused for SSRF via redirect chains",
		SeverityBoost: "",
		RequiresSameHost: true,
	},
	// === Version disclosure → CVE exploitation ===
	{
		Name: "version-to-cve",
		FromVuln: []string{"version", "fingerprint", "tech-detect", "tech"},
		ToVuln:   []string{"cve", "rce", "lfi", "ssrf", "sqli", "auth-bypass"},
		Relation: "enables",
		Confidence: 0.65,
		Reason: "Version disclosure identifies vulnerable software for targeted CVE exploitation",
		SeverityBoost: "",
		RequiresSameHost: true,
	},
	// === Debug mode → info leak ===
	{
		Name: "debug-to-info-leak",
		FromVuln: []string{"debug", "trace", "verbose"},
		ToVuln:   []string{"exposure", "info-leak", "config", "source-code"},
		Relation: "enables",
		Confidence: 0.7,
		Reason: "Debug mode leaks internal paths, variables, and stack traces",
		SeverityBoost: "",
		RequiresSameHost: true,
	},
	// === Directory listing → LFI ===
	{
		Name: "dir-list-to-lfi",
		FromVuln: []string{"listing", "directory", "dir-listing"},
		ToVuln:   []string{"lfi", "path-traversal", "file-read"},
		Relation: "enables",
		Confidence: 0.6,
		Reason: "Directory listing reveals file paths useful for path traversal",
		SeverityBoost: "",
		RequiresSameHost: true,
	},
	// === Backup files → source code leak ===
	{
		Name: "backup-to-source-leak",
		FromVuln: []string{"backup", "dump", "archive"},
		ToVuln:   []string{"source-code", "exposure", "config", "info-leak"},
		Relation: "enables",
		Confidence: 0.75,
		Reason: "Backup files may contain source code and configuration secrets",
		SeverityBoost: "high",
		RequiresSameHost: true,
	},
	// === CVE → RCE (direct) ===
	{
		Name: "cve-to-rce",
		FromVuln: []string{"cve"},
		ToVuln:   []string{"rce", "code-execution", "command-injection"},
		Relation: "enables",
		Confidence: 0.8,
		Reason: "CVE vulnerability may allow remote code execution",
		SeverityBoost: "critical",
		RequiresSameHost: true,
	},
	// === Misconfig → unauthorized access ===
	{
		Name: "misconfig-to-access",
		FromVuln: []string{"misconfig", "config", "exposure"},
		ToVuln:   []string{"panel", "admin", "dashboard", "console", "default-login"},
		Relation: "enables",
		Confidence: 0.65,
		Reason: "Misconfiguration may expose administrative interfaces without auth",
		SeverityBoost: "high",
		RequiresSameHost: true,
	},
	// === Token leak → auth bypass ===
	{
		Name: "token-leak-to-auth-bypass",
		FromVuln: []string{"token", "api-key", "secret", "jwt", "credential"},
		ToVuln:   []string{"auth-bypass", "auth", "panel", "admin"},
		Relation: "enables",
		Confidence: 0.85,
		Reason: "Leaked tokens or API keys enable authentication bypass",
		SeverityBoost: "critical",
		RequiresSameHost: false,
	},
	// === Subdomain takeover → phishing ===
	{
		Name: "subdomain-takeover-to-phishing",
		FromVuln: []string{"takeover", "subdomain", "dangling"},
		ToVuln:   []string{"xss", "phishing", "redirect"},
		Relation: "enables",
		Confidence: 0.7,
		Reason: "Subdomain takeover enables phishing and XSS on trusted domain",
		SeverityBoost: "high",
		RequiresSameHost: false,
	},
}

// AttackGraph is a directed graph of findings and their relationships
type AttackGraph struct {
	nodes   map[string]*Finding
	edges   []*ChainEdge
	outAdj  map[string][]*ChainEdge // adjacency list: node ID → outgoing edges
	inAdj   map[string][]*ChainEdge // adjacency list: node ID → incoming edges
	rules   []ChainRule
	mu      sync.RWMutex
}

// NewAttackGraph creates a new graph with the given rules (defaults if nil)
func NewAttackGraph(rules []ChainRule) *AttackGraph {
	if rules == nil {
		rules = DefaultChainRules
	}
	return &AttackGraph{
		nodes:  make(map[string]*Finding),
		edges:  []*ChainEdge{},
		outAdj: make(map[string][]*ChainEdge),
		inAdj:  make(map[string][]*ChainEdge),
		rules:  rules,
	}
}

// AddFinding adds a finding to the graph and evaluates chain rules
func (g *AttackGraph) AddFinding(f *Finding) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if f.ID == "" {
		f.ID = fmt.Sprintf("%s:%s:%s", f.TemplateID, f.Host, f.MatcherName)
	}
	if _, exists := g.nodes[f.ID]; exists {
		return
	}
	g.nodes[f.ID] = f

	// Evaluate chain rules against all existing nodes
	for _, existing := range g.nodes {
		if existing.ID == f.ID {
			continue
		}
		// New finding as source, existing as target
		g.evaluateRules(f, existing)
		// Existing as source, new finding as target
		g.evaluateRules(existing, f)
	}
}

// AddFindings adds multiple findings at once
func (g *AttackGraph) AddFindings(findings []*Finding) {
	for _, f := range findings {
		g.AddFinding(f)
	}
}

// evaluateRules checks all chain rules between two findings
func (g *AttackGraph) evaluateRules(from, to *Finding) {
	for _, rule := range g.rules {
		if !vulnMatches(from, rule.FromVuln) {
			continue
		}
		if !vulnMatches(to, rule.ToVuln) {
			continue
		}
		if rule.RequiresSameHost && !strings.EqualFold(from.Host, to.Host) {
			continue
		}
		if rule.RequiresSamePort && from.Port != to.Port {
			continue
		}
		// Don't add self-loops
		if from.ID == to.ID {
			continue
		}
		edge := &ChainEdge{
			From:       from,
			To:         to,
			Relation:   rule.Relation,
			Confidence: rule.Confidence,
			Reason:     rule.Reason,
		}
		g.edges = append(g.edges, edge)
		g.outAdj[from.ID] = append(g.outAdj[from.ID], edge)
		g.inAdj[to.ID] = append(g.inAdj[to.ID], edge)
	}
}

// vulnMatches checks if a finding matches any of the required vuln types
func vulnMatches(f *Finding, types []string) bool {
	if len(types) == 0 {
		return false
	}
	vt := strings.ToLower(f.VulnTypeOr())
	for _, t := range types {
		t = strings.ToLower(t)
		if vt == t || strings.Contains(vt, t) {
			return true
		}
		if f.HasTag(t) {
			return true
		}
	}
	// Also check template ID contains the type
	tid := strings.ToLower(f.TemplateID)
	for _, t := range types {
		t = strings.ToLower(t)
		if strings.Contains(tid, t) {
			return true
		}
	}
	return false
}

// Nodes returns all findings in the graph
func (g *AttackGraph) Nodes() []*Finding {
	g.mu.RLock()
	defer g.mu.RUnlock()
	nodes := make([]*Finding, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// Edges returns all edges in the graph
func (g *AttackGraph) Edges() []*ChainEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	edges := make([]*ChainEdge, len(g.edges))
	copy(edges, g.edges)
	return edges
}

// OutgoingEdges returns edges going out from a node
func (g *AttackGraph) OutgoingEdges(nodeID string) []*ChainEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	edges := g.outAdj[nodeID]
	result := make([]*ChainEdge, len(edges))
	copy(result, edges)
	return result
}

// IncomingEdges returns edges coming into a node
func (g *AttackGraph) IncomingEdges(nodeID string) []*ChainEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	edges := g.inAdj[nodeID]
	result := make([]*ChainEdge, len(edges))
	copy(result, edges)
	return result
}

// NodeCount returns the number of nodes
func (g *AttackGraph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// EdgeCount returns the number of edges
func (g *AttackGraph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.edges)
}

// GetNode returns a node by ID
func (g *AttackGraph) GetNode(id string) *Finding {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodes[id]
}

// FindRule returns the chain rule that created an edge (by matching rule name)
func (g *AttackGraph) FindRule(edge *ChainEdge) *ChainRule {
	for i := range g.rules {
		if g.rules[i].Relation == edge.Relation &&
			vulnMatches(edge.From, g.rules[i].FromVuln) &&
			vulnMatches(edge.To, g.rules[i].ToVuln) {
			return &g.rules[i]
		}
	}
	return nil
}
