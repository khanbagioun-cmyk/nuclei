package attackchain

import (
	"sort"
	"strings"
)

// AttackChain represents a multi-step exploit path
type AttackChain struct {
	Steps      []*ChainEdge // ordered list of edges forming the chain
	Findings   []*Finding   // ordered list of findings (len = len(Steps)+1)
	MaxSeverity string      // highest severity in the chain
	FinalSeverity string    // escalated severity after chain analysis
	Confidence float64      // combined confidence (product of edge confidences)
	Score      float64      // overall chain score (severity * confidence * depth)
	RiskScore  float64      // risk score (0-100)
	Description string      // human-readable summary
}

// ChainFinder finds attack chains in an AttackGraph using DFS
type ChainFinder struct {
	graph    *AttackGraph
	maxDepth int
	visited  map[string]bool
	results  []*AttackChain
	minConf  float64
}

// NewChainFinder creates a chain finder
func NewChainFinder(graph *AttackGraph, maxDepth int, minConfidence float64) *ChainFinder {
	if maxDepth <= 0 {
		maxDepth = 5
	}
	if minConfidence < 0 {
		minConfidence = 0
	}
	return &ChainFinder{
		graph:    graph,
		maxDepth: maxDepth,
		minConf:  minConfidence,
	}
}

// FindAll finds all attack chains in the graph
func (cf *ChainFinder) FindAll() []*AttackChain {
	cf.results = []*AttackChain{}

	// Start DFS from each node that has outgoing edges but no incoming edges
	// (entry points), or from all nodes if no pure entry points exist
	entryPoints := cf.findEntryPoints()
	if len(entryPoints) == 0 {
		// No entry points — use all nodes with outgoing edges
		for _, n := range cf.graph.Nodes() {
			if len(cf.graph.OutgoingEdges(n.ID)) > 0 {
				entryPoints = append(entryPoints, n)
			}
		}
	}

	for _, start := range entryPoints {
		cf.visited = map[string]bool{}
		cf.dfs(start, []*ChainEdge{}, 1.0)
	}

	// Deduplicate and sort by score
	cf.results = deduplicateChains(cf.results)
	sort.Slice(cf.results, func(i, j int) bool {
		return cf.results[i].Score > cf.results[j].Score
	})

	return cf.results
}

// findEntryPoints returns nodes with outgoing edges but no incoming edges
func (cf *ChainFinder) findEntryPoints() []*Finding {
	var entries []*Finding
	for _, n := range cf.graph.Nodes() {
		if len(cf.graph.IncomingEdges(n.ID)) == 0 && len(cf.graph.OutgoingEdges(n.ID)) > 0 {
			entries = append(entries, n)
		}
	}
	return entries
}

// dfs performs depth-first search for attack chains
func (cf *ChainFinder) dfs(node *Finding, path []*ChainEdge, confidence float64) {
	// Check depth limit
	if len(path) >= cf.maxDepth {
		cf.recordChain(path, confidence)
		return
	}

	// Mark current node as visited in this path
	cf.visited[node.ID] = true
	defer func() { delete(cf.visited, node.ID) }()

	outEdges := cf.graph.OutgoingEdges(node.ID)
	if len(outEdges) == 0 && len(path) > 0 {
		// Reached a leaf — record the chain
		cf.recordChain(path, confidence)
		return
	}

	extended := false
	for _, edge := range outEdges {
		// Skip cycles
		if cf.visited[edge.To.ID] {
			continue
		}
		// Skip low-confidence edges
		if edge.Confidence < cf.minConf {
			continue
		}
		newConf := confidence * edge.Confidence
		newPath := append(path, edge)
		cf.dfs(edge.To, newPath, newConf)
		extended = true
	}

	if !extended && len(path) > 0 {
		cf.recordChain(path, confidence)
	}
}

// recordChain records a found chain
func (cf *ChainFinder) recordChain(path []*ChainEdge, confidence float64) {
	if len(path) == 0 {
		return
	}

	chain := &AttackChain{
		Steps:      path,
		Findings:   []*Finding{path[0].From},
		Confidence: confidence,
	}

	maxSev := SeverityInfo
	for _, edge := range path {
		chain.Findings = append(chain.Findings, edge.To)
		maxSev = MaxSeverity(maxSev, edge.From.Severity)
		maxSev = MaxSeverity(maxSev, edge.To.Severity)
	}
	chain.MaxSeverity = maxSev

	// Apply severity boosts
	finalSev := maxSev
	for _, edge := range path {
		rule := cf.graph.FindRule(edge)
		if rule != nil && rule.SeverityBoost != "" {
			if SeverityValue(rule.SeverityBoost) > SeverityValue(finalSev) {
				finalSev = rule.SeverityBoost
			}
		}
	}
	chain.FinalSeverity = finalSev

	// Calculate score: severity * confidence * depth bonus
	sevVal := float64(SeverityValue(finalSev))
	depthBonus := 1.0 + float64(len(path))*0.2
	chain.Score = sevVal * confidence * depthBonus

	// Risk score (0-100): severity (1-5) * confidence (0-1) * depth factor * 20
	chain.RiskScore = sevVal * confidence * depthBonus * 20
	if chain.RiskScore > 100 {
		chain.RiskScore = 100
	}

	chain.Description = cf.describeChain(chain)
	cf.results = append(cf.results, chain)
}

// describeChain generates a human-readable description
func (cf *ChainFinder) describeChain(chain *AttackChain) string {
	var sb strings.Builder
	sb.WriteString(chain.Findings[0].VulnTypeOr())
	for i, edge := range chain.Steps {
		sb.WriteString(" →[")
		sb.WriteString(edge.Relation)
		sb.WriteString("]→ ")
		sb.WriteString(chain.Findings[i+1].VulnTypeOr())
	}
	return sb.String()
}

// deduplicateChains removes duplicate chains (same sequence of node IDs)
func deduplicateChains(chains []*AttackChain) []*AttackChain {
	seen := make(map[string]bool)
	var result []*AttackChain
	for _, c := range chains {
		key := chainKey(c)
		if !seen[key] {
			seen[key] = true
			result = append(result, c)
		}
	}
	return result
}

// chainKey generates a unique key for a chain based on node sequence
func chainKey(c *AttackChain) string {
	var sb strings.Builder
	for i, f := range c.Findings {
		if i > 0 {
			sb.WriteString("->")
		}
		sb.WriteString(f.ID)
	}
	return sb.String()
}

// TopChains returns the N highest-scoring chains
func TopChains(chains []*AttackChain, n int) []*AttackChain {
	if n <= 0 || n >= len(chains) {
		return chains
	}
	return chains[:n]
}

// ChainsBySeverity groups chains by final severity
func ChainsBySeverity(chains []*AttackChain) map[string][]*AttackChain {
	result := map[string][]*AttackChain{
		SeverityCritical: {},
		SeverityHigh:     {},
		SeverityMedium:   {},
		SeverityLow:      {},
		SeverityInfo:     {},
	}
	for _, c := range chains {
		sev := strings.ToLower(c.FinalSeverity)
		if _, ok := result[sev]; ok {
			result[sev] = append(result[sev], c)
		} else {
			result[SeverityInfo] = append(result[SeverityInfo], c)
		}
	}
	return result
}

// ChainSummary returns statistics about found chains
type ChainSummary struct {
	TotalChains     int
	CriticalChains  int
	HighChains      int
	MediumChains    int
	LowChains       int
	AvgChainLength  float64
	MaxChainLength  int
	AvgRiskScore    float64
	MaxRiskScore    float64
	UniqueFindings  int
	TotalFindings   int
}

// Summarize returns summary statistics about the chains
func Summarize(chains []*AttackChain) ChainSummary {
	s := ChainSummary{TotalChains: len(chains)}
	totalLen := 0
	totalRisk := 0.0
	findingSet := make(map[string]bool)

	for _, c := range chains {
		totalLen += len(c.Steps)
		if len(c.Steps) > s.MaxChainLength {
			s.MaxChainLength = len(c.Steps)
		}
		totalRisk += c.RiskScore
		if c.RiskScore > s.MaxRiskScore {
			s.MaxRiskScore = c.RiskScore
		}
		for _, f := range c.Findings {
			findingSet[f.ID] = true
			s.TotalFindings++
		}
		switch strings.ToLower(c.FinalSeverity) {
		case SeverityCritical:
			s.CriticalChains++
		case SeverityHigh:
			s.HighChains++
		case SeverityMedium:
			s.MediumChains++
		case SeverityLow:
			s.LowChains++
		}
	}

	if s.TotalChains > 0 {
		s.AvgChainLength = float64(totalLen) / float64(s.TotalChains)
		s.AvgRiskScore = totalRisk / float64(s.TotalChains)
	}
	s.UniqueFindings = len(findingSet)
	return s
}
