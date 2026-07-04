package templatelearn

import (
	"sort"
	"sync"
)

// QualityScore represents the reliability score of a template
type QualityScore struct {
	TemplateID     string  `json:"template_id"`
	Score          float64 `json:"score"`           // 0.0 (unreliable) to 1.0 (highly reliable)
	TPCount        int     `json:"tp_count"`        // true positive marks
	FPCount        int     `json:"fp_count"`        // false positive marks
	FNCount        int     `json:"fn_count"`        // false negative marks
	TotalFindings  int     `json:"total_findings"`  // total feedback entries
	FPRate         float64 `json:"fp_rate"`         // FP / (TP + FP)
	Confidence     string  `json:"confidence"`      // high, medium, low, unknown
	Suppressed     bool    `json:"suppressed"`
	Recommendation string  `json:"recommendation"`  // action recommendation
}

// QualityReport is a summary of all template quality scores
type QualityReport struct {
	TotalTemplates  int            `json:"total_templates"`
	HighConfidence  int            `json:"high_confidence"`
	MediumConfidence int           `json:"medium_confidence"`
	LowConfidence   int            `json:"low_confidence"`
	Unknown         int            `json:"unknown"`
	Suppressed      int            `json:"suppressed"`
	TopTemplates    []QualityScore `json:"top_templates"`
	WorstTemplates  []QualityScore `json:"worst_templates"`
}

// ScoreTemplate calculates a quality score for a template based on feedback data
func ScoreTemplate(store *FeedbackStore, templateID string) QualityScore {
	score := QualityScore{
		TemplateID: templateID,
		Score:      0.5, // default neutral score for templates with no data
		Confidence: "unknown",
	}

	if store == nil {
		score.Recommendation = "no feedback data available"
		return score
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	// Count feedback by type for this template
	for _, fb := range store.feedback {
		if fb.TemplateID != templateID {
			continue
		}
		score.TotalFindings++
		switch fb.Type {
		case FeedbackTruePositive:
			score.TPCount++
		case FeedbackFalsePositive:
			score.FPCount++
		case FeedbackFalseNegative:
			score.FNCount++
		}
	}

	// Check if suppressed
	for _, rule := range store.suppressions {
		if rule.TemplateID == templateID {
			score.Suppressed = true
			break
		}
	}

	// Calculate score
	if score.TotalFindings == 0 {
		score.Score = 0.5
		score.Confidence = "unknown"
		score.Recommendation = "no feedback data — treat as neutral"
		return score
	}

	total := score.TPCount + score.FPCount
	if total > 0 {
		score.FPRate = float64(score.FPCount) / float64(total)
	} else {
		score.FPRate = 0.0
	}

	// Score formula: TP weight positive, FP weight negative, FN slight negative
	// Score = (TP - FP*2 - FN*0.5) / total, clamped to [0, 1]
	// The FP penalty is doubled because FPs are more costly than FNs
	rawScore := float64(score.TPCount) - float64(score.FPCount)*2.0 - float64(score.FNCount)*0.5
	maxPossible := float64(total) + float64(score.FNCount)
	if maxPossible > 0 {
		score.Score = rawScore / maxPossible
	} else {
		score.Score = 0.5
	}

	// Clamp to [0, 1]
	if score.Score < 0 {
		score.Score = 0
	}
	if score.Score > 1 {
		score.Score = 1
	}

	// Determine confidence level
	if score.Suppressed {
		score.Confidence = "suppressed"
		score.Recommendation = "template is suppressed — skip or fix"
	} else if score.FPRate >= 0.5 && total >= 3 {
		score.Confidence = "low"
		score.Recommendation = "high FP rate — review and fix matchers"
	} else if score.FPRate > 0.2 && total >= 3 {
		score.Confidence = "medium"
		score.Recommendation = "moderate FP rate — monitor"
	} else if score.TPCount >= 3 && score.FPRate < 0.1 {
		score.Confidence = "high"
		score.Recommendation = "reliable template — safe to use"
	} else if score.TPCount > 0 && score.FPCount == 0 {
		score.Confidence = "high"
		score.Recommendation = "no FPs reported — reliable"
	} else {
		score.Confidence = "medium"
		score.Recommendation = "limited data — continue monitoring"
	}

	return score
}

// ScoreAllTemplates generates quality scores for all templates in the feedback store
func ScoreAllTemplates(store *FeedbackStore) QualityReport {
	report := QualityReport{}

	if store == nil {
		return report
	}

	store.mu.RLock()
	templateIDs := make(map[string]bool)
	for _, fb := range store.feedback {
		templateIDs[fb.TemplateID] = true
	}
	store.mu.RUnlock()

	var scores []QualityScore
	for tid := range templateIDs {
		s := ScoreTemplate(store, tid)
		scores = append(scores, s)

		report.TotalTemplates++
		switch s.Confidence {
		case "high":
			report.HighConfidence++
		case "medium":
			report.MediumConfidence++
		case "low":
			report.LowConfidence++
		case "suppressed":
			report.Suppressed++
		default:
			report.Unknown++
		}
	}

	// Sort by score descending for top templates
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score > scores[j].Score
	})

	// Top 10 — copy to avoid reordering by worst sort
	topCount := 10
	if len(scores) < topCount {
		topCount = len(scores)
	}
	topCopy := make([]QualityScore, topCount)
	copy(topCopy, scores[:topCount])
	report.TopTemplates = topCopy

	// Worst 10 (reverse)
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score < scores[j].Score
	})
	worstCount := 10
	if len(scores) < worstCount {
		worstCount = len(scores)
	}
	worstCopy := make([]QualityScore, worstCount)
	copy(worstCopy, scores[:worstCount])
	report.WorstTemplates = worstCopy

	return report
}

// QualityFilter is a streaming filter that suppresses low-quality findings
// based on template quality scores from the feedback store
type QualityFilter struct {
	store    *FeedbackStore
	minScore float64
	mu       sync.RWMutex
}

// NewQualityFilter creates a new quality filter
func NewQualityFilter(store *FeedbackStore, minScore float64) *QualityFilter {
	return &QualityFilter{
		store:    store,
		minScore: minScore,
	}
}

// ShouldReport returns true if a finding from the given template should be reported
// (i.e., the template's quality score is above the minimum threshold)
func (qf *QualityFilter) ShouldReport(templateID, host, matcherName, vulnType string) (bool, string) {
	if qf == nil || qf.store == nil {
		return true, ""
	}

	// Check suppression rules first
	suppressed, _ := qf.store.ShouldSuppress(templateID, host, matcherName, vulnType)
	if suppressed {
		return false, "suppressed by rule"
	}

	// Check quality score
	score := ScoreTemplate(qf.store, templateID)
	if score.Suppressed {
		return false, "template suppressed"
	}
	if score.TotalFindings >= 3 && score.Score < qf.minScore {
		qf.mu.RLock()
		minScore := qf.minScore
		qf.mu.RUnlock()
		return false, "template quality score " + formatScore(score.Score) + " below threshold " + formatScore(minScore)
	}

	return true, ""
}

// SetMinScore updates the minimum quality score threshold
func (qf *QualityFilter) SetMinScore(score float64) {
	qf.mu.Lock()
	defer qf.mu.Unlock()
	qf.minScore = score
}

func formatScore(f float64) string {
	return formatFloat(f)
}

func formatFloat(f float64) string {
	if f == 0 {
		return "0.00"
	}
	if f == 1 {
		return "1.00"
	}
	// Simple formatting without strconv
	whole := int(f)
	frac := int((f - float64(whole)) * 100)
	if frac < 0 {
		frac = -frac
	}
	return formatInt(whole) + "." + formatIntPadded(frac)
}

func formatInt(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func formatIntPadded(i int) string {
	if i < 10 {
		return "0" + formatInt(i)
	}
	return formatInt(i)
}
