package templatelearn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScoreTemplate_NoData(t *testing.T) {
	store := NewFeedbackStore("", 3)
	score := ScoreTemplate(store, "test-template")

	if score.Score != 0.5 {
		t.Errorf("expected neutral score 0.5, got %f", score.Score)
	}
	if score.Confidence != "unknown" {
		t.Errorf("expected confidence 'unknown', got '%s'", score.Confidence)
	}
	if score.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", score.TotalFindings)
	}
}

func TestScoreTemplate_HighConfidence(t *testing.T) {
	store := NewFeedbackStore("", 3)

	// Add 5 TP, 0 FP
	for i := 0; i < 5; i++ {
		store.MarkFeedback("good-template", "host"+string(rune('a'+i)), "matcher1", "xss", FeedbackTruePositive, "", "")
	}

	score := ScoreTemplate(store, "good-template")

	if score.TPCount != 5 {
		t.Errorf("expected 5 TP, got %d", score.TPCount)
	}
	if score.FPCount != 0 {
		t.Errorf("expected 0 FP, got %d", score.FPCount)
	}
	if score.FPRate != 0 {
		t.Errorf("expected 0 FP rate, got %f", score.FPRate)
	}
	if score.Confidence != "high" {
		t.Errorf("expected confidence 'high', got '%s'", score.Confidence)
	}
	if score.Score < 0.9 {
		t.Errorf("expected high score >= 0.9, got %f", score.Score)
	}
}

func TestScoreTemplate_LowConfidence(t *testing.T) {
	store := NewFeedbackStoreWithDistinctHosts("", 3, 10) // high distinct threshold so it won't auto-suppress

	// Add 1 TP, 4 FP from 2 distinct hosts → 80% FP rate, below suppression threshold
	store.MarkFeedback("bad-template", "host1.com", "m1", "xss", FeedbackTruePositive, "", "")
	store.MarkFeedback("bad-template", "host2.com", "m1", "xss", FeedbackFalsePositive, "", "")
	store.MarkFeedback("bad-template", "host2.com", "m1", "xss", FeedbackFalsePositive, "", "")
	store.MarkFeedback("bad-template", "host3.com", "m1", "xss", FeedbackFalsePositive, "", "")
	store.MarkFeedback("bad-template", "host3.com", "m1", "xss", FeedbackFalsePositive, "", "")

	score := ScoreTemplate(store, "bad-template")

	if score.FPRate < 0.5 {
		t.Errorf("expected FP rate >= 0.5, got %f", score.FPRate)
	}
	if score.Confidence != "low" {
		t.Errorf("expected confidence 'low', got '%s'", score.Confidence)
	}
	if score.Score > 0.3 {
		t.Errorf("expected low score <= 0.3, got %f", score.Score)
	}
}

func TestScoreTemplate_Suppressed(t *testing.T) {
	store := NewFeedbackStore("", 3)

	// Add FPs from 3 distinct hosts to trigger auto-suppression
	store.MarkFeedback("auto-supp", "h1.com", "m1", "xss", FeedbackFalsePositive, "", "")
	store.MarkFeedback("auto-supp", "h2.com", "m1", "xss", FeedbackFalsePositive, "", "")
	store.MarkFeedback("auto-supp", "h3.com", "m1", "xss", FeedbackFalsePositive, "", "")

	score := ScoreTemplate(store, "auto-supp")

	if !score.Suppressed {
		t.Error("expected template to be suppressed")
	}
	if score.Confidence != "suppressed" {
		t.Errorf("expected confidence 'suppressed', got '%s'", score.Confidence)
	}
}

func TestScoreTemplate_MediumConfidence(t *testing.T) {
	store := NewFeedbackStore("", 3)

	// Add 5 TP, 2 FP → ~29% FP rate
	for i := 0; i < 5; i++ {
		store.MarkFeedback("med-template", "h"+string(rune('a'+i)), "m1", "xss", FeedbackTruePositive, "", "")
	}
	store.MarkFeedback("med-template", "h6", "m1", "xss", FeedbackFalsePositive, "", "")
	store.MarkFeedback("med-template", "h7", "m1", "xss", FeedbackFalsePositive, "", "")

	score := ScoreTemplate(store, "med-template")

	if score.FPRate < 0.2 || score.FPRate >= 0.5 {
		t.Errorf("expected FP rate 0.2-0.5, got %f", score.FPRate)
	}
	if score.Confidence != "medium" {
		t.Errorf("expected confidence 'medium', got '%s'", score.Confidence)
	}
}

func TestScoreAllTemplates(t *testing.T) {
	store := NewFeedbackStore("", 3)

	// Good template
	for i := 0; i < 5; i++ {
		store.MarkFeedback("good", "h"+string(rune('a'+i)), "m", "xss", FeedbackTruePositive, "", "")
	}

	// Bad template — 3 FPs from distinct hosts to trigger auto-suppression
	store.MarkFeedback("bad", "h1.com", "m", "xss", FeedbackFalsePositive, "", "")
	store.MarkFeedback("bad", "h2.com", "m", "xss", FeedbackFalsePositive, "", "")
	store.MarkFeedback("bad", "h3.com", "m", "xss", FeedbackFalsePositive, "", "")

	report := ScoreAllTemplates(store)

	if report.TotalTemplates != 2 {
		t.Errorf("expected 2 templates, got %d", report.TotalTemplates)
	}
	if report.HighConfidence != 1 {
		t.Errorf("expected 1 high confidence, got %d", report.HighConfidence)
	}
	if report.Suppressed != 1 {
		t.Errorf("expected 1 suppressed, got %d", report.Suppressed)
	}

	if len(report.TopTemplates) == 0 {
		t.Error("expected non-empty top templates")
	}
	if report.TopTemplates[0].TemplateID != "good" {
		t.Errorf("expected top template 'good', got '%s'", report.TopTemplates[0].TemplateID)
	}
}

func TestQualityFilter_ShouldReport(t *testing.T) {
	store := NewFeedbackStore("", 3)

	// Good template — lots of TPs
	for i := 0; i < 5; i++ {
		store.MarkFeedback("good-tmpl", "h"+string(rune('a'+i)), "m", "xss", FeedbackTruePositive, "", "")
	}

	// Bad template — auto-suppressed (3 FPs from distinct hosts)
	store.MarkFeedback("bad-tmpl", "h1.com", "m", "xss", FeedbackFalsePositive, "", "")
	store.MarkFeedback("bad-tmpl", "h2.com", "m", "xss", FeedbackFalsePositive, "", "")
	store.MarkFeedback("bad-tmpl", "h3.com", "m", "xss", FeedbackFalsePositive, "", "")

	qf := NewQualityFilter(store, 0.5)

	// Good template should pass
	shouldReport, reason := qf.ShouldReport("good-tmpl", "host", "m", "xss")
	if !shouldReport {
		t.Errorf("expected good template to pass, but rejected: %s", reason)
	}

	// Bad template should be suppressed
	shouldReport, reason = qf.ShouldReport("bad-tmpl", "host", "m", "xss")
	if shouldReport {
		t.Error("expected bad template to be suppressed, but it passed")
	}
	if reason == "" {
		t.Error("expected non-empty suppression reason")
	}

	// Unknown template should pass (no data)
	shouldReport, _ = qf.ShouldReport("unknown-tmpl", "host", "m", "xss")
	if !shouldReport {
		t.Error("expected unknown template to pass (no data)")
	}
}

func TestQualityFilter_NilStore(t *testing.T) {
	qf := NewQualityFilter(nil, 0.5)

	shouldReport, _ := qf.ShouldReport("test", "host", "m", "xss")
	if !shouldReport {
		t.Error("expected nil store to pass all findings")
	}
}

func TestQualityFilter_SetMinScore(t *testing.T) {
	store := NewFeedbackStore("", 3)

	// Template with 3 TP, 1 FP → score ~0.25
	store.MarkFeedback("test", "h1", "m", "xss", FeedbackTruePositive, "", "")
	store.MarkFeedback("test", "h2", "m", "xss", FeedbackTruePositive, "", "")
	store.MarkFeedback("test", "h3", "m", "xss", FeedbackTruePositive, "", "")
	store.MarkFeedback("test", "h4", "m", "xss", FeedbackFalsePositive, "", "")

	qf := NewQualityFilter(store, 0.5)

	// With min 0.5, should be rejected
	shouldReport, _ := qf.ShouldReport("test", "host", "m", "xss")
	if shouldReport {
		t.Error("expected rejection with min score 0.5")
	}

	// Lower threshold to 0.1
	qf.SetMinScore(0.1)
	shouldReport, _ = qf.ShouldReport("test", "host", "m", "xss")
	if !shouldReport {
		t.Error("expected pass with min score 0.1")
	}
}

func TestScoreTemplate_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "feedback.json")

	store := NewFeedbackStore(path, 3)

	// Add data
	for i := 0; i < 5; i++ {
		store.MarkFeedback("persist-test", "h"+string(rune('a'+i)), "m", "xss", FeedbackTruePositive, "", "")
	}

	// Save
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load into new store
	store2 := NewFeedbackStore(path, 3)
	if err := store2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	score := ScoreTemplate(store2, "persist-test")
	if score.TPCount != 5 {
		t.Errorf("expected 5 TP after load, got %d", score.TPCount)
	}
	if score.Confidence != "high" {
		t.Errorf("expected 'high' confidence after load, got '%s'", score.Confidence)
	}

	// Cleanup
	os.Remove(path)
}
