package templatelearn

import (
	"testing"
	"fmt"
)

func TestDebugScores(t *testing.T) {
	store := NewFeedbackStore("", 3)

	for i := 0; i < 5; i++ {
		store.MarkFeedback("good", "h"+string(rune('a'+i)), "m", "xss", FeedbackTruePositive, "", "")
	}

	store.MarkFeedback("bad", "h1", "m", "xss", FeedbackFalsePositive, "", "")
	store.MarkFeedback("bad", "h1", "m", "xss", FeedbackFalsePositive, "", "")
	store.MarkFeedback("bad", "h1", "m", "xss", FeedbackFalsePositive, "", "")

	goodScore := ScoreTemplate(store, "good")
	badScore := ScoreTemplate(store, "bad")
	
	fmt.Printf("GOOD: score=%f, TP=%d, FP=%d, total=%d, conf=%s, supp=%v\n",
		goodScore.Score, goodScore.TPCount, goodScore.FPCount, goodScore.TotalFindings, goodScore.Confidence, goodScore.Suppressed)
	fmt.Printf("BAD:  score=%f, TP=%d, FP=%d, total=%d, conf=%s, supp=%v\n",
		badScore.Score, badScore.TPCount, badScore.FPCount, badScore.TotalFindings, badScore.Confidence, badScore.Suppressed)
}
