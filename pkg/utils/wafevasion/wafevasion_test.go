package wafevasion

import (
	"strings"
	"testing"
)

func TestCaseSwap(t *testing.T) {
	result := caseSwap("SELECT")
	if len(result) != 6 {
		t.Errorf("expected length 6, got %d", len(result))
	}
	lower := strings.ToLower(result)
	if lower != "select" {
		t.Errorf("case-insensitive mismatch: got %s", result)
	}
}

func TestURLHexEncode(t *testing.T) {
	result := urlHexEncode("a'b<c>")
	if !strings.Contains(result, "%27") {
		t.Errorf("expected %%27 for single quote, got %s", result)
	}
	if !strings.Contains(result, "%3c") {
		t.Errorf("expected %%3c for <, got %s", result)
	}
}

func TestSQLCommentInsert(t *testing.T) {
	result := sqlCommentInsert("UNION SELECT")
	if !strings.Contains(result, "/**/") {
		t.Errorf("expected /**/ in result, got %s", result)
	}
	// Comments split keywords: "UNION" -> "UN/**/ION" so "union" won't be contiguous
	lower := strings.ToLower(result)
	if !strings.Contains(lower, "un") || !strings.Contains(lower, "ion") {
		t.Errorf("expected keyword fragments in result, got %s", result)
	}
}

func TestWhitespaceReplace(t *testing.T) {
	result := whitespaceReplace("SELECT * FROM users")
	if strings.Contains(result, " ") {
		// May still contain spaces if + was chosen, but at least one alt should be present
	}
	if result == "SELECT * FROM users" {
		t.Errorf("expected whitespace replacement, got unchanged string")
	}
}

func TestGenerateSQLiVariants(t *testing.T) {
	variants := GenerateSQLiVariants("UNION SELECT")
	if len(variants) < 3 {
		t.Errorf("expected at least 3 variants, got %d", len(variants))
	}
	found := false
	for _, v := range variants {
		if strings.Contains(v, "/**/") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected at least one variant with /**/")
	}
}

func TestGenerateXSSVariants(t *testing.T) {
	variants := GenerateXSSVariants("<script>alert(1)</script>")
	if len(variants) < 3 {
		t.Errorf("expected at least 3 variants, got %d", len(variants))
	}
}

func TestGeneratePathTraversalVariants(t *testing.T) {
	variants := GeneratePathTraversalVariants("../../etc/passwd")
	if len(variants) < 3 {
		t.Errorf("expected at least 3 variants, got %d", len(variants))
	}
	found := false
	for _, v := range variants {
		if strings.Contains(v, "%2f") || strings.Contains(v, "%2e") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected at least one encoded variant")
	}
}

func TestTransformPayload(t *testing.T) {
	config := &EvasionConfig{
		Techniques:    []Technique{TechniqueCaseSwap},
		Randomize:     false,
		MaxTransforms: 1,
	}
	result := TransformPayload("test", config)
	if strings.ToLower(result) != "test" {
		t.Errorf("caseSwap should preserve chars: got %s", result)
	}
}

func TestEncodeHexBytes(t *testing.T) {
	result := EncodeHexBytes("admin")
	if !strings.HasPrefix(result, "0x") {
		t.Errorf("expected 0x prefix, got %s", result)
	}
}

func TestRandomUserAgent(t *testing.T) {
	ua := RandomUserAgent()
	if ua == "" {
		t.Error("expected non-empty user agent")
	}
}

func TestRandomXForwardedFor(t *testing.T) {
	xff := RandomXForwardedFor()
	parts := strings.Split(xff, ".")
	if len(parts) != 4 {
		t.Errorf("expected 4 octets, got %d", len(parts))
	}
}
