package matchers

import (
	"testing"
)

func TestGetScope(t *testing.T) {
	tests := []struct {
		input    string
		expected ScopeType
	}{
		{"", ScopeAll},
		{"all", ScopeAll},
		{"final-only", ScopeFinalOnly},
		{"redirects-only", ScopeRedirectsOnly},
		{"invalid", ScopeAll},
	}
	for _, tt := range tests {
		m := &Matcher{Scope: tt.input}
		if got := m.GetScope(); got != tt.expected {
			t.Errorf("GetScope(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestGetConfidence(t *testing.T) {
	tests := []struct {
		input    string
		expected ConfidenceType
	}{
		{"", ConfidenceMedium},
		{"low", ConfidenceLow},
		{"medium", ConfidenceMedium},
		{"high", ConfidenceHigh},
		{"invalid", ConfidenceMedium},
	}
	for _, tt := range tests {
		m := &Matcher{Confidence: tt.input}
		if got := m.GetConfidence(); got != tt.expected {
			t.Errorf("GetConfidence(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestAppliesToRedirect(t *testing.T) {
	tests := []struct {
		scope   string
		isFinal bool
		expected bool
	}{
		{"all", true, true},
		{"all", false, true},
		{"final-only", true, true},
		{"final-only", false, false},
		{"redirects-only", true, false},
		{"redirects-only", false, true},
		{"", true, true},
		{"", false, true},
	}
	for _, tt := range tests {
		m := &Matcher{Scope: tt.scope}
		if got := m.AppliesToRedirect(tt.isFinal); got != tt.expected {
			t.Errorf("AppliesToRedirect(scope=%q, isFinal=%v) = %v, want %v", tt.scope, tt.isFinal, got, tt.expected)
		}
	}
}
