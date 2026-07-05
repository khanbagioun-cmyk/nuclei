package correlation

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	stringslice "github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func makeFinding(templateID, host string, tags []string, sev severity.Severity) *output.ResultEvent {
	return &output.ResultEvent{
		TemplateID: templateID,
		Host:       host,
		Info: model.Info{
			Name:           "test",
			Tags:           stringslice.StringSlice{Value: tags},
			SeverityHolder: severity.Holder{Severity: sev},
		},
	}
}

func TestCorrelate_TechToCVE(t *testing.T) {
	engine := NewEngine()

	findings := []*output.ResultEvent{
		makeFinding("tech-detect", "example.com", []string{"tech", "wordpress"}, severity.Low),
		makeFinding("CVE-2024-1234", "example.com", []string{"cve", "wordpress"}, severity.High),
		makeFinding("CVE-2024-5678", "other.com", []string{"cve", "apache"}, severity.Critical),
	}

	result := engine.Correlate(findings)

	if len(result.Links) == 0 {
		t.Fatal("expected at least 1 correlation link")
	}

	found := false
	for _, link := range result.Links {
		if link.SourceTemplateID == "tech-detect" && link.TargetTemplateID == "CVE-2024-1234" {
			found = true
		}
	}
	if !found {
		t.Error("expected tech-detect → CVE-2024-1234 correlation")
	}

	if result.Boosted == 0 {
		t.Error("expected at least 1 boosted finding")
	}
}

func TestCorrelate_NoCrossHost(t *testing.T) {
	engine := NewEngine()

	findings := []*output.ResultEvent{
		makeFinding("tech-detect", "host1.com", []string{"tech"}, severity.Low),
		makeFinding("CVE-2024-1234", "host2.com", []string{"cve"}, severity.High),
	}

	result := engine.Correlate(findings)

	if len(result.Links) != 0 {
		t.Errorf("expected 0 cross-host correlations, got %d", len(result.Links))
	}
}

func TestCorrelate_ExposureToExploit(t *testing.T) {
	engine := NewEngine()

	findings := []*output.ResultEvent{
		makeFinding("exposed-db", "example.com", []string{"exposure"}, severity.High),
		makeFinding("exploit-db", "example.com", []string{"exploit"}, severity.Critical),
	}

	result := engine.Correlate(findings)

	found := false
	for _, link := range result.Links {
		if link.RuleID == "exposure-to-exploit" {
			found = true
		}
	}
	if !found {
		t.Error("expected exposure-to-exploit correlation")
	}
}

func TestCorrelate_DefaultLoginToAuth(t *testing.T) {
	engine := NewEngine()

	findings := []*output.ResultEvent{
		makeFinding("default-login-tomcat", "example.com", []string{"default-login"}, severity.High),
		makeFinding("auth-bypass", "example.com", []string{"auth"}, severity.Critical),
	}

	result := engine.Correlate(findings)

	found := false
	for _, link := range result.Links {
		if link.RuleID == "default-login-to-auth-bypass" {
			found = true
		}
	}
	if !found {
		t.Error("expected default-login-to-auth-bypass correlation")
	}
}

func TestCorrelate_SelfCorrelation(t *testing.T) {
	engine := NewEngine()

	// Same finding matches both source and target — should not correlate with itself
	f := makeFinding("dual-template", "example.com", []string{"tech", "cve"}, severity.High)
	findings := []*output.ResultEvent{f}

	result := engine.Correlate(findings)

	for _, link := range result.Links {
		if link.SourceTemplateID == link.TargetTemplateID {
			t.Errorf("found self-correlation: %s -> %s", link.SourceTemplateID, link.TargetTemplateID)
		}
	}
}

func TestAddRule(t *testing.T) {
	engine := NewEngine()
	before := len(engine.rules)

	engine.AddRule(CorrelationRule{
		ID:     "custom",
		Name:   "custom rule",
		Source: FindingMatch{Tag: "xss"},
		Target: FindingMatch{Tag: "sqli"},
		Action: ActionLink,
	})

	if len(engine.rules) != before+1 {
		t.Errorf("expected %d rules, got %d", before+1, len(engine.rules))
	}
}

func TestSummary(t *testing.T) {
	r := CorrelationResult{
		Links:   []FindingLink{{}},
		Boosted: 3,
		Deduped: 1,
	}
	s := r.Summary()
	if !strings.Contains(s, "1 links") || !strings.Contains(s, "3 boosted") || !strings.Contains(s, "1 deduped") {
		t.Errorf("unexpected summary: %s", s)
	}
}
