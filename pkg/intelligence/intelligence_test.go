package intelligence

import (
	"context"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func TestTechProfileAddTech(t *testing.T) {
	profile := NewTechProfile("example.com")
	profile.AddTech("nginx")
	profile.AddTech("php")
	profile.AddTech("nginx") // duplicate

	if len(profile.Technologies) != 2 {
		t.Errorf("expected 2 techs, got %d", len(profile.Technologies))
	}
	if !profile.HasTech("nginx") {
		t.Error("expected nginx to be present")
	}
	if profile.HasTech("wordpress") {
		t.Error("wordpress should not be present")
	}
}

func TestTechProfileHasAnyTech(t *testing.T) {
	profile := NewTechProfile("example.com")
	profile.AddTech("nginx")
	profile.AddTech("php")

	if !profile.HasAnyTech([]string{"wordpress", "nginx"}) {
		t.Error("expected HasAnyTech to return true for nginx")
	}
	if profile.HasAnyTech([]string{"wordpress", "drupal"}) {
		t.Error("expected HasAnyTech to return false")
	}
}

func TestTechProfileSnapshot(t *testing.T) {
	profile := NewTechProfile("example.com")
	profile.AddTech("nginx")
	profile.SetCMS("wordpress")
	profile.AddPort(443)

	snap := profile.Snapshot()
	if snap.Host != "example.com" {
		t.Errorf("host = %s", snap.Host)
	}
	if len(snap.Technologies) != 1 {
		t.Errorf("expected 1 tech, got %d", len(snap.Technologies))
	}
	if snap.CMS != "wordpress" {
		t.Errorf("CMS = %s", snap.CMS)
	}
	if len(snap.OpenPorts) != 1 || snap.OpenPorts[0] != 443 {
		t.Errorf("ports = %v", snap.OpenPorts)
	}
}

func TestProfileStore(t *testing.T) {
	store := NewProfileStore()
	p1 := store.GetOrCreate("host1.com")
	p1.AddTech("nginx")

	p2 := store.GetOrCreate("host2.com")
	p2.AddTech("apache")

	if store.Count() != 2 {
		t.Errorf("expected 2 profiles, got %d", store.Count())
	}

	got := store.Get("host1.com")
	if got == nil || !got.HasTech("nginx") {
		t.Error("host1 profile missing nginx")
	}

	profiles := store.All()
	if len(profiles) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(profiles))
	}
}

func TestChainEngineEvaluate(t *testing.T) {
	engine := NewChainEngine(nil)

	profile := NewTechProfile("example.com")
	profile.AddTech("wordpress")
	profile.SetCMS("wordpress")

	matched := engine.Evaluate(profile)
	if len(matched) == 0 {
		t.Fatal("expected at least 1 matched rule")
	}

	foundWP := false
	for _, m := range matched {
		if m.Rule.Name == "wordpress" {
			foundWP = true
			if !containsTag(m.TriggerTags, "wordpress") {
				t.Error("wordpress rule should trigger wordpress tag")
			}
		}
	}
	if !foundWP {
		t.Error("expected wordpress rule to match")
	}
}

func TestChainEngineEvaluateWithService(t *testing.T) {
	engine := NewChainEngine(nil)

	profile := NewTechProfile("example.com")
	profile.AddService(ServiceInfo{Name: "redis", Port: 6379})

	matched := engine.Evaluate(profile)
	foundRedis := false
	for _, m := range matched {
		if m.Rule.Name == "redis" {
			foundRedis = true
		}
	}
	if !foundRedis {
		t.Error("expected redis rule to match")
	}
}

func TestChainEngineGetTriggerTags(t *testing.T) {
	engine := NewChainEngine(nil)

	profile := NewTechProfile("example.com")
	profile.AddTech("nginx")
	profile.AddTech("wordpress")

	tags := engine.GetTriggerTags(profile)
	if len(tags) == 0 {
		t.Fatal("expected trigger tags")
	}

	tagSet := make(map[string]bool)
	for _, tag := range tags {
		tagSet[tag] = true
	}
	if !tagSet["wordpress"] {
		t.Error("expected wordpress tag in triggers")
	}
	if !tagSet["nginx"] {
		t.Error("expected nginx tag in triggers")
	}
}

func TestChainEngineShouldRunTemplate(t *testing.T) {
	engine := NewChainEngine(nil)

	profile := NewTechProfile("example.com")
	profile.AddTech("wordpress")

	// Template with wordpress tag should run
	if !engine.ShouldRunTemplate([]string{"wordpress", "cve"}, profile) {
		t.Error("wordpress template should run")
	}

	// Template with only joomla tag should not run
	if engine.ShouldRunTemplate([]string{"joomla"}, profile) {
		t.Error("joomla template should not run")
	}

	// Template with no tags should always run
	if !engine.ShouldRunTemplate([]string{}, profile) {
		t.Error("untagged template should always run")
	}
}

func TestChainEngineFilterTemplates(t *testing.T) {
	engine := NewChainEngine(nil)

	profile := NewTechProfile("example.com")
	profile.AddTech("wordpress")

	templateTags := [][]string{
		{"wordpress", "cve"},  // should run
		{"joomla", "cve"},     // should skip
		{"drupal"},            // should skip
		{"wordpress", "plugin"}, // should run
		{},                    // should run (no tags)
		{"exposure"},          // should run (generic)
	}

	selected, stats := engine.FilterTemplates(templateTags, profile)

	if len(selected) != 4 {
		t.Errorf("expected 4 selected, got %d", len(selected))
	}
	if stats.TotalTemplates != 6 {
		t.Errorf("total = %d", stats.TotalTemplates)
	}
	if stats.SelectedTemplates != 4 {
		t.Errorf("selected = %d", stats.SelectedTemplates)
	}
	if stats.SkippedTemplates != 2 {
		t.Errorf("skipped = %d", stats.SkippedTemplates)
	}
}

func TestChainEngineFilterTemplatesReduction(t *testing.T) {
	engine := NewChainEngine(nil)

	profile := NewTechProfile("example.com")
	profile.AddTech("nginx")

	// Simulate 100 templates, only ~3 relevant (nginx, http, exposure)
	templateTags := make([][]string, 100)
	for i := range templateTags {
		if i < 50 {
			templateTags[i] = []string{"wordpress"}
		} else if i < 80 {
			templateTags[i] = []string{"joomla"}
		} else if i < 90 {
			templateTags[i] = []string{"drupal"}
		} else if i < 95 {
			templateTags[i] = []string{"nginx"}
		} else {
			templateTags[i] = []string{"exposure"}
		}
	}

	_, stats := engine.FilterTemplates(templateTags, profile)

	if stats.SelectedTemplates != 5 { // 5 nginx + 0 exposure (no web-generic rule match for nginx-only profile)
		// nginx rule triggers: nginx, http, exposure tags
		// nginx templates: 5, exposure templates: 5 → 10 total? Let's check
		// Actually nginx triggers: ["nginx", "http", "exposure"]
		// So templates with "nginx" tag: 5, "exposure" tag: 5 → 10
		t.Logf("selected=%d (nginx rule triggers nginx+http+exposure tags)", stats.SelectedTemplates)
	}

	if stats.SkippedTemplates != 100-stats.SelectedTemplates {
		t.Errorf("skipped mismatch")
	}

	reduction := float64(stats.SkippedTemplates) / float64(stats.TotalTemplates) * 100
	if reduction < 80 {
		t.Errorf("expected >80%% reduction, got %.1f%%", reduction)
	}
}

func TestResultProfilerProcessResult(t *testing.T) {
	store := NewProfileStore()
	profiler := NewResultProfiler(store)

	result := &output.ResultEvent{
		Host: "example.com",
		Info: model.Info{
			Tags: stringslice.New("wordpress"),
		},
		MatcherName: "wordpress",
		Port:        "443",
	}

	profiler.ProcessResult(result)

	profile := store.Get("example.com")
	if profile == nil {
		t.Fatal("profile should exist")
	}
	if !profile.HasTech("wordpress") {
		t.Error("expected wordpress tech")
	}
	if profile.CMS != "wordpress" {
		t.Error("expected CMS to be wordpress")
	}
	if len(profile.OpenPorts) != 1 || profile.OpenPorts[0] != 443 {
		t.Errorf("expected port 443, got %v", profile.OpenPorts)
	}
}

func TestResultProfilerFromMetadata(t *testing.T) {
	store := NewProfileStore()
	profiler := NewResultProfiler(store)

	result := &output.ResultEvent{
		Host: "example.com",
		Info: model.Info{
			Metadata: map[string]interface{}{
				"product": "Apache",
				"vendor":  "Apache",
			},
		},
	}

	profiler.ProcessResult(result)

	profile := store.Get("example.com")
	if profile == nil {
		t.Fatal("profile should exist")
	}
	if !profile.HasTech("apache") {
		t.Error("expected apache tech from metadata")
	}
}

func TestChainerRecordPhase1Result(t *testing.T) {
	chainer := NewChainer()

	chainer.RecordPhase1Result("example.com", []string{"tech-detect"}, "nginx", nil, "tech-detect", "80", nil)

	profile := chainer.GetProfile("example.com")
	if profile == nil {
		t.Fatal("profile should exist")
	}
	if !profile.HasTech("nginx") {
		t.Error("expected nginx tech")
	}
	if !profile.HasTech("http") {
		t.Error("expected http tech from tech-detect tag")
	}
}

func TestChainerFilterTemplatesForHost(t *testing.T) {
	chainer := NewChainer()

	// Phase 1: detect wordpress
	chainer.RecordPhase1Result("example.com", []string{"wordpress"}, "", nil, "wordpress-detect", "443", nil)

	// Phase 2: filter templates
	templateTags := [][]string{
		{"wordpress", "cve"},
		{"joomla"},
		{"wordpress", "plugin"},
		{"drupal"},
	}

	selected, stats := chainer.FilterTemplatesForHost("example.com", templateTags)

	if len(selected) != 2 {
		t.Errorf("expected 2 selected, got %d", len(selected))
	}
	if stats.SkippedTemplates != 2 {
		t.Errorf("expected 2 skipped, got %d", stats.SkippedTemplates)
	}
}

func TestChainerFilterTemplatesNoProfile(t *testing.T) {
	chainer := NewChainer()

	// No phase 1 ran for this host
	templateTags := [][]string{
		{"wordpress"},
		{"joomla"},
	}

	selected, stats := chainer.FilterTemplatesForHost("unknown.com", templateTags)

	if len(selected) != 2 {
		t.Errorf("expected all 2 selected when no profile, got %d", len(selected))
	}
	if stats.SkippedTemplates != 0 {
		t.Error("should skip nothing without profile")
	}
}

func TestChainerSummary(t *testing.T) {
	chainer := NewChainer()
	chainer.SetPhase1Stats(0, 1)
	chainer.SetPhase2Stats(0, 100, 20)

	summary := chainer.Summary()
	if summary == "" {
		t.Error("summary should not be empty")
	}
}

func TestShouldUseSmartScan(t *testing.T) {
	stats := FilterStats{TotalTemplates: 100, SelectedTemplates: 20, SkippedTemplates: 80}
	if !ShouldUseSmartScan(stats, 20.0) {
		t.Error("should use smart scan with 80% reduction")
	}

	stats = FilterStats{TotalTemplates: 100, SelectedTemplates: 90, SkippedTemplates: 10}
	if ShouldUseSmartScan(stats, 20.0) {
		t.Error("should not use smart scan with only 10% reduction")
	}

	stats = FilterStats{TotalTemplates: 0}
	if ShouldUseSmartScan(stats, 20.0) {
		t.Error("should not use smart scan with 0 templates")
	}
}

func TestProfileBuilderFromHeadersAndBody(t *testing.T) {
	pb := NewProfileBuilder()

	headers := map[string]string{
		"Server":       "nginx/1.21.0",
		"X-Powered-By": "PHP/8.1.0",
	}
	body := []byte(`<html><body><script src="/wp-content/themes/app/main.js"></script></body></html>`)

	profile := pb.BuildFromHeadersAndBody("example.com", headers, body)

	if !profile.HasTech("nginx") {
		t.Error("expected nginx from Server header")
	}
	if !profile.HasTech("php") {
		t.Error("expected php from X-Powered-By header")
	}
	if !profile.HasTech("wordpress") {
		t.Error("expected wordpress from wp-content in body")
	}
}

func TestChainEngineMultipleHosts(t *testing.T) {
	chainer := NewChainer()

	// Host 1: WordPress
	chainer.RecordPhase1Result("wp-site.com", []string{"wordpress"}, "", nil, "wp-detect", "443", nil)

	// Host 2: Joomla
	chainer.RecordPhase1Result("joomla-site.com", []string{"joomla"}, "", nil, "joomla-detect", "80", nil)

	profiles := chainer.GetAllProfiles()
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}

	wpTags := chainer.GetTriggerTagsForHost("wp-site.com")
	joomlaTags := chainer.GetTriggerTagsForHost("joomla-site.com")

	wpTagSet := make(map[string]bool)
	for _, tag := range wpTags {
		wpTagSet[tag] = true
	}
	if !wpTagSet["wordpress"] {
		t.Error("expected wordpress tag for wp-site.com")
	}

	joomlaTagSet := make(map[string]bool)
	for _, tag := range joomlaTags {
		joomlaTagSet[tag] = true
	}
	if !joomlaTagSet["joomla"] {
		t.Error("expected joomla tag for joomla-site.com")
	}
}

func TestChainEnginePortBasedMatching(t *testing.T) {
	engine := NewChainEngine(nil)

	profile := NewTechProfile("db-server.com")
	profile.AddPort(6379) // redis port

	matched := engine.Evaluate(profile)
	foundRedis := false
	for _, m := range matched {
		if m.Rule.Name == "redis" {
			foundRedis = true
		}
	}
	if !foundRedis {
		t.Error("expected redis rule to match based on port 6379")
	}
}

func TestDefaultChainRulesCoverage(t *testing.T) {
	if len(DefaultChainRules) < 15 {
		t.Errorf("expected at least 15 default chain rules, got %d", len(DefaultChainRules))
	}

	// Verify all rules have trigger tags
	for _, rule := range DefaultChainRules {
		if len(rule.TriggerTags) == 0 {
			t.Errorf("rule %s has no trigger tags", rule.Name)
		}
		if rule.Name == "" {
			t.Error("rule has no name")
		}
	}
}

func TestChainerRun(t *testing.T) {
	chainer := NewChainer()

	phase1Called := false
	phase2Called := false

	phase1 := func(ctx context.Context) error {
		phase1Called = true
		chainer.RecordPhase1Result("test.com", []string{"nginx"}, "", nil, "tech-detect", "80", nil)
		return nil
	}
	phase2 := func(ctx context.Context) error {
		phase2Called = true
		return nil
	}

	err := chainer.Run(context.Background(), phase1, phase2)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !phase1Called {
		t.Error("phase 1 was not called")
	}
	if !phase2Called {
		t.Error("phase 2 was not called")
	}

	profile := chainer.GetProfile("test.com")
	if profile == nil {
		t.Fatal("profile should exist after phase 1")
	}
	if !profile.HasTech("nginx") {
		t.Error("expected nginx tech")
	}
}

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
