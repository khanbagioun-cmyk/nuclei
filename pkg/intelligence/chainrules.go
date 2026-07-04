package intelligence

import (
	"strings"
)

// ChainRule defines which template tags to run based on detected tech
type ChainRule struct {
	Name         string   // rule name (e.g., "wordpress")
	MatchTech    []string // techs that trigger this rule (any match)
	MatchCMS     string   // CMS that triggers this rule (exact match)
	MatchService string   // service that triggers this rule (e.g., "ssh")
	MatchPort    int      // port that triggers this rule (0 = any)
	TriggerTags  []string // template tags to run when this rule matches
	Priority     int      // higher = more important (e.g., critical CVEs first)
}

// DefaultChainRules maps detected technologies to relevant template tags.
// When a tech is detected, only templates with these tags will be run,
// skipping potentially thousands of irrelevant templates.
var DefaultChainRules = []ChainRule{
	// === CMS ===
	{
		Name: "wordpress", MatchCMS: "wordpress",
		MatchTech: []string{"wordpress"},
		TriggerTags: []string{"wordpress", "wp-plugin", "wp-theme", "wp", "cms", "exposure"},
		Priority: 9,
	},
	{
		Name: "joomla", MatchCMS: "joomla",
		MatchTech: []string{"joomla"},
		TriggerTags: []string{"joomla", "cms", "exposure"},
		Priority: 8,
	},
	{
		Name: "drupal", MatchCMS: "drupal",
		MatchTech: []string{"drupal"},
		TriggerTags: []string{"drupal", "cms", "exposure"},
		Priority: 8,
	},
	{
		Name: "magento", MatchCMS: "magento",
		MatchTech: []string{"magento"},
		TriggerTags: []string{"magento", "ecommerce", "exposure"},
		Priority: 8,
	},

	// === Web Servers ===
	{
		Name: "apache", MatchTech: []string{"apache"},
		TriggerTags: []string{"apache", "http", "exposure"},
		Priority: 5,
	},
	{
		Name: "nginx", MatchTech: []string{"nginx"},
		TriggerTags: []string{"nginx", "http", "exposure"},
		Priority: 5,
	},
	{
		Name: "iis", MatchTech: []string{"iis", "microsoft-iis"},
		TriggerTags: []string{"iis", "microsoft", "windows", "exposure"},
		Priority: 6,
	},

	// === Languages/Frameworks ===
	{
		Name: "php", MatchTech: []string{"php"},
		TriggerTags: []string{"php", "exposure"},
		Priority: 4,
	},
	{
		Name: "aspnet", MatchTech: []string{"asp.net", "aspnet"},
		TriggerTags: []string{"asp", "aspnet", "iis", "windows", "exposure"},
		Priority: 6,
	},
	{
		Name: "tomcat", MatchTech: []string{"tomcat"},
		TriggerTags: []string{"tomcat", "java", "exposure"},
		Priority: 7,
	},
	{
		Name: "jboss", MatchTech: []string{"jboss"},
		TriggerTags: []string{"jboss", "java", "exposure"},
		Priority: 7,
	},
	{
		Name: "spring", MatchTech: []string{"spring", "spring-boot"},
		TriggerTags: []string{"spring", "java", "exposure"},
		Priority: 8,
	},
	{
		Name: "nodejs", MatchTech: []string{"node.js", "nodejs", "express"},
		TriggerTags: []string{"node", "nodejs", "express", "exposure"},
		Priority: 5,
	},
	{
		Name: "ruby", MatchTech: []string{"ruby", "rails", "ruby-on-rails"},
		TriggerTags: []string{"ruby", "rails", "exposure"},
		Priority: 6,
	},
	{
		Name: "python", MatchTech: []string{"python", "django", "flask"},
		TriggerTags: []string{"python", "django", "flask", "exposure"},
		Priority: 5,
	},

	// === Services ===
	{
		Name: "ssh", MatchService: "ssh",
		TriggerTags: []string{"ssh", "exposure"},
		Priority: 4,
	},
	{
		Name: "ftp", MatchService: "ftp",
		TriggerTags: []string{"ftp", "exposure"},
		Priority: 5,
	},
	{
		Name: "redis", MatchService: "redis", MatchPort: 6379,
		TriggerTags: []string{"redis", "exposure"},
		Priority: 8,
	},
	{
		Name: "mongodb", MatchService: "mongodb", MatchPort: 27017,
		TriggerTags: []string{"mongodb", "mongo", "exposure"},
		Priority: 8,
	},
	{
		Name: "mysql", MatchService: "mysql", MatchPort: 3306,
		TriggerTags: []string{"mysql", "exposure"},
		Priority: 7,
	},
	{
		Name: "postgresql", MatchService: "postgresql", MatchPort: 5432,
		TriggerTags: []string{"postgres", "postgresql", "exposure"},
		Priority: 7,
	},
	{
		Name: "elasticsearch", MatchService: "elasticsearch", MatchPort: 9200,
		TriggerTags: []string{"elasticsearch", "elastic", "exposure"},
		Priority: 8,
	},
	{
		Name: "memcached", MatchService: "memcached", MatchPort: 11211,
		TriggerTags: []string{"memcached", "exposure"},
		Priority: 7,
	},
	{
		Name: "docker", MatchService: "docker", MatchPort: 2375,
		TriggerTags: []string{"docker", "exposure"},
		Priority: 9,
	},
	{
		Name: "kubernetes", MatchService: "k8s-api", MatchPort: 6443,
		TriggerTags: []string{"kubernetes", "k8s", "exposure"},
		Priority: 9,
	},

	// === Cloud ===
	{
		Name: "s3-bucket", MatchTech: []string{"s3", "amazon-s3"},
		TriggerTags: []string{"s3", "aws", "cloud", "exposure"},
		Priority: 7,
	},

	// === Generic (always run if we found a web app) ===
	{
		Name: "web-generic", MatchTech: []string{"http", "https"},
		TriggerTags: []string{"exposure", "config", "misconfig"},
		Priority: 1,
	},
}

// ChainEngine evaluates chain rules against tech profiles
type ChainEngine struct {
	rules []ChainRule
}

// NewChainEngine creates a chain engine with default rules
func NewChainEngine(rules []ChainRule) *ChainEngine {
	if rules == nil {
		rules = DefaultChainRules
	}
	return &ChainEngine{rules: rules}
}

// MatchedRule holds a rule that matched and its triggered tags
type MatchedRule struct {
	Rule       ChainRule
	TriggerTags []string
}

// Evaluate checks all rules against a TechProfile and returns matched rules
func (ce *ChainEngine) Evaluate(profile *TechProfile) []MatchedRule {
	snap := profile.Snapshot()
	return ce.EvaluateSnapshot(snap)
}

// EvaluateSnapshot works on a snapshot (no locks needed)
func (ce *ChainEngine) EvaluateSnapshot(snap TechProfileSnapshot) []MatchedRule {
	var matched []MatchedRule
	techSet := make(map[string]bool)
	for _, t := range snap.Technologies {
		techSet[strings.ToLower(t)] = true
	}
	for _, rule := range ce.rules {
		if ce.ruleMatchesSnapshot(rule, snap, techSet) {
			matched = append(matched, MatchedRule{Rule: rule, TriggerTags: rule.TriggerTags})
		}
	}
	return matched
}

func (ce *ChainEngine) ruleMatchesSnapshot(rule ChainRule, snap TechProfileSnapshot, techSet map[string]bool) bool {
	// Check tech match
	if len(rule.MatchTech) > 0 {
		for _, tech := range rule.MatchTech {
			if techSet[strings.ToLower(tech)] {
				return true
			}
		}
	}

	// Check CMS match
	if rule.MatchCMS != "" && strings.EqualFold(snap.CMS, rule.MatchCMS) {
		return true
	}

	// Check service match (with optional port constraint)
	if rule.MatchService != "" {
		for _, svc := range snap.Services {
			if strings.EqualFold(svc.Name, rule.MatchService) {
				if rule.MatchPort == 0 || svc.Port == rule.MatchPort {
					return true
				}
			}
		}
	}

	// Check port match alone (when MatchService is set, also try port-only match)
	if rule.MatchPort > 0 {
		for _, port := range snap.OpenPorts {
			if port == rule.MatchPort {
				return true
			}
		}
	}

	return false
}

// GetTriggerTags returns all unique tags that should be run for a profile
func (ce *ChainEngine) GetTriggerTags(profile *TechProfile) []string {
	matched := ce.Evaluate(profile)
	tagSet := make(map[string]bool)
	for _, m := range matched {
		for _, tag := range m.TriggerTags {
			tagSet[tag] = true
		}
	}
	var tags []string
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	return tags
}

// GetTriggerTagsFromSnapshot returns all unique tags for a snapshot
func (ce *ChainEngine) GetTriggerTagsFromSnapshot(snap TechProfileSnapshot) []string {
	matched := ce.EvaluateSnapshot(snap)
	tagSet := make(map[string]bool)
	for _, m := range matched {
		for _, tag := range m.TriggerTags {
			tagSet[tag] = true
		}
	}
	var tags []string
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	return tags
}

// ShouldRunTemplate decides if a template should run based on its tags and the profile
// Returns true if the template's tags intersect with the triggered tags
func (ce *ChainEngine) ShouldRunTemplate(templateTags []string, profile *TechProfile) bool {
	if len(templateTags) == 0 {
		return true // templates with no tags always run
	}

	triggerTags := ce.GetTriggerTags(profile)
	triggerSet := make(map[string]bool)
	for _, t := range triggerTags {
		triggerSet[strings.ToLower(t)] = true
	}

	for _, tag := range templateTags {
		if triggerSet[strings.ToLower(tag)] {
			return true
		}
	}

	return false
}

// FilterStats holds statistics about template filtering
type FilterStats struct {
	TotalTemplates    int
	SelectedTemplates int
	SkippedTemplates  int
	TriggerTags       []string
	MatchedRules      int
}

// FilterTemplates filters a list of template tag lists based on the profile
// Returns the indices of templates that should run
func (ce *ChainEngine) FilterTemplates(templateTags [][]string, profile *TechProfile) (selected []int, stats FilterStats) {
	triggerTags := ce.GetTriggerTags(profile)
	triggerSet := make(map[string]bool)
	for _, t := range triggerTags {
		triggerSet[strings.ToLower(t)] = true
	}

	matched := ce.Evaluate(profile)
	stats = FilterStats{
		TotalTemplates: len(templateTags),
		TriggerTags:    triggerTags,
		MatchedRules:   len(matched),
	}

	for i, tags := range templateTags {
		if len(tags) == 0 {
			selected = append(selected, i)
			stats.SelectedTemplates++
			continue
		}
		shouldRun := false
		for _, tag := range tags {
			if triggerSet[strings.ToLower(tag)] {
				shouldRun = true
				break
			}
		}
		if shouldRun {
			selected = append(selected, i)
			stats.SelectedTemplates++
		} else {
			stats.SkippedTemplates++
		}
	}

	return selected, stats
}
