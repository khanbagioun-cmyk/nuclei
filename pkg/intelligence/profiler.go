package intelligence

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// ResultProfiler maps scan ResultEvents to TechProfiles
type ResultProfiler struct {
	store *ProfileStore
}

// NewResultProfiler creates a new ResultProfiler
func NewResultProfiler(store *ProfileStore) *ResultProfiler {
	return &ResultProfiler{store: store}
}

// ProcessResult inspects a ResultEvent and updates the TechProfile for the host
func (rp *ResultProfiler) ProcessResult(result *output.ResultEvent) {
	if result == nil || result.Host == "" {
		return
	}

	host := result.Host
	profile := rp.store.GetOrCreate(host)

	tags := result.Info.Tags.ToSlice()
	for _, tag := range tags {
		classifyTagDirect(profile, tag)
	}

	if result.Info.Metadata != nil {
		classifyMetadataDirect(profile, result.Info.Metadata)
	}

	if result.MatcherName != "" {
		classifyMatcherDirect(profile, result.MatcherName, result.ExtractedResults)
	}

	if result.TemplateID != "" {
		classifyTemplateIDDirect(profile, result.TemplateID)
	}

	if result.Port != "" {
		classifyPortDirect(profile, result.Port)
	}
}

// --- Direct (non-method) classification functions — shared between ResultProfiler and Chainer ---

func classifyTagDirect(profile *TechProfile, tag string) {
	tag = strings.ToLower(tag)

	techMap := map[string]string{
		"wordpress": "wordpress", "wp": "wordpress",
		"joomla":     "joomla",
		"drupal":     "drupal",
		"magento":    "magento",
		"apache":     "apache",
		"nginx":      "nginx",
		"iis":        "iis", "microsoft-iis": "iis",
		"php":        "php",
		"asp.net":    "asp.net", "aspnet": "asp.net",
		"tomcat":     "tomcat",
		"jboss":      "jboss",
		"spring":     "spring", "spring-boot": "spring-boot",
		"node.js":    "node.js", "nodejs": "node.js", "express": "express",
		"ruby":       "ruby", "rails": "ruby-on-rails",
		"python":     "python", "django": "django", "flask": "flask",
		"cloudflare":  "cloudflare",
		"s3":          "s3", "amazon-s3": "s3",
		"docker":      "docker",
		"kubernetes":  "kubernetes", "k8s": "kubernetes",
		"gitlab":      "gitlab",
		"jenkins":     "jenkins",
		"grafana":     "grafana",
		"kibana":      "kibana",
		"redis":       "redis",
		"mongodb":     "mongodb", "mongo": "mongodb",
		"mysql":       "mysql",
		"postgresql":  "postgresql", "postgres": "postgresql",
		"elasticsearch": "elasticsearch", "elastic": "elasticsearch",
		"memcached":   "memcached",
	}

	if tech, ok := techMap[tag]; ok {
		profile.AddTech(tech)
		switch {
		case tech == "wordpress" || tech == "joomla" || tech == "drupal" || tech == "magento":
			profile.SetCMS(tech)
		case tech == "apache" || tech == "nginx" || tech == "iis" || tech == "cloudflare":
			profile.SetWebServer(tech)
		case tech == "php" || tech == "asp.net" || tech == "python" || tech == "ruby" || tech == "node.js":
			profile.SetLanguage(tech)
		case tech == "spring" || tech == "spring-boot" || tech == "tomcat" || tech == "jboss" ||
			tech == "express" || tech == "django" || tech == "flask" || tech == "ruby-on-rails":
			profile.SetFramework(tech)
		}
	}

	if tag == "tech" || tag == "tech-detect" || tag == "fingerprint" {
		profile.AddTech("http")
	}
}

func classifyMetadataDirect(profile *TechProfile, metadata map[string]interface{}) {
	if product, ok := metadata["product"]; ok {
		if s, ok := product.(string); ok && s != "" {
			profile.AddTech(strings.ToLower(s))
		}
	}
	if vendor, ok := metadata["vendor"]; ok {
		if s, ok := vendor.(string); ok && s != "" {
			profile.AddTech(strings.ToLower(s))
		}
	}
	if tech, ok := metadata["tech"]; ok {
		if s, ok := tech.(string); ok && s != "" {
			profile.AddTech(strings.ToLower(s))
		}
	}
}

func classifyMatcherDirect(profile *TechProfile, matcherName string, extractedResults []string) {
	matcherLower := strings.ToLower(matcherName)

	techKeywords := []string{
		"wordpress", "joomla", "drupal", "magento", "apache", "nginx", "iis",
		"php", "asp.net", "aspnet", "tomcat", "jboss", "spring", "node",
		"express", "ruby", "rails", "python", "django", "flask", "cloudflare",
		"docker", "kubernetes", "gitlab", "jenkins", "grafana", "kibana",
		"redis", "mongodb", "mysql", "postgres", "elasticsearch", "memcached",
	}

	for _, kw := range techKeywords {
		if strings.Contains(matcherLower, kw) {
			profile.AddTech(kw)
			break
		}
	}

	for _, ext := range extractedResults {
		extLower := strings.ToLower(ext)
		for _, kw := range techKeywords {
			if strings.Contains(extLower, kw) {
				profile.AddTech(kw)
				break
			}
		}
	}
}

func classifyTemplateIDDirect(profile *TechProfile, templateID string) {
	idLower := strings.ToLower(templateID)

	if strings.Contains(idLower, "tech-detect") || strings.Contains(idLower, "fingerprint") {
		profile.AddTech("http")
		return
	}

	techPrefixes := []string{
		"wordpress", "joomla", "drupal", "magento", "apache", "nginx",
		"tomcat", "jboss", "gitlab", "jenkins", "grafana", "kibana",
	}
	for _, prefix := range techPrefixes {
		if strings.HasPrefix(idLower, prefix) {
			profile.AddTech(prefix)
			return
		}
	}
}

func classifyPortDirect(profile *TechProfile, portStr string) {
	portStr = strings.Split(portStr, "/")[0]
	portStr = strings.TrimSpace(portStr)
	var port int
	for _, ch := range portStr {
		if ch < '0' || ch > '9' {
			return
		}
		port = port*10 + int(ch-'0')
	}
	if port > 0 {
		profile.AddPort(port)

		portServiceMap := map[int]string{
			22: "ssh", 21: "ftp", 25: "smtp", 53: "dns",
			3306: "mysql", 5432: "postgresql", 6379: "redis",
			27017: "mongodb", 9200: "elasticsearch", 11211: "memcached",
			2375: "docker", 6443: "kubernetes",
		}
		if svc, ok := portServiceMap[port]; ok {
			profile.AddService(ServiceInfo{Name: svc, Port: port})
		}
	}
}

// ProfileBuilder builds a tech profile from HTTP headers and response body
type ProfileBuilder struct {
	patterns []techPattern
}

type techPattern struct {
	pattern  string
	tech     string
	isHeader bool
}

// NewProfileBuilder creates a ProfileBuilder with built-in fingerprints
func NewProfileBuilder() *ProfileBuilder {
	return &ProfileBuilder{
		patterns: []techPattern{
			{pattern: "server: nginx", tech: "nginx", isHeader: true},
			{pattern: "server: apache", tech: "apache", isHeader: true},
			{pattern: "server: microsoft-iis", tech: "iis", isHeader: true},
			{pattern: "server: cloudflare", tech: "cloudflare", isHeader: true},
			{pattern: "x-powered-by: php", tech: "php", isHeader: true},
			{pattern: "x-powered-by: asp.net", tech: "asp.net", isHeader: true},
			{pattern: "x-powered-by: express", tech: "express", isHeader: true},
			{pattern: "set-cookie: wp-settings", tech: "wordpress", isHeader: true},
			{pattern: "set-cookie: laravel_session", tech: "laravel", isHeader: true},
			{pattern: "set-cookie: jsessionid", tech: "java", isHeader: true},
			{pattern: "set-cookie: phpsessid", tech: "php", isHeader: true},
			{pattern: "set-cookie: connect.sid", tech: "express", isHeader: true},
			{pattern: "x-aspnet-version", tech: "asp.net", isHeader: true},
			{pattern: "x-drupal-cache", tech: "drupal", isHeader: true},
			{pattern: "x-generator: drupal", tech: "drupal", isHeader: true},
			{pattern: "x-generator: joomla", tech: "joomla", isHeader: true},
			{pattern: "wp-content", tech: "wordpress", isHeader: false},
			{pattern: "wp-includes", tech: "wordpress", isHeader: false},
			{pattern: "react.production", tech: "react", isHeader: false},
			{pattern: "vue.runtime", tech: "vue", isHeader: false},
			{pattern: "angular.min.js", tech: "angular", isHeader: false},
			{pattern: "jquery", tech: "jquery", isHeader: false},
			{pattern: "next.js", tech: "next.js", isHeader: false},
			{pattern: "/_next/static", tech: "next.js", isHeader: false},
			{pattern: "/__nuxt/", tech: "nuxt.js", isHeader: false},
		},
	}
}

// BuildFromHeadersAndBody creates a TechProfile from HTTP response headers + body
func (pb *ProfileBuilder) BuildFromHeadersAndBody(host string, headers map[string]string, body []byte) *TechProfile {
	profile := NewTechProfile(host)

	var headerBuf strings.Builder
	for k, v := range headers {
		headerBuf.WriteString(k + ": " + v + "\n")
	}
	headerStr := strings.ToLower(headerBuf.String())
	bodyStr := strings.ToLower(string(body))

	for _, p := range pb.patterns {
		searchIn := bodyStr
		if p.isHeader {
			searchIn = headerStr
		}
		if strings.Contains(searchIn, p.pattern) {
			profile.AddTech(p.tech)
		}
	}

	return profile
}
