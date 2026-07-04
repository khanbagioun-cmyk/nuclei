package intelligence

import (
	"fmt"
	"regexp"
	"strings"
)

// SynthesizedTemplate represents a nuclei template generated from a CVE
type SynthesizedTemplate struct {
	CVEID         string
	Name          string
	Author        string
	Severity      string
	Description   string
	Remediation   string
	References    []string
	CVSSMetrics   string
	CVSSScore     float64
	CWE           string
	Vendor        string
	Product       string
	Tags          []string
	HTTPRequests  []HTTPRequestSpec
	DNSRequests   []DNSRequestSpec
	Matchers      []MatcherSpec
	Extractors    []ExtractorSpec
	Verified      bool
	Confidence    float64  // 0.0-1.0 how confident we are in the template
	GenerationMethod string  // how the template was generated
}

// HTTPRequestSpec describes an HTTP request to make
type HTTPRequestSpec struct {
	Method  string
	Path    string
	Headers map[string]string
	Body    string
}

// DNSRequestSpec describes a DNS request
type DNSRequestSpec struct {
	Name string
	Type string
}

// MatcherSpec describes a matcher
type MatcherSpec struct {
	Type      string  // word, status, dsl, regex
	Part      string  // body, header, all
	Words     []string
	Regex     []string
	DSL       []string
	Status    []int
	Condition string  // and, or
	Negative  bool
}

// ExtractorSpec describes an extractor
type ExtractorSpec struct {
	Type   string  // regex, xpath, json, word
	Part   string
	Regex  []string
	XPath  []string
	JSON   []string
	Words  []string
	Group  int
	Internal bool
}

// Synthesizer converts NVD CVEs into nuclei template specs
type Synthesizer struct {
	knownProducts map[string]ProductInfo
}

// ProductInfo holds metadata about known products
type ProductInfo struct {
	Name           string
	WebPath        string  // typical path to detect
	VersionHeader  string  // header that contains version
	VersionBody    string  // regex to extract version from body
	VersionPath    string  // path that exposes version
	FaviconHash    string
	Tags           []string
}

// NewSynthesizer creates a synthesizer with known product patterns
func NewSynthesizer() *Synthesizer {
	s := &Synthesizer{
		knownProducts: make(map[string]ProductInfo),
	}
	s.registerKnownProducts()
	return s
}

func (s *Synthesizer) registerKnownProducts() {
	products := []ProductInfo{
		{Name: "wordpress", WebPath: "/wp-login.php", VersionPath: "/wp-includes/version.html", Tags: []string{"wordpress", "cms"}, VersionBody: `Version\s+([0-9.]+)`},
		{Name: "joomla", WebPath: "/administrator/", VersionPath: "/language/en-GB/en-GB.xml", Tags: []string{"joomla", "cms"}, VersionBody: `<version>([0-9.]+)</version>`},
		{Name: "drupal", WebPath: "/user/login", VersionPath: "/CHANGELOG.txt", Tags: []string{"drupal", "cms"}, VersionBody: `Drupal\s+([0-9.]+)`},
		{Name: "apache", VersionHeader: "Server: Apache/([0-9.]+)", Tags: []string{"apache", "webserver"}},
		{Name: "nginx", VersionHeader: "Server: nginx/([0-9.]+)", Tags: []string{"nginx", "webserver"}},
		{Name: "tomcat", WebPath: "/manager/html", VersionPath: "/docs/", Tags: []string{"tomcat", "java"}, VersionBody: `Apache Tomcat/([0-9.]+)`},
		{Name: "jenkins", WebPath: "/login", VersionPath: "/api/json", Tags: []string{"jenkins", "ci"}, VersionBody: `"version":"([0-9.]+)"`},
		{Name: "gitlab", WebPath: "/users/sign_in", Tags: []string{"gitlab", "devops"}, VersionBody: `GitLab Community Edition ([0-9.]+)`},
		{Name: "confluence", WebPath: "/login.action", Tags: []string{"confluence", "atlassian"}, VersionBody: `ajs-version-number" content="([0-9.]+)"`},
		{Name: "grafana", WebPath: "/login", VersionPath: "/api/health", Tags: []string{"grafana", "monitoring"}, VersionBody: `"version":"([0-9.]+)"`},
		{Name: "kibana", WebPath: "/app/kibana", Tags: []string{"kibana", "elastic"}, VersionBody: `"version":"([0-9.]+)"`},
		{Name: "struts", WebPath: "/struts/webconsole.html", Tags: []string{"struts", "java"}, VersionBody: `Struts Problem Report.*?Struts\s+([0-9.]+)`},
		{Name: "spring", VersionPath: "/actuator/info", Tags: []string{"spring", "java"}, VersionBody: `"version":"([0-9.]+)"`},
		{Name: "thinkphp", WebPath: "/", Tags: []string{"thinkphp", "php"}, VersionBody: `ThinkPHP\s+V?([0-9.]+)`},
		{Name: "weblogic", WebPath: "/console/login/LoginForm.jsp", Tags: []string{"weblogic", "java"}, VersionBody: `WebLogic Server Version: ([0-9.]+)`},
		{Name: "spring_boot", VersionPath: "/actuator", Tags: []string{"spring-boot", "java"}},
		{Name: "iis", VersionHeader: "Server: Microsoft-IIS/([0-9.]+)", Tags: []string{"iis", "microsoft"}},
		{Name: "vmware_vcenter", WebPath: "/ui/", Tags: []string{"vmware", "vcenter"}, VersionBody: `VSPHERE_UI_VERSION.*?([0-9.]+)`},
		{Name: "fortinet", WebPath: "/login", Tags: []string{"fortinet", "firewall"}, VersionBody: `FortiOS\s+([0-9.]+)`},
		{Name: "paloalto", WebPath: "/php/login.php", Tags: []string{"paloalto", "firewall"}, VersionBody: `"version":"([0-9.]+)"`},
		{Name: "pan-os", WebPath: "/php/login.php", Tags: []string{"paloalto", "pan-os", "firewall"}, VersionBody: `"version":"([0-9.]+)"`},
		{Name: "cloud ngfw", WebPath: "/php/login.php", Tags: []string{"paloalto", "firewall"}, VersionBody: `"version":"([0-9.]+)"`},
		{Name: "citrix", WebPath: "/citrix/", Tags: []string{"citrix", "netscaler"}},
		{Name: "f5_bigip", WebPath: "/tmui/login.jsp", Tags: []string{"f5", "bigip"}, VersionBody: `BIG-IP\s+([0-9.]+)`},
		{Name: "redis", Tags: []string{"redis"}, VersionBody: `redis_version:([0-9.]+)`},
		{Name: "elasticsearch", WebPath: "/", Tags: []string{"elasticsearch"}, VersionBody: `"number"\s*:\s*"([0-9.]+)"`},
		// Expanded product database — common CVE targets
		{Name: "jango", WebPath: "/admin/", Tags: []string{"django", "python"}, VersionBody: `Django\s+Version\s+([0-9.]+)`},
		{Name: "django", WebPath: "/admin/", Tags: []string{"django", "python"}, VersionBody: `Django\s+Version\s+([0-9.]+)`},
		{Name: "laravel", WebPath: "/", Tags: []string{"laravel", "php"}, VersionBody: `Laravel\s+v?([0-9.]+)`},
		{Name: "rails", WebPath: "/", Tags: []string{"rails", "ruby"}, VersionBody: `Rails\s+([0-9.]+)`},
		{Name: "nodejs", Tags: []string{"node", "nodejs"}, VersionBody: `"node_version":\s*"([0-9.]+)"`},
		{Name: "nextcloud", WebPath: "/login", Tags: []string{"nextcloud", "cloud"}, VersionBody: `version"?\s*[:=]\s*"?([0-9.]+)`},
		{Name: "owncloud", WebPath: "/login", Tags: []string{"owncloud", "cloud"}, VersionBody: `version"?\s*[:=]\s*"?([0-9.]+)`},
		{Name: "rabbitmq", WebPath: "/", Tags: []string{"rabbitmq"}, VersionBody: `RabbitMQ\s+([0-9.]+)`},
		{Name: "solr", WebPath: "/solr/admin/", Tags: []string{"solr", "search"}, VersionBody: `"lucene_solr_implementation_version":\s*"([0-9.]+)"`},
		{Name: "zabbix", WebPath: "/zabbix/", Tags: []string{"zabbix", "monitoring"}, VersionBody: `Zabbix\s+([0-9.]+)`},
		{Name: "phpmyadmin", WebPath: "/index.php", Tags: []string{"phpmyadmin", "database"}, VersionBody: `phpMyAdmin\s+([0-9.]+)`},
		{Name: "prestashop", WebPath: "/admin/", Tags: []string{"prestashop", "ecommerce"}, VersionBody: `PrestaShop\s+([0-9.]+)`},
		{Name: "magento", WebPath: "/admin/", Tags: []string{"magento", "ecommerce"}, VersionBody: `Magento\s+([0-9.]+)`},
		{Name: "opencart", WebPath: "/admin/", Tags: []string{"opencart", "ecommerce"}, VersionBody: `OpenCart\s+([0-9.]+)`},
		{Name: "sonarqube", WebPath: "/sessions/new", Tags: []string{"sonarqube", "ci"}, VersionBody: `"version":\s*"([0-9.]+)"`},
		{Name: "nexus", WebPath: "/", Tags: []string{"nexus", "repository"}, VersionBody: `Nexus\s+Repository\s+Manager\s+([0-9.]+)`},
		{Name: "harbor", WebPath: "/api/v2.0/systeminfo", Tags: []string{"harbor", "registry"}, VersionBody: `"harbor_version":\s*"([0-9.]+)"`},
		{Name: "minio", WebPath: "/minio/health/live", Tags: []string{"minio", "storage"}, VersionBody: `"version":\s*"([0-9.]+)"`},
		{Name: "consul", WebPath: "/v1/status/leader", Tags: []string{"consul"}, VersionBody: `"version":\s*"([0-9.]+)"`},
		{Name: "etcd", WebPath: "/version", Tags: []string{"etcd"}, VersionBody: `"etcdserver":\s*"([0-9.]+)"`},
		{Name: "portainer", WebPath: "/", Tags: []string{"portainer"}, VersionBody: `"Version":\s*"([0-9.]+)"`},
		{Name: "airflow", WebPath: "/login/", Tags: []string{"airflow"}, VersionBody: `"version":\s*"([0-9.]+)"`},
		{Name: "superset", WebPath: "/login/", Tags: []string{"superset"}, VersionBody: `"version":\s*"([0-9.]+)"`},
		{Name: "metabase", WebPath: "/api/session/properties", Tags: []string{"metabase"}, VersionBody: `"version":\s*"([0-9.]+)"`},
		{Name: "rundeck", WebPath: "/user/login", Tags: []string{"rundeck"}, VersionBody: `Rundeck\s+([0-9.]+)`},
		{Name: "sophos", WebPath: "/", Tags: []string{"sophos", "firewall"}, VersionBody: `Sophos\s+([0-9.]+)`},
		{Name: "sonatype", WebPath: "/", Tags: []string{"nexus", "repository"}, VersionBody: `Nexus\s+Repository\s+Manager\s+([0-9.]+)`},
		{Name: "crmeb_java", WebPath: "/", Tags: []string{"crmeb", "java", "ecommerce"}, VersionBody: `"version"?\s*[:=]\s*"?([0-9.]+)`},
		{Name: "netapp", WebPath: "/", Tags: []string{"netapp", "storage"}, VersionBody: `Active\s+IQ\s+Config\s+Advisor\s+([0-9.]+)`},
		{Name: "active_iq_config_advisor", WebPath: "/", Tags: []string{"netapp", "storage"}, VersionBody: `Active\s+IQ\s+Config\s+Advisor\s+([0-9.]+)`},
		{Name: "veeam", WebPath: "/", Tags: []string{"veeam", "backup"}, VersionBody: `Veeam\s+([0-9.]+)`},
		{Name: "kyocera", WebPath: "/", Tags: []string{"kyocera", "printer"}, VersionBody: `KYOCERA\s+([0-9.]+)`},
		{Name: "synology", WebPath: "/", Tags: []string{"synology", "nas"}, VersionBody: `Synology\s+([0-9.]+)`},
		{Name: "qnap", WebPath: "/", Tags: []string{"qnap", "nas"}, VersionBody: `QNAP\s+([0-9.]+)`},
		{Name: "mikrotik", WebPath: "/", Tags: []string{"mikrotik", "router"}, VersionBody: `RouterOS\s+([0-9.]+)`},
		{Name: "unifi", WebPath: "/", Tags: []string{"unifi", "ubiquiti"}, VersionBody: `UniFi\s+([0-9.]+)`},
		{Name: "pfsense", WebPath: "/", Tags: []string{"pfsense", "firewall"}, VersionBody: `pfSense\s+([0-9.]+)`},
		{Name: "opnsense", WebPath: "/", Tags: []string{"opnsense", "firewall"}, VersionBody: `OPNsense\s+([0-9.]+)`},
		{Name: "manageengine", WebPath: "/", Tags: []string{"manageengine", "zoho"}, VersionBody: `ManageEngine\s+([0-9.]+)`},
		{Name: "splunk", WebPath: "/en-US/account/login", Tags: []string{"splunk"}, VersionBody: `Splunk\s+([0-9.]+)`},
		{Name: "zevenet", WebPath: "/", Tags: []string{"zevenet", "lb"}, VersionBody: `Zevenet\s+([0-9.]+)`},
	}
	for _, p := range products {
		s.knownProducts[p.Name] = p
	}
}

// Synthesize converts a NVD CVE into a template spec
func (s *Synthesizer) Synthesize(cve *NVDCVE) (*SynthesizedTemplate, error) {
	desc := cve.GetEnglishDescription()
	if desc == "" {
		return nil, fmt.Errorf("no description for %s", cve.ID)
	}

	vendor, product := cve.GetVendorProduct()
	tags := s.generateTags(cve, product)
	name := s.generateName(cve, desc, product)

	tmpl := &SynthesizedTemplate{
		CVEID:        cve.ID,
		Name:         name,
		Author:       "nuclei-cvesync",
		Severity:     cve.GetSeverity(),
		Description:  desc,
		References:   cve.GetReferenceURLs(),
		CVSSMetrics:  cve.GetCVSSVector(),
		CVSSScore:    cve.GetCVSSScore(),
		CWE:          cve.GetCWE(),
		Vendor:       vendor,
		Product:      product,
		Tags:         tags,
		GenerationMethod: "heuristic",
	}

	if cve.IsCISAKEV() {
		tmpl.Tags = append(tmpl.Tags, "kev")
	}

	s.generateDetection(cve, desc, tmpl)
	tmpl.Confidence = s.assessConfidence(tmpl)

	return tmpl, nil
}

func (s *Synthesizer) generateName(cve *NVDCVE, desc, product string) string {
	// Try to extract product name from description
	if product == "" {
		product = extractProductFromDesc(desc)
	}

	vulnType := classifyVulnType(desc)
	if product != "" && vulnType != "" {
		return fmt.Sprintf("%s - %s", strings.Title(product), vulnType)
	}
	if product != "" {
		return fmt.Sprintf("%s - Vulnerability", strings.Title(product))
	}
	// Use first sentence of description
	sentences := strings.SplitN(desc, ".", 2)
	if len(sentences) > 0 && len(sentences[0]) < 120 {
		return strings.TrimSpace(sentences[0])
	}
	return cve.ID
}

func (s *Synthesizer) generateTags(cve *NVDCVE, product string) []string {
	tags := []string{"cve", fmt.Sprintf("cve%s", cve.ID[4:8])}

	if product != "" {
		productLower := strings.ToLower(product)
		if info, ok := s.knownProducts[productLower]; ok {
			tags = append(tags, info.Tags...)
		} else {
			tags = append(tags, productLower)
		}
	}
	tags = append(tags, "vuln")
	return tags
}

// generateDetection creates HTTP requests and matchers based on CVE analysis
func (s *Synthesizer) generateDetection(cve *NVDCVE, desc string, tmpl *SynthesizedTemplate) {
	vulnType := classifyVulnType(desc)
	product := strings.ToLower(tmpl.Product)
	if product == "" {
		product = strings.ToLower(extractProductFromDesc(desc))
	}

	// Check if we know this product
	info, knownProduct := s.knownProducts[product]

	// Strategy 1: If product is known, use known detection paths
	if knownProduct {
		s.generateKnownProductDetection(cve, desc, tmpl, info, vulnType)
		return
	}

	// Strategy 2: Extract paths from description
	paths := extractPathsFromDesc(desc)
	if len(paths) > 0 {
		s.generatePathBasedDetection(cve, desc, tmpl, paths, vulnType)
		return
	}

	// Strategy 3: Version-based detection from CPE
	versionRanges := cve.GetAffectedVersions()
	if len(versionRanges) > 0 {
		s.generateVersionBasedDetection(cve, desc, tmpl, versionRanges, vulnType)
		return
	}

	// Strategy 4: Generic fingerprinting
	s.generateGenericDetection(cve, desc, tmpl, vulnType)
}

func (s *Synthesizer) generateKnownProductDetection(cve *NVDCVE, desc string, tmpl *SynthesizedTemplate, info ProductInfo, vulnType string) {
	seenPaths := make(map[string]bool)
	addRequest := func(path string) {
		if path != "" && !seenPaths[path] {
			seenPaths[path] = true
			tmpl.HTTPRequests = append(tmpl.HTTPRequests, HTTPRequestSpec{
				Method: "GET",
				Path:   path,
			})
		}
	}

	// Request 1: Fingerprinting request
	if info.WebPath != "" {
		addRequest(info.WebPath)
	}

	// Request 2: Version detection
	versionPath := info.VersionPath
	if versionPath == "" && info.WebPath != "" {
		versionPath = info.WebPath
	}
	addRequest(versionPath)

	// Matchers based on vulnerability type
	switch vulnType {
	case "Authentication Bypass", "Auth Bypass":
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "status",
			Status:    []int{200},
			Condition: "and",
		})
		if info.VersionBody != "" {
			tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
				Type:      "regex",
				Part:      "body",
				Regex:     []string{info.VersionBody},
				Condition: "and",
			})
		}
	case "SQL Injection", "XSS", "Cross-Site Scripting":
		// Look for error patterns or injection indicators
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "word",
			Part:      "body",
			Words:     s.extractErrorPatterns(desc),
			Condition: "or",
		})
	case "Remote Code Execution", "RCE", "Code Injection":
		// RCE typically needs a payload + indicator
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "word",
			Part:      "body",
			Words:     []string{"root:", "uid=", "whoami", "cmd="},
			Condition: "or",
		})
	case "Information Disclosure", "Info Disclosure":
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "status",
			Status:    []int{200},
			Condition: "and",
		})
		if info.VersionBody != "" {
			tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
				Type:      "regex",
				Part:      "body",
				Regex:     []string{info.VersionBody},
				Condition: "and",
			})
		}
	case "Path Traversal", "Directory Traversal", "LFI":
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "word",
			Part:      "body",
			Words:     []string{"root:x:", "[boot loader]", "[fonts]"},
			Condition: "or",
		})
	case "SSRF":
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "word",
			Part:      "body",
			Words:     []string{"metadata", "169.254.169.254"},
			Condition: "or",
		})
	default:
		// Generic: status 200 + version match
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "status",
			Status:    []int{200},
			Condition: "and",
		})
		if info.VersionBody != "" {
			tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
				Type:      "regex",
				Part:      "body",
				Regex:     []string{info.VersionBody},
				Condition: "and",
			})
		}
	}

	// Product identity word matcher — require product-specific evidence in body
	// This is added in addition to vuln-type-specific matchers to prevent FPs
	productWords := s.generateProductWordsFromCVE(strings.ToLower(tmpl.Product), desc, cve)
	if len(productWords) > 0 {
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "word",
			Part:      "body",
			Words:     productWords,
			Condition: "or",
		})
	}

	// Negative matchers: reject generic error/default pages
	s.addNegativeMatchers(tmpl)

	// Add version extractor
	if info.VersionBody != "" {
		tmpl.Extractors = append(tmpl.Extractors, ExtractorSpec{
			Type:   "regex",
			Part:   "body",
			Regex:  []string{info.VersionBody},
			Group:  1,
			Internal: true,
		})
	}
}

func (s *Synthesizer) generatePathBasedDetection(cve *NVDCVE, desc string, tmpl *SynthesizedTemplate, paths []string, vulnType string) {
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		tmpl.HTTPRequests = append(tmpl.HTTPRequests, HTTPRequestSpec{
			Method: "GET",
			Path:   p,
		})
	}

	// Status matcher
	tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
		Type:      "status",
		Status:    []int{200},
		Condition: "and",
	})

	// Product word matcher — require product-specific evidence in body
	productWords := s.generateProductWordsFromCVE(strings.ToLower(tmpl.Product), desc, cve)
	if len(productWords) > 0 {
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "word",
			Part:      "body",
			Words:     productWords,
			Condition: "or",
		})
	}

	// Keywords from description as additional matchers
	keywords := extractKeywordsFromDesc(desc)
	if len(keywords) > 0 {
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "word",
			Part:      "body",
			Words:     keywords,
			Condition: "or",
		})
	}

	// Negative matchers: reject generic error/default pages
	s.addNegativeMatchers(tmpl)
}

func (s *Synthesizer) generateVersionBasedDetection(cve *NVDCVE, desc string, tmpl *SynthesizedTemplate, ranges []VersionRange, vulnType string) {
	product := strings.ToLower(tmpl.Product)
	if product == "" {
		product = strings.ToLower(extractProductFromDesc(desc))
	}

	info, knownProduct := s.knownProducts[product]

	// Build product-specific keyword matcher from full CVE data
	productWords := s.generateProductWordsFromCVE(product, desc, cve)

	// Determine which paths to probe
	var versionPaths []string
	if knownProduct {
		if info.VersionPath != "" {
			versionPaths = []string{info.VersionPath}
		}
		if info.WebPath != "" && (len(versionPaths) == 0 || versionPaths[0] != info.WebPath) {
			versionPaths = append(versionPaths, info.WebPath)
		}
	}
	if len(versionPaths) == 0 {
		versionPaths = []string{"/"}
	}

	seenPaths := make(map[string]bool)
	for _, p := range versionPaths {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if !seenPaths[p] {
			seenPaths[p] = true
			tmpl.HTTPRequests = append(tmpl.HTTPRequests, HTTPRequestSpec{
				Method: "GET",
				Path:   p,
			})
		}
	}

	// Status matcher: require 200
	tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
		Type:      "status",
		Status:    []int{200},
		Condition: "and",
	})

	// Version regex: use product-specific if known, otherwise tightened generic
	versionRegex := `version["\s:>]+([0-9.]+)`
	if knownProduct && info.VersionBody != "" {
		versionRegex = info.VersionBody
	} else {
		versionRegex = `(?i)"?version"?\s*[:=]\s*"?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`
	}
	tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
		Type:      "regex",
		Part:      "body",
		Regex:     []string{versionRegex},
		Condition: "and",
	})

	// Product word matcher: require at least one product-specific keyword in body
	// This is the critical FP guard — prevents matching on any 200 page with a version string
	if len(productWords) > 0 {
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "word",
			Part:      "body",
			Words:     productWords,
			Condition: "or",
		})
	}

	// Negative matchers: reject generic 404/error/default pages that return 200
	s.addNegativeMatchers(tmpl)

	tmpl.Extractors = append(tmpl.Extractors, ExtractorSpec{
		Type:     "regex",
		Part:     "body",
		Regex:    []string{versionRegex},
		Group:    1,
		Internal: true,
	})
}

func (s *Synthesizer) generateGenericDetection(cve *NVDCVE, desc string, tmpl *SynthesizedTemplate, vulnType string) {
	tmpl.HTTPRequests = append(tmpl.HTTPRequests, HTTPRequestSpec{
		Method: "GET",
		Path:   "/",
	})

	// Product word matcher — mandatory to prevent FPs on generic 200 pages
	productWords := s.generateProductWordsFromCVE(strings.ToLower(tmpl.Product), desc, cve)

	keywords := extractKeywordsFromDesc(desc)

	// Combine product words and description keywords
	allWords := append(productWords, keywords...)
	if len(allWords) > 0 {
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "word",
			Part:      "body",
			Words:     allWords,
			Condition: "or",
		})
	} else {
		// Last resort: use CVE ID itself as a word matcher
		// This will almost never match, which is the correct behavior
		// for templates with no detectable product evidence
		tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
			Type:      "word",
			Part:      "body",
			Words:     []string{strings.ToLower(tmpl.CVEID)},
			Condition: "or",
		})
	}

	// Also require status 200 (AND with word matcher)
	tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
		Type:      "status",
		Status:    []int{200},
		Condition: "and",
	})

	// Negative matchers: reject generic error/default pages
	s.addNegativeMatchers(tmpl)
}

func (s *Synthesizer) assessConfidence(tmpl *SynthesizedTemplate) float64 {
	confidence := 0.3 // base

	if len(tmpl.HTTPRequests) > 0 {
		confidence += 0.1
	}
	if len(tmpl.Matchers) > 0 {
		confidence += 0.1
	}
	if tmpl.Product != "" {
		confidence += 0.15
	}
	if _, known := s.knownProducts[strings.ToLower(tmpl.Product)]; known {
		confidence += 0.2
	}
	if tmpl.CVSSScore >= 7.0 {
		confidence += 0.05
	}
	if contains(tmpl.Tags, "kev") {
		confidence += 0.1
	}
	if len(tmpl.References) >= 2 {
		confidence += 0.05
	}
	// Bonus for having negative matchers (FP-resistant)
	hasNegative := false
	for _, m := range tmpl.Matchers {
		if m.Negative {
			hasNegative = true
			break
		}
	}
	if hasNegative {
		confidence += 0.05
	}

	if confidence > 1.0 {
		confidence = 1.0
	}
	return confidence
}

func (s *Synthesizer) extractErrorPatterns(desc string) []string {
	var patterns []string
	descLower := strings.ToLower(desc)
	if strings.Contains(descLower, "sql") || strings.Contains(descLower, "database") {
		patterns = append(patterns, "SQL syntax", "mysql_fetch", "ORA-", "psql:", "SQLSTATE")
	}
	if strings.Contains(descLower, "stack trace") || strings.Contains(descLower, "exception") {
		patterns = append(patterns, "Exception in thread", "Traceback", "at java.")
	}
	if len(patterns) == 0 {
		patterns = []string{"error", "exception", "stack trace"}
	}
	return patterns
}

// --- Helper functions ---

var pathRegex = regexp.MustCompile(`(?:^|\s)(/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)*\.(?:php|jsp|asp|aspx|html|js|json|xml|txt|cgi))`)

func extractPathsFromDesc(desc string) []string {
	matches := pathRegex.FindAllStringSubmatch(desc, -1)
	var paths []string
	seen := make(map[string]bool)
	for _, m := range matches {
		path := m[1]
		path = strings.TrimSuffix(path, ".")
		if len(path) > 3 && len(path) < 80 && !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	return paths
}

func extractProductFromDesc(desc string) string {
	// Common patterns: "in X product", "X version Y", "X software"
	patterns := []regexp.Regexp{
		*regexp.MustCompile(`(?i)in\s+([A-Z][a-zA-Z0-9\-]+)\s+(?:software|product|version|firmware)`),
		*regexp.MustCompile(`(?i)([A-Z][a-zA-Z0-9\-]+)\s+version\s+[0-9]`),
		*regexp.MustCompile(`(?i)([A-Z][a-zA-Z0-9\-]+)\s+(?:CMS|Plugin|Theme|Module|Component)`),
	}
	for _, p := range patterns {
		m := p.FindStringSubmatch(desc)
		if len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

func classifyVulnType(desc string) string {
	descLower := strings.ToLower(desc)
	switch {
	case strings.Contains(descLower, "sql injection") || strings.Contains(descLower, "sqli"):
		return "SQL Injection"
	case strings.Contains(descLower, "cross-site scripting") || strings.Contains(descLower, " xss"):
		return "XSS"
	case strings.Contains(descLower, "remote code execution") || strings.Contains(descLower, "rce") || strings.Contains(descLower, "code injection"):
		return "Remote Code Execution"
	case strings.Contains(descLower, "authentication bypass") || strings.Contains(descLower, "auth bypass") || strings.Contains(descLower, "bypass authentication"):
		return "Authentication Bypass"
	case strings.Contains(descLower, "path traversal") || strings.Contains(descLower, "directory traversal") || strings.Contains(descLower, "lfi"):
		return "Path Traversal"
	case strings.Contains(descLower, "ssrf") || strings.Contains(descLower, "server-side request forgery"):
		return "SSRF"
	case strings.Contains(descLower, "information disclosure") || strings.Contains(descLower, "info disclosure") || strings.Contains(descLower, "sensitive information"):
		return "Information Disclosure"
	case strings.Contains(descLower, "privilege escalation"):
		return "Privilege Escalation"
	case strings.Contains(descLower, "denial of service") || strings.Contains(descLower, "dos"):
		return "DoS"
	case strings.Contains(descLower, "csrf") || strings.Contains(descLower, "cross-site request forgery"):
		return "CSRF"
	case strings.Contains(descLower, "file upload") || strings.Contains(descLower, "unrestricted upload"):
		return "File Upload"
	case strings.Contains(descLower, "deserialization"):
		return "Deserialization"
	case strings.Contains(descLower, "command injection") || strings.Contains(descLower, "os command"):
		return "Command Injection"
	case strings.Contains(descLower, "xxe") || strings.Contains(descLower, "xml external entity"):
		return "XXE"
	case strings.Contains(descLower, "ssti") || strings.Contains(descLower, "template injection"):
		return "SSTI"
	case strings.Contains(descLower, "open redirect") || strings.Contains(descLower, "url redirect"):
		return "Open Redirect"
	case strings.Contains(descLower, "xve") || strings.Contains(descLower, "xxe"):
		return "XXE"
	default:
		return "Vulnerability"
	}
}

func extractKeywordsFromDesc(desc string) []string {
	var keywords []string
	// Extract quoted strings
	quotedRegex := regexp.MustCompile(`"([^"]{3,50})"`)
	matches := quotedRegex.FindAllStringSubmatch(desc, -1)
	for _, m := range matches {
		keywords = append(keywords, m[1])
	}
	// Extract error-like patterns
	if strings.Contains(strings.ToLower(desc), "error") {
		keywords = append(keywords, "error", "exception")
	}
	// Extract product names
	productRegex := regexp.MustCompile(`\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b`)
	productMatches := productRegex.FindAllStringSubmatch(desc, 5)
	for _, m := range productMatches {
		if len(m[1]) > 3 {
			keywords = append(keywords, m[1])
		}
	}
	if len(keywords) == 0 {
		keywords = []string{"404", "500", "error"}
	}
	return keywords
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// generateProductWords extracts product-specific keywords to use as body matchers.
// These prevent false positives by requiring the response to contain evidence
// of the actual product, not just any 200 response.
// Sources: product name, vendor, CPE, known product tags, reference URLs, description.
func (s *Synthesizer) generateProductWords(product string, desc string) []string {
	return s.generateProductWordsFromCVE(product, desc, nil)
}

// generateProductWordsFromCVE is the enhanced version that mines the full CVE struct
func (s *Synthesizer) generateProductWordsFromCVE(product string, desc string, cve *NVDCVE) []string {
	var words []string
	seen := make(map[string]bool)
	addWord := func(w string) {
		w = strings.TrimSpace(strings.ToLower(w))
		if len(w) >= 3 && !seen[w] {
			seen[w] = true
			words = append(words, w)
		}
	}

	// 1. From product name — split on separators
	if product != "" {
		for _, part := range strings.FieldsFunc(product, func(r rune) bool { return r == ' ' || r == '_' || r == '-' }) {
			addWord(part)
		}
		addWord(strings.ReplaceAll(product, " ", "_"))
		addWord(strings.ReplaceAll(product, " ", "-"))
	}

	// 2. From known product info tags
	if info, ok := s.knownProducts[product]; ok {
		for _, tag := range info.Tags {
			addWord(tag)
		}
	}

	// 3. From CPE vendor and product in CVE affected data
	if cve != nil {
		for _, aff := range cve.Affected {
			for _, ad := range aff.AffectedData {
				if ad.Vendor != "" {
					addWord(ad.Vendor)
				}
				if ad.Product != "" {
					addWord(ad.Product)
					for _, part := range strings.FieldsFunc(ad.Product, func(r rune) bool { return r == ' ' || r == '_' || r == '-' }) {
						addWord(part)
					}
				}
				// Mine CPE strings: cpe:2.3:a:vendor:product:...
				for _, cpe := range ad.CPEs {
					parts := strings.Split(cpe, ":")
					if len(parts) >= 5 {
						addWord(parts[3])
						addWord(parts[4])
					}
				}
			}
		}

		// 4. From reference URLs — extract product/repo names from GitHub, advisory pages
		for _, ref := range cve.References {
			u := ref.URL
			if strings.Contains(u, "github.com/") {
				segments := strings.Split(strings.TrimSuffix(u, "/"), "/")
				if len(segments) >= 5 {
					addWord(segments[4])
				}
			}
			if strings.Contains(u, "security.") || strings.Contains(u, "advisory") || strings.Contains(u, "bulletin") {
				parts := strings.Split(u, "/")
				for _, p := range parts {
					if len(p) >= 4 && len(p) <= 20 {
						addWord(p)
					}
				}
			}
			for _, tag := range ref.Tags {
				addWord(tag)
			}
		}
	}

	// 5. From description — vendor near product keywords
	vendorRegex := regexp.MustCompile(`(?i)([a-z][a-z0-9_\-]{3,20})\s+(?:software|product|version|firmware|component|endpoint)`)
	for _, m := range vendorRegex.FindAllStringSubmatch(desc, 3) {
		addWord(m[1])
	}

	// 6. From description — file paths (contain product-specific names)
	pathRegex := regexp.MustCompile(`/([a-z][a-z0-9_\-]{2,15})/[a-z]`)
	for _, m := range pathRegex.FindAllStringSubmatch(desc, 5) {
		addWord(m[1])
	}

	// 7. Filter out generic words that would cause FPs
	genericWords := map[string]bool{
		"version": true, "http": true, "https": true, "html": true,
		"json": true, "xml": true, "api": true, "com": true, "org": true,
		"net": true, "www": true, "the": true, "and": true, "for": true,
		"new": true, "old": true, "web": true, "app": true, "server": true,
		"client": true, "system": true, "service": true, "endpoint": true,
		"vulnerability": true, "exploit": true, "attack": true, "software": true,
		"product": true, "component": true, "firmware": true, "update": true,
		"patch": true, "fix": true, "issue": true, "bug": true,
		"error": true, "exception": true, "stack": true, "trace": true,
		"advisory": true, "security": true, "bulletin": true,
	}
	filtered := words[:0]
	for _, w := range words {
		if !genericWords[w] {
			filtered = append(filtered, w)
		}
	}

	// Limit to reasonable number
	if len(filtered) > 10 {
		filtered = filtered[:10]
	}
	return filtered
}

// addNegativeMatchers adds matchers that reject common false positive patterns.
// These are added as negative matchers so a match only occurs when the response
// does NOT contain these patterns. This catches:
// - Generic 404/error pages that return 200
// - Default web server pages
// - CMS "page not found" responses
func (s *Synthesizer) addNegativeMatchers(tmpl *SynthesizedTemplate) {
	tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
		Type:      "word",
		Part:      "body",
		Words:     []string{"not found", "404", "page not found", "doesn't exist", "does not exist"},
		Condition: "or",
		Negative:  true,
	})
	tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
		Type:      "word",
		Part:      "body",
		Words:     []string{"welcome to nginx", "welcome to apache", "it works!", "default page", "index of /"},
		Condition: "or",
		Negative:  true,
	})
}
