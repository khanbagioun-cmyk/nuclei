package discovery

import (
	"context"
	"sync"
	"time"
)

// Config configures the discovery engine
type Config struct {
	Domains          []string      `json:"domains"`
	IPs             []string      `json:"ips"`
	CIDRs           []string      `json:"cidrs"`
	Wordlist        string        `json:"wordlist"`
	ResolverFile    string        `json:"resolver_file"`
	Ports           []int         `json:"ports"`
	TopPorts        int           `json:"top_ports"`
	Threads         int           `json:"threads"`
	Timeout         time.Duration `json:"timeout"`
	HTTPTimeout     time.Duration `json:"http_timeout"`
	CrawlDepth      int           `json:"crawl_depth"`
	CrawlMaxPages   int           `json:"crawl_max_pages"`
	CloudProviders  []string      `json:"cloud_providers"`
	CloudBucketNames []string     `json:"cloud_bucket_names"`
	UserAgent       string        `json:"user_agent"`
	SkipDNS         bool          `json:"skip_dns"`
	SkipPortScan    bool          `json:"skip_port_scan"`
	SkipWebCrawl    bool          `json:"skip_web_crawl"`
	SkipCloud       bool          `json:"skip_cloud"`
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Threads:        25,
		Timeout:        5 * time.Second,
		HTTPTimeout:    10 * time.Second,
		CrawlDepth:     2,
		CrawlMaxPages:  50,
		Ports:          DefaultPorts,
		SkipCloud:      true,
		UserAgent:      "Mozilla/5.0 (nuclei-discovery)",
	}
}

// DefaultPorts are commonly scanned ports
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1433, 1521, 2049, 2181, 2375, 3306, 3389, 5432, 5900,
	5984, 6379, 6443, 7474, 8000, 8080, 8081, 8443, 8888, 9000, 9090,
	9200, 9300, 9418, 11211, 15672, 27017, 50070,
}

// Result is the aggregate discovery output
type Result struct {
	Domains   []DomainResult   `json:"domains"`
	Hosts     []HostResult     `json:"hosts"`
	Services  []ServiceResult  `json:"services"`
	WebApps   []WebAppResult   `json:"web_apps"`
	CloudReqs []CloudResource  `json:"cloud_resources"`
	Errors    []string         `json:"errors,omitempty"`
}

// DomainResult holds DNS enumeration results
type DomainResult struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Nameservers []string `json:"nameservers"`
	MXRecords  []string `json:"mx_records"`
	TXTRecords []string `json:"txt_records"`
	HasWildcard bool    `json:"has_wildcard"`
}

// HostResult holds port scan results for a host
type HostResult struct {
	Host    string          `json:"host"`
	IP      string          `json:"ip"`
	OpenPorts []PortResult  `json:"open_ports"`
}

// PortResult holds details about an open port
type PortResult struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
}

// ServiceResult holds a discovered service
type ServiceResult struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
	Protocol string `json:"protocol"`
}

// WebAppResult holds web application crawl data
type WebAppResult struct {
	URL     string            `json:"url"`
	Title   string            `json:"title"`
	Headers map[string]string `json:"headers"`
	Tech    []string          `json:"tech"`
	Forms   []FormInfo        `json:"forms"`
	Links   []string          `json:"links"`
	JSFiles []string          `json:"js_files"`
	Status  int               `json:"status"`
}

// FormInfo holds HTML form metadata
type FormInfo struct {
	Action string `json:"action"`
	Method string `json:"method"`
	Inputs []FormField `json:"inputs"`
}

// FormField holds form input metadata
type FormField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// CloudResource holds a discovered cloud resource
type CloudResource struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Exists   bool   `json:"exists"`
	Public   bool   `json:"public"`
}

// Discovery orchestrates all discovery modules
type Discovery struct {
	config   Config
	resolver *Resolver
	result   *Result
	mu       sync.Mutex
}

// New creates a new Discovery engine
func New(cfg Config) *Discovery {
	if cfg.Threads <= 0 {
		cfg.Threads = 25
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}
	if cfg.CrawlDepth <= 0 {
		cfg.CrawlDepth = 2
	}
	if cfg.CrawlMaxPages <= 0 {
		cfg.CrawlMaxPages = 50
	}
	d := &Discovery{
		config: cfg,
		result: &Result{},
	}
	d.resolver = NewResolver(cfg.ResolverFile, cfg.Timeout)
	return d
}

// Run executes all enabled discovery modules
func (d *Discovery) Run(ctx context.Context) (*Result, error) {
	var wg sync.WaitGroup

	if !d.config.SkipDNS && len(d.config.Domains) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.runDNSEnum(ctx)
		}()
	}

	if !d.config.SkipPortScan && (len(d.config.IPs) > 0 || len(d.config.CIDRs) > 0 || len(d.config.Domains) > 0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.runPortScan(ctx)
		}()
	}

	if !d.config.SkipWebCrawl {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.runWebCrawl(ctx)
		}()
	}

	if !d.config.SkipCloud && len(d.config.CloudProviders) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.runCloudEnum(ctx)
		}()
	}

	wg.Wait()
	return d.result, nil
}

func (d *Discovery) addDomainResult(r DomainResult) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.result.Domains = append(d.result.Domains, r)
}

func (d *Discovery) addHostResult(r HostResult) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.result.Hosts = append(d.result.Hosts, r)
}

func (d *Discovery) addServiceResult(r ServiceResult) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.result.Services = append(d.result.Services, r)
}

func (d *Discovery) addWebAppResult(r WebAppResult) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.result.WebApps = append(d.result.WebApps, r)
}

func (d *Discovery) addCloudResult(r CloudResource) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.result.CloudReqs = append(d.result.CloudReqs, r)
}

func (d *Discovery) addError(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.result.Errors = append(d.result.Errors, msg)
}
