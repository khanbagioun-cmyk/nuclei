package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DefaultSubdomainWordlist is a compact built-in subdomain wordlist
var DefaultSubdomainWordlist = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
	"api", "dev", "staging", "test", "beta", "prod", "admin", "portal",
	"vpn", "m", "mobile", "app", "apps", "secure", "auth", "sso",
	"git", "gitlab", "jenkins", "ci", "build", "deploy", "release",
	"internal", "intranet", "extranet", "office", "remote", "cloud",
	"aws", "azure", "gcp", "cdn", "static", "assets", "media",
	"img", "images", "files", "download", "upload", "storage",
	"db", "database", "sql", "redis", "cache", "elastic", "search",
	"monitor", "grafana", "prometheus", "status", "health", "metrics",
	"logs", "log", "analytics", "tracking", "report", "dashboard",
	"shop", "store", "cart", "checkout", "pay", "billing", "account",
	"login", "register", "signup", "signin", "oauth", "token", "jwt",
	"ws", "websocket", "socket", "stream", "realtime", "push",
	"v1", "v2", "v3", "rest", "graphql", "rpc", "grpc",
	"backup", "bak", "old", "new", "tmp", "temp", "sandbox",
	"docs", "wiki", "help", "support", "faq", "kb", "knowledge",
	"hr", "finance", "sales", "marketing", "crm", "erp", "sap",
	"mx", "mx1", "mx2", "relay", "outbound", "inbound",
	"ns", "ns3", "ns4", "dns", "dns1", "dns2",
	"qa", "uat", "preprod", "demo", "preview", "stage",
	"edge", "node", "worker", "master", "slave", "proxy",
	"lb", "haproxy", "nginx", "apache", "tomcat", "jboss",
	"kibana", "solr", "rabbitmq", "mongo", "minio", "consul",
	"etcd", "zookeeper", "nexus", "sonar", "jira", "confluence",
}

// Resolver wraps miekg/dns client for DNS queries
type Resolver struct {
	client    *dns.Client
	servers   []string
	timeout   time.Duration
}

// NewResolver creates a DNS resolver
func NewResolver(resolverFile string, timeout time.Duration) *Resolver {
	r := &Resolver{
		client:  &dns.Client{Timeout: timeout},
		timeout: timeout,
		servers: []string{"8.8.8.8:53", "1.1.1.1:53"},
	}
	if resolverFile != "" {
		if data, err := os.ReadFile(resolverFile); err == nil {
			var servers []string
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if !strings.Contains(line, ":") {
					line += ":53"
				}
				servers = append(servers, line)
			}
			if len(servers) > 0 {
				r.servers = servers
			}
		}
	}
	return r
}

// Query performs a DNS query for the given type
func (r *Resolver) Query(name string, qtype uint16) ([]dns.RR, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true

	var lastErr error
	for _, server := range r.servers {
		resp, _, err := r.client.Exchange(msg, server)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS query failed: %s", dns.RcodeToString[resp.Rcode])
			continue
		}
		return resp.Answer, nil
	}
	return nil, lastErr
}

// ResolveA resolves A records
func (r *Resolver) ResolveA(name string) ([]string, error) {
	answers, err := r.Query(name, dns.TypeA)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, rr := range answers {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips, nil
}

// CheckWildcard detects if a domain has wildcard DNS
func (r *Resolver) CheckWildcard(domain string) bool {
	random := fmt.Sprintf("%s-wildcard-test-%d.%s", "nuclei", time.Now().UnixNano(), domain)
	ips, err := r.ResolveA(random)
	if err == nil && len(ips) > 0 {
		return true
	}
	return false
}

// runDNSEnum runs DNS enumeration on all configured domains
func (d *Discovery) runDNSEnum(ctx context.Context) {
	sem := make(chan struct{}, d.config.Threads)
	var wg sync.WaitGroup

	for _, domain := range d.config.Domains {
		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d.enumerateDomain(ctx, dom)
		}(domain)
	}
	wg.Wait()
}

func (d *Discovery) enumerateDomain(ctx context.Context, domain string) {
	result := DomainResult{Domain: domain}

	result.HasWildcard = d.resolver.CheckWildcard(domain)
	if result.HasWildcard {
		d.addError(fmt.Sprintf("wildcard DNS detected for %s — results may contain false positives", domain))
	}

	wordlist := d.loadWordlist()

	sem := make(chan struct{}, d.config.Threads)
	var subWg sync.WaitGroup
	var subMu sync.Mutex

	for _, word := range wordlist {
		select {
		case <-ctx.Done():
			return
		default:
		}

		subWg.Add(1)
		go func(w string) {
			defer subWg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			subdomain := fmt.Sprintf("%s.%s", w, domain)
			ips, err := d.resolver.ResolveA(subdomain)
			if err != nil || len(ips) == 0 {
				return
			}
			subMu.Lock()
			result.Subdomains = append(result.Subdomains, subdomain)
			subMu.Unlock()
		}(word)
	}
	subWg.Wait()

	if ns, err := d.resolver.Query(domain, dns.TypeNS); err == nil {
		for _, rr := range ns {
			if nsRecord, ok := rr.(*dns.NS); ok {
				result.Nameservers = append(result.Nameservers, strings.TrimSuffix(nsRecord.Ns, "."))
			}
		}
	}

	if mx, err := d.resolver.Query(domain, dns.TypeMX); err == nil {
		for _, rr := range mx {
			if mxRecord, ok := rr.(*dns.MX); ok {
				result.MXRecords = append(result.MXRecords, strings.TrimSuffix(mxRecord.Mx, "."))
			}
		}
	}

	if txt, err := d.resolver.Query(domain, dns.TypeTXT); err == nil {
		for _, rr := range txt {
			if txtRecord, ok := rr.(*dns.TXT); ok {
				result.TXTRecords = append(result.TXTRecords, strings.Join(txtRecord.Txt, " "))
			}
		}
	}

	d.addDomainResult(result)
}

func (d *Discovery) loadWordlist() []string {
	if d.config.Wordlist != "" {
		if data, err := os.ReadFile(d.config.Wordlist); err == nil {
			var words []string
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					words = append(words, line)
				}
			}
			if len(words) > 0 {
				return words
			}
		}
	}
	return DefaultSubdomainWordlist
}

// resolveHost resolves a hostname to IPs using the resolver
func (d *Discovery) resolveHost(host string) []string {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}
	}
	ips, err := d.resolver.ResolveA(host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	return ips
}
