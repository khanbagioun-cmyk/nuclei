package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/discovery"
)

func main() {
	domains := flag.String("d", "", "target domains (comma-separated)")
	domainsFile := flag.String("df", "", "target domains file (one per line)")
	ips := flag.String("ip", "", "target IPs (comma-separated)")
	cidrs := flag.String("cidr", "", "target CIDRs (comma-separated)")
	wordlist := flag.String("wl", "", "subdomain wordlist file")
	resolvers := flag.String("r", "", "resolvers file")
	ports := flag.String("p", "", "ports to scan (comma-separated)")
	topPorts := flag.Int("tp", 0, "top N ports to scan")
	threads := flag.Int("c", 25, "concurrency")
	timeout := flag.Duration("timeout", 5*time.Second, "connection timeout")
	httpTimeout := flag.Duration("http-timeout", 10*time.Second, "HTTP timeout")
	crawlDepth := flag.Int("cd", 2, "crawl depth")
	crawlMax := flag.Int("cm", 50, "max pages to crawl")
	cloudProviders := flag.String("cp", "", "cloud providers (comma-separated: s3,gcs,azure,digitalocean)")
	skipDNS := flag.Bool("skip-dns", false, "skip DNS enumeration")
	skipPort := flag.Bool("skip-port", false, "skip port scanning")
	skipWeb := flag.Bool("skip-web", false, "skip web crawling")
	skipCloud := flag.Bool("skip-cloud", true, "skip cloud enumeration")
	outputJSON := flag.String("oJ", "", "output JSON file")
	outputText := flag.String("o", "", "output text file")
	help := flag.Bool("h", false, "show help")
	flag.Parse()

	if *help || (len(os.Args) == 1) {
		fmt.Println(`nuclei-discover — target topology discovery

Usage:
  nuclei-discover [options]

Target Options:
  -d <domains>         Target domains (comma-separated)
  -df <file>           Target domains file (one per line)
  -ip <ips>            Target IPs (comma-separated)
  -cidr <cidrs>        Target CIDRs (comma-separated)

DNS Options:
  -wl <file>           Subdomain wordlist file
  -r <file>            Resolvers file

Port Scan Options:
  -p <ports>           Ports to scan (comma-separated)
  -tp <n>              Top N ports (use built-in list)

Web Crawl Options:
  -cd <n>              Crawl depth (default 2)
  -cm <n>              Max pages to crawl (default 50)

Cloud Enum Options:
  -cp <providers>      Cloud providers: s3,gcs,azure,digitalocean

General Options:
  -c <n>               Concurrency (default 25)
  -timeout <dur>       Connection timeout (default 5s)
  -http-timeout <dur>  HTTP timeout (default 10s)
  -skip-dns            Skip DNS enumeration
  -skip-port           Skip port scanning
  -skip-web            Skip web crawling
  -skip-cloud          Skip cloud enumeration (default true)

Output:
  -oJ <file>           Output JSON file
  -o <file>            Output text file

Examples:
  nuclei-discover -d example.com
  nuclei-discover -d example.com -skip-dns -skip-cloud
  nuclei-discover -ip 192.168.1.1 -p 22,80,443,3306
  nuclei-discover -d example.com -cp s3,gcs -skip-dns`)
		os.Exit(0)
	}

	cfg := discovery.DefaultConfig()

	if *domains != "" {
		cfg.Domains = splitComma(*domains)
	}
	if *domainsFile != "" {
		cfg.Domains = append(cfg.Domains, readFileLines(*domainsFile)...)
	}
	if *ips != "" {
		cfg.IPs = splitComma(*ips)
	}
	if *cidrs != "" {
		cfg.CIDRs = splitComma(*cidrs)
	}
	if *wordlist != "" {
		cfg.Wordlist = *wordlist
	}
	if *resolvers != "" {
		cfg.ResolverFile = *resolvers
	}
	if *ports != "" {
		cfg.Ports = parsePorts(*ports)
	}
	if *topPorts > 0 {
		cfg.Ports = discovery.DefaultPorts[:min(*topPorts, len(discovery.DefaultPorts))]
	}
	if *cloudProviders != "" {
		cfg.CloudProviders = splitComma(*cloudProviders)
		cfg.SkipCloud = false
	}

	cfg.Threads = *threads
	cfg.Timeout = *timeout
	cfg.HTTPTimeout = *httpTimeout
	cfg.CrawlDepth = *crawlDepth
	cfg.CrawlMaxPages = *crawlMax
	cfg.SkipDNS = *skipDNS
	cfg.SkipPortScan = *skipPort
	cfg.SkipWebCrawl = *skipWeb
	cfg.SkipCloud = *skipCloud

	if len(cfg.Domains) == 0 && len(cfg.IPs) == 0 && len(cfg.CIDRs) == 0 {
		fmt.Fprintln(os.Stderr, "[ERR] no targets specified. Use -d, -ip, or -cidr")
		os.Exit(1)
	}

	fmt.Printf("[discovery] starting with %d domains, %d IPs, %d CIDRs\n",
		len(cfg.Domains), len(cfg.IPs), len(cfg.CIDRs))
	fmt.Printf("[discovery] DNS=%v PortScan=%v WebCrawl=%v Cloud=%v\n",
		!cfg.SkipDNS, !cfg.SkipPortScan, !cfg.SkipWebCrawl, !cfg.SkipCloud)

	d := discovery.New(cfg)
	ctx := context.Background()

	start := time.Now()
	result, err := d.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] discovery failed: %s\n", err)
		os.Exit(1)
	}
	elapsed := time.Since(start)

	fmt.Printf("\n[discovery] completed in %s\n", elapsed)
	printSummary(result)

	if *outputJSON != "" {
		data, _ := json.MarshalIndent(result, "", "  ")
		os.WriteFile(*outputJSON, data, 0644)
		fmt.Printf("[discovery] JSON results written to %s\n", *outputJSON)
	}

	if *outputText != "" {
		data := formatTextResult(result)
		os.WriteFile(*outputText, []byte(data), 0644)
		fmt.Printf("[discovery] text results written to %s\n", *outputText)
	}
}

func printSummary(r *discovery.Result) {
	fmt.Println("\n=== Discovery Summary ===")
	if len(r.Domains) > 0 {
		totalSubs := 0
		for _, d := range r.Domains {
			totalSubs += len(d.Subdomains)
		}
		fmt.Printf("  Domains:     %d (%d subdomains found)\n", len(r.Domains), totalSubs)
	}
	if len(r.Hosts) > 0 {
		totalPorts := 0
		for _, h := range r.Hosts {
			totalPorts += len(h.OpenPorts)
		}
		fmt.Printf("  Hosts:       %d (%d open ports)\n", len(r.Hosts), totalPorts)
	}
	if len(r.Services) > 0 {
		fmt.Printf("  Services:    %d\n", len(r.Services))
	}
	if len(r.WebApps) > 0 {
		fmt.Printf("  Web Apps:    %d\n", len(r.WebApps))
	}
	if len(r.CloudReqs) > 0 {
		public := 0
		for _, c := range r.CloudReqs {
			if c.Public {
				public++
			}
		}
		fmt.Printf("  Cloud:       %d resources (%d public)\n", len(r.CloudReqs), public)
	}
	if len(r.Errors) > 0 {
		fmt.Printf("  Errors:      %d\n", len(r.Errors))
	}

	fmt.Println("\n=== Details ===")
	for _, d := range r.Domains {
		fmt.Printf("\n[Domain] %s\n", d.Domain)
		if d.HasWildcard {
			fmt.Println("  ⚠ wildcard DNS detected")
		}
		if len(d.Nameservers) > 0 {
			fmt.Printf("  NS: %s\n", strings.Join(d.Nameservers, ", "))
		}
		if len(d.MXRecords) > 0 {
			fmt.Printf("  MX: %s\n", strings.Join(d.MXRecords, ", "))
		}
		if len(d.Subdomains) > 0 {
			for _, s := range d.Subdomains {
				fmt.Printf("  → %s\n", s)
			}
		}
	}

	for _, h := range r.Hosts {
		fmt.Printf("\n[Host] %s (%s)\n", h.Host, h.IP)
		for _, p := range h.OpenPorts {
			banner := ""
			if p.Banner != "" {
				banner = " — " + truncate(p.Banner, 60)
			}
			fmt.Printf("  %d/tcp open  %s%s\n", p.Port, p.Service, banner)
		}
	}

	for _, w := range r.WebApps {
		fmt.Printf("\n[Web] %s (HTTP %d)\n", w.URL, w.Status)
		if w.Title != "" {
			fmt.Printf("  Title: %s\n", w.Title)
		}
		if len(w.Tech) > 0 {
			fmt.Printf("  Tech:  %s\n", strings.Join(w.Tech, ", "))
		}
		if len(w.Forms) > 0 {
			fmt.Printf("  Forms: %d\n", len(w.Forms))
		}
		if len(w.Links) > 0 {
			fmt.Printf("  Links: %d\n", len(w.Links))
		}
		if len(w.JSFiles) > 0 {
			fmt.Printf("  JS:    %d files\n", len(w.JSFiles))
		}
	}

	for _, c := range r.CloudReqs {
		status := "private"
		if c.Public {
			status = "PUBLIC"
		}
		fmt.Printf("\n[Cloud] %s://%s (%s, HTTP %d)\n", c.Provider, c.Name, status, c.Status)
		fmt.Printf("  URL: %s\n", c.URL)
	}

	for _, e := range r.Errors {
		fmt.Printf("\n[ERR] %s\n", e)
	}
}

func formatTextResult(r *discovery.Result) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Discovery Results — %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Domains: %d, Hosts: %d, Services: %d, WebApps: %d, Cloud: %d\n\n",
		len(r.Domains), len(r.Hosts), len(r.Services), len(r.WebApps), len(r.CloudReqs)))

	for _, d := range r.Domains {
		sb.WriteString(fmt.Sprintf("DOMAIN: %s\n", d.Domain))
		for _, s := range d.Subdomains {
			sb.WriteString(fmt.Sprintf("  SUB: %s\n", s))
		}
	}
	for _, h := range r.Hosts {
		sb.WriteString(fmt.Sprintf("HOST: %s (%s)\n", h.Host, h.IP))
		for _, p := range h.OpenPorts {
			sb.WriteString(fmt.Sprintf("  PORT: %d/%s\n", p.Port, p.Service))
		}
	}
	for _, w := range r.WebApps {
		sb.WriteString(fmt.Sprintf("WEB: %s [%d] %s\n", w.URL, w.Status, w.Title))
		sb.WriteString(fmt.Sprintf("  TECH: %s\n", strings.Join(w.Tech, ",")))
	}
	for _, c := range r.CloudReqs {
		sb.WriteString(fmt.Sprintf("CLOUD: %s/%s exists=%v public=%v\n", c.Provider, c.Name, c.Exists, c.Public))
	}

	return sb.String()
}

func splitComma(s string) []string {
	var result []string
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			result = append(result, v)
		}
	}
	return result
}

func readFileLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

func parsePorts(s string) []int {
	var ports []int
	for _, v := range strings.Split(s, ",") {
		var p int
		if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &p); err == nil {
			if p > 0 && p < 65536 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
