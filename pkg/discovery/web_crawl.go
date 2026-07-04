package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TechFingerprints maps header/body patterns to technology names
var TechFingerprints = []struct {
	Pattern string
	Tech    string
	Header  bool
}{
	{`(?i)x-powered-by:\s*PHP`, "PHP", true},
	{`(?i)x-powered-by:\s*ASP\.NET`, "ASP.NET", true},
	{`(?i)x-powered-by:\s*Express`, "Express", true},
	{`(?i)x-aspnet-version`, "ASP.NET", true},
	{`(?i)server:\s*nginx`, "Nginx", true},
	{`(?i)server:\s*Apache`, "Apache", true},
	{`(?i)server:\s*cloudflare`, "Cloudflare", true},
	{`(?i)server:\s*Microsoft-IIS`, "IIS", true},
	{`(?i)server:\s*gunicorn`, "Gunicorn", true},
	{`(?i)server:\s*jetty`, "Jetty", true},
	{`(?i)x-amz-cf-id`, "CloudFront", true},
	{`(?i)x-vercel-id`, "Vercel", true},
	{`(?i)x-served-by:\s*cache`, "Fastly", true},
	{`(?i)set-cookie:\s*wp-settings`, "WordPress", true},
	{`(?i)set-cookie:\s*JSESSIONID`, "Java", true},
	{`(?i)set-cookie:\s*PHPSESSID`, "PHP", true},
	{`(?i)set-cookie:\s*csrf_token`, "Django", true},
	{`(?i)set-cookie:\s*connect\.sid`, "Express", true},
	{`(?i)set-cookie:\s*laravel_session`, "Laravel", true},
	{`(?i)set-cookie:\s*rack\.session`, "Ruby-on-Rails", true},
	{`(?i)x-drupal-cache`, "Drupal", true},
	{`(?i)x-generator:\s*Drupal`, "Drupal", true},
	{`(?i)x-Generator:\s*joomla`, "Joomla", true},
	{`(?i)wp-content`, "WordPress", false},
	{`(?i)wp-includes`, "WordPress", false},
	{`(?i)cdn\.jsdelivr\.net/bootstrap`, "Bootstrap", false},
	{`(?i)react\.production`, "React", false},
	{`(?i)vue\.runtime`, "Vue.js", false},
	{`(?i)angular\.min\.js`, "Angular", false},
	{`(?i)jquery`, "jQuery", false},
	{`(?i)next\.js`, "Next.js", false},
	{`(?i)nuxt`, "Nuxt.js", false},
	{`(?i)gatsby`, "Gatsby", false},
	{`(?i)svelte`, "Svelte", false},
}

var (
	linkRegex   = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
	jsRegex     = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	formRegex   = regexp.MustCompile(`(?is)<form[^>]*>.*?</form>`)
	formActionRegex = regexp.MustCompile(`(?i)action\s*=\s*["']([^"']+)["']`)
	formMethodRegex = regexp.MustCompile(`(?i)method\s*=\s*["']([^"']+)["']`)
	inputRegex  = regexp.MustCompile(`(?is)<input[^>]*>`)
	inputNameRegex = regexp.MustCompile(`(?i)name\s*=\s*["']([^"']+)["']`)
	inputTypeRegex = regexp.MustCompile(`(?i)type\s*=\s*["']([^"']+)["']`)
	titleRegex  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

// httpClient creates a configured HTTP client
func (d *Discovery) httpClient() *http.Client {
	return &http.Client{
		Timeout: d.config.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:  false,
			MaxIdleConns:       100,
			MaxIdleConnsPerHost: 10,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}
}

// runWebCrawl crawls discovered HTTP services
func (d *Discovery) runWebCrawl(ctx context.Context) {
	targets := d.collectWebTargets()
	if len(targets) == 0 {
		return
	}

	sem := make(chan struct{}, d.config.Threads)
	var wg sync.WaitGroup

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d.crawlURL(ctx, t, 0)
		}(target)
	}
	wg.Wait()
}

func (d *Discovery) collectWebTargets() []string {
	var targets []string
	seen := make(map[string]bool)

	addTarget := func(host string, port int, https bool) {
		scheme := "http"
		if https {
			scheme = "https"
		}
		u := fmt.Sprintf("%s://%s", scheme, net_JoinHostPort(host, port))
		if !seen[u] {
			seen[u] = true
			targets = append(targets, u)
		}
	}

	d.mu.Lock()
	for _, hr := range d.result.Hosts {
		for _, pr := range hr.OpenPorts {
			switch pr.Service {
			case "http", "http-proxy":
				addTarget(hr.Host, pr.Port, false)
			case "https", "https-alt":
				addTarget(hr.Host, pr.Port, true)
			}
		}
	}
	for _, sr := range d.result.Services {
		switch sr.Service {
		case "http", "http-proxy":
			addTarget(sr.Host, sr.Port, false)
		case "https", "https-alt":
			addTarget(sr.Host, sr.Port, true)
		}
	}
	d.mu.Unlock()

	if len(targets) == 0 {
		for _, domain := range d.config.Domains {
			addTarget(domain, 80, false)
			addTarget(domain, 443, true)
		}
	}

	return targets
}

// crawlURL crawls a URL up to maxDepth, collecting links/forms/tech
func (d *Discovery) crawlURL(ctx context.Context, targetURL string, depth int) {
	if depth >= d.config.CrawlDepth {
		return
	}

	client := d.httpClient()
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", d.config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return
	}

	result := WebAppResult{
		URL:     targetURL,
		Status:  resp.StatusCode,
		Headers: extractHeaders(resp.Header),
		Tech:    detectTech(resp.Header, body),
		Links:   extractLinks(targetURL, body),
		JSFiles: extractJSFiles(targetURL, body),
		Forms:   extractForms(body),
	}

	if title := titleRegex.FindSubmatch(body); len(title) > 1 {
		result.Title = strings.TrimSpace(string(title[1]))
	}

	d.addWebAppResult(result)

	if depth+1 < d.config.CrawlDepth {
		d.crawlSubLinks(ctx, targetURL, result.Links, depth+1)
	}
}

func (d *Discovery) crawlSubLinks(ctx context.Context, baseURL string, links []string, depth int) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return
	}

	visited := make(map[string]bool)
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for _, link := range links {
		if d.visitedCount(visited) >= d.config.CrawlMaxPages {
			break
		}

		absLink := resolveURL(base, link)
		if absLink == "" || visited[absLink] {
			continue
		}
		if !sameHost(base, absLink) {
			continue
		}
		visited[absLink] = true

		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d.crawlURL(ctx, u, depth)
		}(absLink)
	}
	wg.Wait()
}

func (d *Discovery) visitedCount(m map[string]bool) int {
	return len(m)
}

func extractHeaders(h http.Header) map[string]string {
	result := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			result[k] = v[0]
		}
	}
	return result
}

func detectTech(headers http.Header, body []byte) []string {
	techSet := make(map[string]bool)

	var headerBuf strings.Builder
	for k, v := range headers {
		for _, val := range v {
			headerBuf.WriteString(fmt.Sprintf("%s: %s\n", k, val))
		}
	}
	headerStr := headerBuf.String()
	bodyStr := string(body)

	for _, fp := range TechFingerprints {
		re := regexp.MustCompile(fp.Pattern)
		searchIn := bodyStr
		if fp.Header {
			searchIn = headerStr
		}
		if re.MatchString(searchIn) {
			techSet[fp.Tech] = true
		}
	}

	var techs []string
	for t := range techSet {
		techs = append(techs, t)
	}
	return techs
}

func extractLinks(baseURL string, body []byte) []string {
	matches := linkRegex.FindAllSubmatch(body, -1)
	seen := make(map[string]bool)
	var links []string
	base, _ := url.Parse(baseURL)

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		link := string(m[1])
		abs := resolveURL(base, link)
		if abs != "" && !seen[abs] {
			seen[abs] = true
			links = append(links, abs)
		}
	}
	return links
}

func extractJSFiles(baseURL string, body []byte) []string {
	matches := jsRegex.FindAllSubmatch(body, -1)
	seen := make(map[string]bool)
	var jsFiles []string
	base, _ := url.Parse(baseURL)

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		src := string(m[1])
		abs := resolveURL(base, src)
		if abs != "" && !seen[abs] {
			seen[abs] = true
			jsFiles = append(jsFiles, abs)
		}
	}
	return jsFiles
}

func extractForms(body []byte) []FormInfo {
	var forms []FormInfo
	formMatches := formRegex.FindAll(body, -1)
	for _, formHTML := range formMatches {
		fi := FormInfo{}
		if m := formActionRegex.FindSubmatch(formHTML); len(m) > 1 {
			fi.Action = string(m[1])
		}
		if m := formMethodRegex.FindSubmatch(formHTML); len(m) > 1 {
			fi.Method = strings.ToUpper(string(m[1]))
		} else {
			fi.Method = "GET"
		}
		inputMatches := inputRegex.FindAll(formHTML, -1)
		for _, inputHTML := range inputMatches {
			field := FormField{}
			if m := inputNameRegex.FindSubmatch(inputHTML); len(m) > 1 {
				field.Name = string(m[1])
			}
			if m := inputTypeRegex.FindSubmatch(inputHTML); len(m) > 1 {
				field.Type = strings.ToLower(string(m[1]))
			} else {
				field.Type = "text"
			}
			if field.Name != "" {
				fi.Inputs = append(fi.Inputs, field)
			}
		}
		forms = append(forms, fi)
	}
	return forms
}

func resolveURL(base *url.URL, link string) string {
	if link == "" || strings.HasPrefix(link, "#") || strings.HasPrefix(link, "javascript:") || strings.HasPrefix(link, "mailto:") {
		return ""
	}
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

func sameHost(base *url.URL, absURL string) bool {
	u, err := url.Parse(absURL)
	if err != nil {
		return false
	}
	return u.Hostname() == base.Hostname()
}

// CrawlSingleURL crawls a single URL — exported for testing/external use
func (d *Discovery) CrawlSingleURL(ctx context.Context, targetURL string) WebAppResult {
	client := d.httpClient()
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return WebAppResult{URL: targetURL}
	}
	req.Header.Set("User-Agent", d.config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return WebAppResult{URL: targetURL}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))

	result := WebAppResult{
		URL:     targetURL,
		Status:  resp.StatusCode,
		Headers: extractHeaders(resp.Header),
		Tech:    detectTech(resp.Header, body),
		Links:   extractLinks(targetURL, body),
		JSFiles: extractJSFiles(targetURL, body),
		Forms:   extractForms(body),
	}
	if title := titleRegex.FindSubmatch(body); len(title) > 1 {
		result.Title = strings.TrimSpace(string(title[1]))
	}
	return result
}

// net_JoinHostPort wraps net.JoinHostPort to avoid importing net twice
func net_JoinHostPort(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// unused but kept for future timestamp support
var _ = time.Now
