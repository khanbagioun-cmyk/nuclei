package intelligence

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const githubAPIBase = "https://api.github.com"

// PoCResult represents a proof-of-concept found on GitHub
type PoCResult struct {
	RepoURL       string
	Description   string
	Path          string
	RawURL        string
	Stars         int
	Language      string
	HasExploitCode bool
	ExploitType   string  // "http", "python", "bash", "go"
}

// GitHubSearchResponse represents GitHub search API response
type GitHubSearchResponse struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		Name        string `json:"name"`
		Path        string `json:"path"`
		HTMLURL     string `json:"html_url"`
		URL         string `json:"url"`
		Repository  struct {
			FullName     string `json:"full_name"`
			HTMLURL      string `json:"html_url"`
			Stargazers   int    `json:"stargazers_count"`
		} `json:"repository"`
		Score       float64 `json:"score"`
	} `json:"items"`
}

// PoCMatcher searches GitHub for PoCs and uses them to enhance templates
type PoCMatcher struct {
	Token      string
	HTTPClient *http.Client
}

// NewPoCMatcher creates a PoC matcher
func NewPoCMatcher(token string) *PoCMatcher {
	return &PoCMatcher{
		Token: token,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// SearchPoCs searches GitHub for exploit PoCs for a given CVE
func (p *PoCMatcher) SearchPoCs(cveID string) ([]PoCResult, error) {
	queries := []string{
		fmt.Sprintf("%s poc", cveID),
		fmt.Sprintf("%s exploit", cveID),
		fmt.Sprintf("%s CVE", cveID),
	}

	var allResults []PoCResult
	seen := make(map[string]bool)

	for _, q := range queries {
		results, err := p.searchCode(q)
		if err != nil {
			continue
		}
		for _, r := range results {
			if !seen[r.RawURL] {
				seen[r.RawURL] = true
				allResults = append(allResults, r)
			}
		}
		if len(allResults) >= 10 {
			break
		}
	}

	return allResults, nil
}

func (p *PoCMatcher) searchCode(query string) ([]PoCResult, error) {
	params := url.Values{}
	params.Set("q", query)
	params.Set("per_page", "5")
	params.Set("sort", "stars")
	params.Set("order", "desc")

	req, err := http.NewRequest("GET", githubAPIBase+"/search/code?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if p.Token != "" {
		req.Header.Set("Authorization", "token "+p.Token)
	}

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var searchResp GitHubSearchResponse
	if err := json.Unmarshal(body, &searchResp); err != nil {
		return nil, err
	}

	var results []PoCResult
	for _, item := range searchResp.Items {
		rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/master/%s",
			item.Repository.FullName, item.Path)

		poc := PoCResult{
			RepoURL:     item.Repository.HTMLURL,
			Description: item.Name,
			Path:        item.Path,
			RawURL:      rawURL,
			Stars:       item.Repository.Stargazers,
		}
		poc.ExploitType = classifyExploitFile(item.Name)
		poc.HasExploitCode = poc.ExploitType != ""
		results = append(results, poc)
	}

	return results, nil
}

// EnhanceTemplate uses PoC data to improve a synthesized template
func (p *PoCMatcher) EnhanceTemplate(tmpl *SynthesizedTemplate, pocs []PoCResult) {
	if len(pocs) == 0 {
		return
	}

	for _, poc := range pocs {
		if !poc.HasExploitCode {
			continue
		}

		// Fetch PoC content to extract paths and payloads
		content, err := p.fetchContent(poc.RawURL)
		if err != nil {
			continue
		}

		extractedPaths := extractHTTPPaths(content)
		for _, path := range extractedPaths {
			if !templateHasPath(tmpl, path) {
				tmpl.HTTPRequests = append(tmpl.HTTPRequests, HTTPRequestSpec{
					Method: "GET",
					Path:   path,
				})
			}
		}

		extractedPayloads := extractPayloads(content)
		if len(extractedPayloads) > 0 {
			for _, payload := range extractedPayloads {
				tmpl.Matchers = append(tmpl.Matchers, MatcherSpec{
					Type:      "word",
					Part:      "body",
					Words:     []string{payload},
					Condition: "or",
				})
			}
		}

		tmpl.Tags = append(tmpl.Tags, "poc")
		tmpl.Confidence = min64(tmpl.Confidence+0.15, 1.0)
		tmpl.GenerationMethod = "poc-enhanced"
		break // Only use first valid PoC
	}
}

func (p *PoCMatcher) fetchContent(rawURL string) (string, error) {
	resp, err := p.HTTPClient.Get(rawURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func classifyExploitFile(filename string) string {
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".py"):
		return "python"
	case strings.HasSuffix(lower, ".sh"):
		return "bash"
	case strings.HasSuffix(lower, ".go"):
		return "go"
	case strings.HasSuffix(lower, ".rb"):
		return "ruby"
	case strings.HasSuffix(lower, ".js"):
		return "javascript"
	case strings.HasSuffix(lower, ".http"):
		return "http"
	case strings.HasSuffix(lower, ".yaml"), strings.HasSuffix(lower, ".yml"):
		return "yaml"
	default:
		return ""
	}
}

var httpPathRegex = regexp.MustCompile(`(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(/[a-zA-Z0-9_\-/.?=&+%]+)`)

func extractHTTPPaths(content string) []string {
	matches := httpPathRegex.FindAllStringSubmatch(content, -1)
	var paths []string
	seen := make(map[string]bool)
	for _, m := range matches {
		path := strings.Split(m[1], "?")[0] // strip query params
		if len(path) > 3 && len(path) < 100 && !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	return paths
}

func extractPayloads(content string) []string {
	var payloads []string
	// Look for common exploit indicators
	patterns := []string{
		`"root:[x*]:"`,
		`"uid=\d+"`,
		`"whoami"`,
		`"id:"`,
		`"success"`,
		`"vulnerable"`,
		`"exploit"`,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if re.MatchString(content) {
			matches := re.FindAllString(content, -1)
			payloads = append(payloads, matches...)
		}
	}
	return payloads
}

func templateHasPath(tmpl *SynthesizedTemplate, path string) bool {
	for _, req := range tmpl.HTTPRequests {
		if req.Path == path {
			return true
		}
	}
	return false
}

func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
