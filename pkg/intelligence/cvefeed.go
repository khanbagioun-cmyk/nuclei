package intelligence

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const nvdAPIBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDCVE represents a single CVE from the NVD API
type NVDCVE struct {
	ID            string         `json:"id"`
	SourceID      string         `json:"sourceIdentifier"`
	Published     string         `json:"published"`
	LastModified  string         `json:"lastModified"`
	VulnStatus    string         `json:"vulnStatus"`
	Descriptions  []NVDDescription `json:"descriptions"`
	Affected      []NVDAffected  `json:"affected,omitempty"`
	Metrics       NVDMetrics     `json:"metrics,omitempty"`
	Weaknesses    []NVDWeakness  `json:"weaknesses,omitempty"`
	References    []NVDReference `json:"references,omitempty"`
	CISAExploitAdd string        `json:"cisaExploitAdd,omitempty"`
	CISAActionDue string        `json:"cisaActionDue,omitempty"`
}

type NVDDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type NVDAffected struct {
	Source      string           `json:"source"`
	AffectedData []NVDAffectedData `json:"affectedData,omitempty"`
}

type NVDAffectedData struct {
	Vendor        string         `json:"vendor"`
	Product       string         `json:"product"`
	DefaultStatus string         `json:"defaultStatus,omitempty"`
	CPEs          []string       `json:"cpes,omitempty"`
	Versions      []NVDVersion   `json:"versions,omitempty"`
}

type NVDVersion struct {
	Version     string `json:"version"`
	LessThan    string `json:"lessThan,omitempty"`
	VersionType string `json:"versionType,omitempty"`
	Status      string `json:"status"`
}

type NVDMetrics struct {
	CVSSv31 []CVSSv31 `json:"cvssMetricV31,omitempty"`
	CVSSv2  []CVSSv2  `json:"cvssMetricV2,omitempty"`
}

type CVSSv31 struct {
	Source             string        `json:"source"`
	Type               string        `json:"type"`
	CVSSData           CVSSData31    `json:"cvssData"`
	ExploitabilityScore float64      `json:"exploitabilityScore,omitempty"`
	ImpactScore        float64       `json:"impactScore,omitempty"`
}

type CVSSData31 struct {
	Version       string  `json:"version"`
	VectorString  string  `json:"vectorString"`
	BaseScore     float64 `json:"baseScore"`
	BaseSeverity  string  `json:"baseSeverity"`
}

type CVSSv2 struct {
	Source             string        `json:"source"`
	Type               string        `json:"type"`
	CVSSData           CVSSData2     `json:"cvssData"`
}

type CVSSData2 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
}

type NVDWeakness struct {
	Source      string           `json:"source"`
	Type        string           `json:"type"`
	Description []NVDDescription `json:"description"`
}

type NVDReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags,omitempty"`
}

// NVDResponse is the top-level API response
type NVDResponse struct {
	ResultsPerPage int      `json:"resultsPerPage"`
	StartIndex     int      `json:"startIndex"`
	TotalResults   int      `json:"totalResults"`
	Format         string   `json:"format"`
	Version        string   `json:"version"`
	Timestamp      string   `json:"timestamp"`
	Vulnerabilities []struct {
		CVE NVDCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

// CVEFeedConfig configures the NVD feed fetcher
type CVEFeedConfig struct {
	APIKey       string
	ResultsPerPage int
	StartIndex   int
	PubStartDate string  // YYYY-MM-DDTHH:mm:ss.sss
	PubEndDate   string
	CVEID       string  // specific CVE
	KeywordSearch string
	HTTPTimeout  time.Duration
}

// DefaultCVEFeedConfig returns sensible defaults
func DefaultCVEFeedConfig() CVEFeedConfig {
	now := time.Now()
	return CVEFeedConfig{
		ResultsPerPage: 50,
		StartIndex:     0,
		PubStartDate:   now.AddDate(0, 0, -7).Format("2006-01-02T15:04:05.000"),
		PubEndDate:     now.Format("2006-01-02T15:04:05.000"),
		HTTPTimeout:    30 * time.Second,
	}
}

// FetchCVEs queries the NVD API and returns parsed CVEs
func FetchCVEs(cfg CVEFeedConfig) ([]NVDCVE, error) {
	params := url.Values{}
	if cfg.CVEID != "" {
		params.Set("cveId", cfg.CVEID)
	} else {
		params.Set("resultsPerPage", fmt.Sprintf("%d", cfg.ResultsPerPage))
		params.Set("startIndex", fmt.Sprintf("%d", cfg.StartIndex))
		if cfg.PubStartDate != "" {
			params.Set("pubStartDate", cfg.PubStartDate)
		}
		if cfg.PubEndDate != "" {
			params.Set("pubEndDate", cfg.PubEndDate)
		}
		if cfg.KeywordSearch != "" {
			params.Set("keywordSearch", cfg.KeywordSearch)
		}
	}

	reqURL := nvdAPIBase + "?" + params.Encode()

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if cfg.APIKey != "" {
		req.Header.Set("apiKey", cfg.APIKey)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: cfg.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching NVD: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API returned %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("parsing NVD JSON: %w", err)
	}

	cves := make([]NVDCVE, len(nvdResp.Vulnerabilities))
	for i, v := range nvdResp.Vulnerabilities {
		cves[i] = v.CVE
	}
	return cves, nil
}

// FetchSingleCVE fetches a specific CVE by ID
func FetchSingleCVE(cveID string, apiKey string) (*NVDCVE, error) {
	cfg := CVEFeedConfig{
		CVEID:      cveID,
		APIKey:     apiKey,
		HTTPTimeout: 30 * time.Second,
	}
	cves, err := FetchCVEs(cfg)
	if err != nil {
		return nil, err
	}
	if len(cves) == 0 {
		return nil, fmt.Errorf("CVE %s not found", cveID)
	}
	return &cves[0], nil
}

// GetEnglishDescription returns the English description
func (c *NVDCVE) GetEnglishDescription() string {
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(c.Descriptions) > 0 {
		return c.Descriptions[0].Value
	}
	return ""
}

// GetPrimaryCPE returns the first CPE from affected data
func (c *NVDCVE) GetPrimaryCPE() string {
	for _, aff := range c.Affected {
		for _, ad := range aff.AffectedData {
			if len(ad.CPEs) > 0 {
				return ad.CPEs[0]
			}
		}
	}
	return ""
}

// GetVendorProduct extracts vendor and product from CPE or affected data
func (c *NVDCVE) GetVendorProduct() (vendor, product string) {
	for _, aff := range c.Affected {
		for _, ad := range aff.AffectedData {
			if ad.Vendor != "" && ad.Product != "" {
				return ad.Vendor, ad.Product
			}
		}
	}
	cpe := c.GetPrimaryCPE()
	if cpe != "" {
		parts := strings.Split(cpe, ":")
		if len(parts) >= 5 {
			return parts[3], parts[4]
		}
	}
	return "", ""
}

// GetCVSSScore returns the CVSS v3.1 base score (or v2 fallback)
func (c *NVDCVE) GetCVSSScore() float64 {
	if len(c.Metrics.CVSSv31) > 0 {
		return c.Metrics.CVSSv31[0].CVSSData.BaseScore
	}
	if len(c.Metrics.CVSSv2) > 0 {
		return c.Metrics.CVSSv2[0].CVSSData.BaseScore
	}
	return 0
}

// GetCVSSVector returns the CVSS v3.1 vector string
func (c *NVDCVE) GetCVSSVector() string {
	if len(c.Metrics.CVSSv31) > 0 {
		return c.Metrics.CVSSv31[0].CVSSData.VectorString
	}
	if len(c.Metrics.CVSSv2) > 0 {
		return c.Metrics.CVSSv2[0].CVSSData.VectorString
	}
	return ""
}

// GetSeverity returns severity string based on CVSS score
func (c *NVDCVE) GetSeverity() string {
	if len(c.Metrics.CVSSv31) > 0 {
		return strings.ToLower(c.Metrics.CVSSv31[0].CVSSData.BaseSeverity)
	}
	score := c.GetCVSSScore()
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

// GetCWE returns the first CWE ID
func (c *NVDCVE) GetCWE() string {
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				return d.Value
			}
		}
	}
	return ""
}

// IsCISAKEV returns true if CVE is in CISA Known Exploited Vulnerabilities catalog
func (c *NVDCVE) IsCISAKEV() bool {
	return c.CISAExploitAdd != ""
}

// GetReferenceURLs returns all reference URLs
func (c *NVDCVE) GetReferenceURLs() []string {
	urls := make([]string, len(c.References))
	for i, r := range c.References {
		urls[i] = r.URL
	}
	return urls
}

// GetAffectedVersions returns version ranges from affected data
func (c *NVDCVE) GetAffectedVersions() []VersionRange {
	var ranges []VersionRange
	for _, aff := range c.Affected {
		for _, ad := range aff.AffectedData {
			for _, v := range ad.Versions {
				if v.Status == "affected" {
					ranges = append(ranges, VersionRange{
						From:       v.Version,
						To:         v.LessThan,
						VersionType: v.VersionType,
					})
				}
			}
		}
	}
	return ranges
}

// VersionRange represents an affected version range
type VersionRange struct {
	From       string
	To         string
	VersionType string
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
