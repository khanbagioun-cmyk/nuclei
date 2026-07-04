package intelligence

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const vulncheckKEVURL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"

// VulnCheckKEVEntry represents a single entry in the VulnCheck KEV catalog
type VulnCheckKEVEntry struct {
	VendorProject                   string           `json:"vendorProject"`
	Product                         string           `json:"product"`
	ShortDescription                string           `json:"shortDescription"`
	VulnerabilityName               string           `json:"vulnerabilityName"`
	RequiredAction                  string           `json:"required_action"`
	KnownRansomwareCampaignUse      string           `json:"knownRansomwareCampaignUse"`
	CVE                             []string         `json:"cve"`
	VulnCheckXDB                    []XDBEntry       `json:"vulncheck_xdb"`
	VulnCheckReportedExploitation   []ReportedExploit `json:"vulncheck_reported_exploitation"`
	ReportedExploitedByVulnCheck    bool             `json:"reported_exploited_by_vulncheck_canaries"`
	DueDate                         *time.Time       `json:"dueDate,omitempty"`
	CISADateAdded                   *time.Time       `json:"cisa_date_added,omitempty"`
	DateAdded                       time.Time        `json:"date_added"`
}

// XDBEntry represents a VulnCheck XDB exploit reference
type XDBEntry struct {
	XDBID       string    `json:"xdb_id"`
	XDBURL      string    `json:"xdb_url"`
	DateAdded   time.Time `json:"date_added"`
	ExploitType string    `json:"exploit_type"`
	CloneSSHURL string    `json:"clone_ssh_url"`
}

// ReportedExploit represents a reported exploitation reference
type ReportedExploit struct {
	URL       string    `json:"url"`
	DateAdded time.Time `json:"date_added"`
}

// VulnCheckKEVCatalog represents the top-level VulnCheck KEV API response
type VulnCheckKEVCatalog struct {
	Data    []VulnCheckKEVEntry `json:"data"`
	Meta    interface{}         `json:"meta,omitempty"`
}

// FetchVulnCheckKEV downloads and parses the VulnCheck KEV catalog.
// Requires VULNCHECK_API_TOKEN environment variable.
func FetchVulnCheckKEV() (*VulnCheckKEVCatalog, error) {
	token := os.Getenv("VULNCHECK_API_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("VULNCHECK_API_TOKEN environment variable not set; register at https://console.vulncheck.com")
	}
	return FetchVulnCheckKEVWithToken(token)
}

// FetchVulnCheckKEVWithToken downloads the VulnCheck KEV catalog with an explicit token
func FetchVulnCheckKEVWithToken(token string) (*VulnCheckKEVCatalog, error) {
	client := &http.Client{Timeout: 60 * time.Second}

	req, err := http.NewRequest("GET", vulncheckKEVURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating VulnCheck KEV request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching VulnCheck KEV feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("VulnCheck KEV: unauthorized (401) — check your API token")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VulnCheck KEV feed returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading VulnCheck KEV response: %w", err)
	}

	var catalog VulnCheckKEVCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("parsing VulnCheck KEV JSON: %w", err)
	}

	return &catalog, nil
}

// GetVulnCheckKEVByCVE returns the VulnCheck KEV entry for a specific CVE ID, if present
func (c *VulnCheckKEVCatalog) GetVulnCheckKEVByCVE(cveID string) (*VulnCheckKEVEntry, bool) {
	for i := range c.Data {
		for _, cve := range c.Data[i].CVE {
			if strings.EqualFold(cve, cveID) {
				return &c.Data[i], true
			}
		}
	}
	return nil, false
}

// GetVulnCheckKEVCVEIDs returns all CVE IDs in the VulnCheck KEV catalog
func (c *VulnCheckKEVCatalog) GetVulnCheckKEVCVEIDs() []string {
	seen := make(map[string]bool)
	var ids []string
	for _, entry := range c.Data {
		for _, cve := range entry.CVE {
			if cve != "" && !seen[strings.ToUpper(cve)] {
				seen[strings.ToUpper(cve)] = true
				ids = append(ids, cve)
			}
		}
	}
	return ids
}

// GetRecentVulnCheckKEV returns VulnCheck KEV entries added since the given date
func (c *VulnCheckKEVCatalog) GetRecentVulnCheckKEV(since time.Time) []VulnCheckKEVEntry {
	var recent []VulnCheckKEVEntry
	for i := range c.Data {
		if c.Data[i].DateAdded.IsZero() {
			continue
		}
		if c.Data[i].DateAdded.After(since) || c.Data[i].DateAdded.Equal(since) {
			recent = append(recent, c.Data[i])
		}
	}
	return recent
}

// IsRansomware returns true if the entry is known to be used by ransomware campaigns
func (e *VulnCheckKEVEntry) IsRansomware() bool {
	return strings.EqualFold(e.KnownRansomwareCampaignUse, "Known")
}

// HasExploitCode returns true if the entry has publicly available exploit code (XDB references)
func (e *VulnCheckKEVEntry) HasExploitCode() bool {
	return len(e.VulnCheckXDB) > 0
}

// IsInCISAKEV returns true if the entry is also in the CISA KEV catalog
func (e *VulnCheckKEVEntry) IsInCISAKEV() bool {
	return e.CISADateAdded != nil
}

// VulnCheckOnly returns true if the entry is NOT in CISA KEV (VulnCheck-exclusive)
func (e *VulnCheckKEVEntry) VulnCheckOnly() bool {
	return e.CISADateAdded == nil
}

// GetVulnCheckKEVPriority returns a priority score based on exploit availability and ransomware use
type VulnCheckKEVPriority int

const (
	VulnCheckKEVPriorityNormal     VulnCheckKEVPriority = 0
	VulnCheckKEVPriorityExploit    VulnCheckKEVPriority = 1 // Has XDB exploit code
	VulnCheckKEVPriorityRansomware VulnCheckKEVPriority = 2 // Ransomware campaign use
	VulnCheckKEVPriorityCritical   VulnCheckKEVPriority = 3 // Ransomware + exploit code
)

// GetPriority returns the priority level for a VulnCheck KEV entry
func (e *VulnCheckKEVEntry) GetPriority() VulnCheckKEVPriority {
	ransomware := e.IsRansomware()
	exploitCode := e.HasExploitCode()

	if ransomware && exploitCode {
		return VulnCheckKEVPriorityCritical
	}
	if ransomware {
		return VulnCheckKEVPriorityRansomware
	}
	if exploitCode {
		return VulnCheckKEVPriorityExploit
	}
	return VulnCheckKEVPriorityNormal
}
