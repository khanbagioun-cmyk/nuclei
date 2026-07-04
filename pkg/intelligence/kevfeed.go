package intelligence

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const cisaKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// CISAKEVCatalog represents the top-level CISA KEV JSON feed
type CISAKEVCatalog struct {
	Title          string           `json:"title"`
	CatalogVersion string           `json:"catalogVersion"`
	DateReleased   string           `json:"dateReleased"`
	Count          int              `json:"count"`
	Vulnerabilities []CISAKEVEntry  `json:"vulnerabilities"`
}

// CISAKEVEntry represents a single entry in the CISA KEV catalog
type CISAKEVEntry struct {
	CVEID                          string `json:"cveID"`
	VendorProject                  string `json:"vendorProject"`
	Product                        string `json:"product"`
	VulnerabilityName              string `json:"vulnerabilityName"`
	DateAdded                      string `json:"dateAdded"`
	ShortDescription               string `json:"shortDescription"`
	RequiredAction                 string `json:"requiredAction"`
	KnownToBeRansomwareCampaignUse bool   `json:"knownToBeRansomwareCampaignUse"`
	Notes                          string `json:"notes"`
	DueDate                        string `json:"dueDate"`
	KnownSoftwareAffected          string `json:"knownSoftwareAffected,omitempty"`
}

// FetchCISAKEV downloads and parses the CISA KEV catalog
func FetchCISAKEV() (*CISAKEVCatalog, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(cisaKEVURL)
	if err != nil {
		return nil, fmt.Errorf("fetching CISA KEV feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CISA KEV feed returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading CISA KEV response: %w", err)
	}

	var catalog CISAKEVCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("parsing CISA KEV JSON: %w", err)
	}

	return &catalog, nil
}

// GetKEVByCVE returns the KEV entry for a specific CVE ID, if present
func (c *CISAKEVCatalog) GetKEVByCVE(cveID string) (*CISAKEVEntry, bool) {
	for i := range c.Vulnerabilities {
		if strings.EqualFold(c.Vulnerabilities[i].CVEID, cveID) {
			return &c.Vulnerabilities[i], true
		}
	}
	return nil, false
}

// GetKEVCVEIDs returns all CVE IDs in the KEV catalog
func (c *CISAKEVCatalog) GetKEVCVEIDs() []string {
	ids := make([]string, 0, c.Count)
	for _, v := range c.Vulnerabilities {
		if v.CVEID != "" {
			ids = append(ids, v.CVEID)
		}
	}
	return ids
}

// GetRecentKEV returns KEV entries added since the given date
func (c *CISAKEVCatalog) GetRecentKEV(since time.Time) []CISAKEVEntry {
	var recent []CISAKEVEntry
	for _, v := range c.Vulnerabilities {
		if v.DateAdded == "" {
			continue
		}
		t, err := time.Parse("2006-01-02", v.DateAdded)
		if err != nil {
			continue
		}
		if t.After(since) || t.Equal(since) {
			recent = append(recent, v)
		}
	}
	return recent
}

// KEVPriority represents the priority level of a KEV entry
type KEVPriority int

const (
	KEVPriorityNormal     KEVPriority = 0
	KEVPriorityRansomware KEVPriority = 1
)

// GetPriority returns the priority level based on ransomware campaign usage
func (e *CISAKEVEntry) GetPriority() KEVPriority {
	if e.KnownToBeRansomwareCampaignUse {
		return KEVPriorityRansomware
	}
	return KEVPriorityNormal
}
