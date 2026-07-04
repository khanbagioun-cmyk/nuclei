package intelligence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LocalVKEVIndex is a locally-built index of VulnCheck KEV CVEs
// derived from scanning the 1,795 community templates tagged "vkev".
// This eliminates the need for a VulnCheck API token.
type LocalVKEVIndex struct {
	CVEs     map[string]*LocalVKEVEntry `json:"cves"`
	BuildDir string                     `json:"build_dir"`
	BuiltAt  time.Time                  `json:"built_at"`
	mu       sync.RWMutex
}

// LocalVKEVEntry represents a single VKEV CVE found in local templates
type LocalVKEVEntry struct {
	CVEID         string   `json:"cve_id"`
	TemplatePaths []string `json:"template_paths"`
	Product       string   `json:"product,omitempty"`
	Vendor        string   `json:"vendor,omitempty"`
	Tags          []string `json:"tags"`
	Severity      string   `json:"severity,omitempty"`
}

// NewLocalVKEVIndex creates an empty index
func NewLocalVKEVIndex() *LocalVKEVIndex {
	return &LocalVKEVIndex{
		CVEs: make(map[string]*LocalVKEVEntry),
	}
}

// BuildLocalVKEVIndex scans a templates directory for vkev-tagged templates
// and builds an index of CVE IDs → template paths
func BuildLocalVKEVIndex(templatesDir string) (*LocalVKEVIndex, error) {
	index := NewLocalVKEVIndex()
	index.BuildDir = templatesDir

	// Walk all YAML files
	err := filepath.Walk(templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)

		// Check if template has vkev tag
		if !strings.Contains(content, "vkev") {
			return nil
		}

		// Extract CVE ID from template ID, name, or tags
		cveID := extractCVEFromTemplate(content)
		if cveID == "" {
			return nil
		}

		entry := index.CVEs[cveID]
		if entry == nil {
			entry = &LocalVKEVEntry{
				CVEID: cveID,
				Tags:  extractTags(content),
			}
			index.CVEs[cveID] = entry
		}
		entry.TemplatePaths = append(entry.TemplatePaths, path)

		// Extract severity
		if entry.Severity == "" {
			entry.Severity = extractField(content, "severity")
		}

		return nil
	})

	index.BuiltAt = time.Now()
	return index, err
}

// extractCVEFromTemplate extracts CVE ID from template content
func extractCVEFromTemplate(content string) string {
	// Look for CVE-YYYY-NNNN pattern in the content
	upper := strings.ToUpper(content)
	idx := strings.Index(upper, "CVE-")
	if idx == -1 {
		return ""
	}

	// Extract CVE-YYYY-NNNNN (variable length number)
	end := idx + 4 // skip "CVE-"
	// Skip year
	for end < len(upper) && (upper[end] >= '0' && upper[end] <= '9') {
		end++
	}
	if end < len(upper) && upper[end] == '-' {
		end++
		for end < len(upper) && (upper[end] >= '0' && upper[end] <= '9') {
			end++
		}
	}

	if end > idx+8 { // minimum "CVE-YY-NN"
		return upper[idx:end]
	}
	return ""
}

// extractTags extracts the tags field from YAML content
func extractTags(content string) []string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "tags:") {
			tagStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "tags:"))
			tagStr = strings.Trim(tagStr, "[]\"")
			parts := strings.Split(tagStr, ",")
			var tags []string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					tags = append(tags, p)
				}
			}
			return tags
		}
	}
	return nil
}

// extractField extracts a simple YAML field value
func extractField(content, field string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, field+":") {
			val := strings.TrimSpace(strings.TrimPrefix(trimmed, field+":"))
			val = strings.Trim(val, "\"'")
			return val
		}
	}
	return ""
}

// IsVulnCheckKEV returns true if a CVE is in the local VKEV index
func (idx *LocalVKEVIndex) IsVulnCheckKEV(cveID string) bool {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	_, found := idx.CVEs[strings.ToUpper(cveID)]
	return found
}

// GetEntry returns the VKEV entry for a CVE
func (idx *LocalVKEVIndex) GetEntry(cveID string) (*LocalVKEVEntry, bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	entry, found := idx.CVEs[strings.ToUpper(cveID)]
	return entry, found
}

// GetCVEIDs returns all CVE IDs in the index
func (idx *LocalVKEVIndex) GetCVEIDs() []string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	ids := make([]string, 0, len(idx.CVEs))
	for cve := range idx.CVEs {
		ids = append(ids, cve)
	}
	return ids
}

// Count returns the number of VKEV CVEs in the index
func (idx *LocalVKEVIndex) Count() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.CVEs)
}

// Save persists the index to a JSON file
func (idx *LocalVKEVIndex) Save(path string) error {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadLocalVKEVIndex loads a previously built index from disk
func LoadLocalVKEVIndex(path string) (*LocalVKEVIndex, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var idx LocalVKEVIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, err
	}
	if idx.CVEs == nil {
		idx.CVEs = make(map[string]*LocalVKEVEntry)
	}
	return &idx, nil
}

// MergeWithAPI merges a local index with an API-fetched VulnCheck KEV catalog
// Entries from the API catalog are added if not already present
func (idx *LocalVKEVIndex) MergeWithAPI(catalog *VulnCheckKEVCatalog) int {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	added := 0
	for i := range catalog.Data {
		entry := &catalog.Data[i]
		for _, cveID := range entry.CVE {
			cveID = strings.ToUpper(cveID)
			if _, exists := idx.CVEs[cveID]; !exists {
				idx.CVEs[cveID] = &LocalVKEVEntry{
					CVEID:   cveID,
					Product: entry.Product,
					Vendor:  entry.VendorProject,
					Tags:    []string{"vkev", "api-sourced"},
				}
				added++
			}
		}
	}
	return added
}
