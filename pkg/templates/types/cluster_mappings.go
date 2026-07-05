package types

import (
	"fmt"
	"sort"
	"strings"

	"github.com/logrusorgru/aurora/v4"
)

// ClusterMappingsMap wraps cluster ID to template IDs mapping
type ClusterMappingsMap struct {
	Map map[string][]string
}

// NewClusterMappingsMap creates a new ClusterMappingsMap from an existing map
func NewClusterMappingsMap(m map[string][]string) *ClusterMappingsMap {
	return &ClusterMappingsMap{Map: m}
}

// Get returns the template IDs for a given cluster ID, or nil, false if the receiver or Map is nil
func (c *ClusterMappingsMap) Get(clusterID string) ([]string, bool) {
	if c == nil || c.Map == nil {
		return nil, false
	}
	v, ok := c.Map[clusterID]
	return v, ok
}

// GetAll returns a copy of the entire map, or an empty map if the receiver or Map is nil
func (c *ClusterMappingsMap) GetAll() map[string][]string {
	if c == nil || c.Map == nil {
		return make(map[string][]string)
	}
	result := make(map[string][]string, len(c.Map))
	for k, v := range c.Map {
		result[k] = append([]string{}, v...)
	}
	return result
}

// Copy returns a deep copy of the ClusterMappingsMap, or nil if the receiver is nil
func (c *ClusterMappingsMap) Copy() *ClusterMappingsMap {
	if c == nil {
		return nil
	}
	return NewClusterMappingsMap(c.GetAll())
}

// ClusterReport holds clustering efficiency statistics for end-of-scan display.
type ClusterReport struct {
	TotalTemplates     int                // len(templatesList) before clustering
	ClusteredTemplates int                // templates that were merged into clusters
	Clusters           int                // number of clusters formed (groups with >1 template)
	RequestsBefore     int                // total requests before clustering
	RequestsAfter      int                // total requests after clustering
	Mappings           *ClusterMappingsMap // cluster ID → []templateID
}

// Display prints the cluster report to the provided writer via the aurora colorizer.
func (r *ClusterReport) Display(noColor bool) {
	if r == nil {
		return
	}
	au := aurora.New(aurora.WithColors(!noColor))

	reduced := r.RequestsBefore - r.RequestsAfter
	ratio := 0.0
	if r.RequestsBefore > 0 {
		ratio = float64(reduced) / float64(r.RequestsBefore) * 100
	}
	avgClusterSize := 0.0
	if r.Clusters > 0 {
		avgClusterSize = float64(r.ClusteredTemplates) / float64(r.Clusters)
	}

	fmt.Println(au.Bold(au.Cyan("\nCluster Efficiency Report:")))
	fmt.Printf("  Templates loaded:    %d\n", r.TotalTemplates)
	fmt.Printf("  Clustered templates: %s (%d clusters, avg %.1f templates/cluster)\n",
		au.Yellow(r.ClusteredTemplates), r.Clusters, avgClusterSize)
	fmt.Printf("  Requests before:     %d\n", r.RequestsBefore)
	fmt.Printf("  Requests after:      %d\n", r.RequestsAfter)
	fmt.Printf("  Requests saved:      %s (%.1f%% reduction)\n",
		au.Green(reduced), ratio)

	if r.Mappings != nil && len(r.Mappings.Map) > 0 {
		type clusterEntry struct {
			id    string
			temps []string
		}
		entries := make([]clusterEntry, 0, len(r.Mappings.Map))
		for id, temps := range r.Mappings.Map {
			if len(temps) > 1 {
				entries = append(entries, clusterEntry{id, temps})
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			return len(entries[i].temps) > len(entries[j].temps)
		})
		const maxShow = 10
		if len(entries) > 0 {
			fmt.Printf("  Top clusters (by size):\n")
			shown := 0
			for _, e := range entries {
				if shown >= maxShow {
					fmt.Printf("    ... and %d more clusters\n", len(entries)-maxShow)
					break
				}
				shortID := e.id
				if len(shortID) > 16 {
					shortID = shortID[:16]
				}
				fmt.Printf("    %s: %d templates (%s)\n",
					shortID, len(e.temps), strings.Join(e.temps[:min(3, len(e.temps))], ", ")+
						func() string {
							if len(e.temps) > 3 {
								return fmt.Sprintf(", ... +%d more", len(e.temps)-3)
							}
							return ""
						}())
				shown++
			}
		}
	}
	fmt.Println()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
