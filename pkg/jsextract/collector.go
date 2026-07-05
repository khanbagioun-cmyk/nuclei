package jsextract

import (
	"sync"
	"net/url"
	"strings"
)

// EndpointCollector thread-safely collects endpoints discovered during JS extraction.
// These can be used by the multi-phase engine to run additional templates
// against discovered API paths.
type EndpointCollector struct {
	mu        sync.RWMutex
	endpoints map[string]bool // key: full URL
}

// NewEndpointCollector creates a new collector.
func NewEndpointCollector() *EndpointCollector {
	return &EndpointCollector{
		endpoints: make(map[string]bool),
	}
}

// AddEndpoint adds a discovered endpoint (relative path + source URL).
// The source URL provides the scheme+host, the path is appended.
func (c *EndpointCollector) AddEndpoint(sourceURL, path string) {
	fullURL := buildURL(sourceURL, path)
	if fullURL == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.endpoints[fullURL] = true
}

// GetEndpoints returns all collected endpoint URLs.
func (c *EndpointCollector) GetEndpoints() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]string, 0, len(c.endpoints))
	for u := range c.endpoints {
		result = append(result, u)
	}
	return result
}

// Count returns the number of collected endpoints.
func (c *EndpointCollector) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.endpoints)
}

// buildURL combines a source URL with a relative path to create a full URL.
func buildURL(sourceURL, path string) string {
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path // already absolute
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	parsed, err := url.Parse(sourceURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + parsed.Host + path
}
