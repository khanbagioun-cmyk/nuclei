package discovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CloudProvider constants
const (
	ProviderS3   = "s3"
	ProviderGCS  = "gcs"
	ProviderAzure = "azure"
	ProviderDigitalOcean = "digitalocean"
)

// DefaultCloudBucketSuffixes generates bucket name variations from a domain
var DefaultCloudBucketSuffixes = []string{
	"", "-backup", "-backups", "-dev", "-prod", "-staging",
	"-test", "-archive", "-data", "-files", "-media",
	"-static", "-assets", "-uploads", "-logs", "-tmp",
	"-db", "-database", "-sql", "-dump", "-export",
}

// CloudEndpoints maps providers to their URL patterns
var CloudEndpoints = map[string]string{
	ProviderS3:          "https://%s.s3.amazonaws.com",
	ProviderGCS:         "https://storage.googleapis.com/%s",
	ProviderAzure:       "https://%s.blob.core.windows.net",
	ProviderDigitalOcean: "https://%s.nyc3.digitaloceanspaces.com",
}

// CloudExistenceCodes are HTTP status codes indicating a resource exists
var CloudExistenceCodes = map[int]bool{
	200: true, // public read
	301: true, // redirect (bucket exists)
	403: true, // exists but access denied
	404: false, // does not exist
}

// runCloudEnum enumerates cloud resources
func (d *Discovery) runCloudEnum(ctx context.Context) {
	bucketNames := d.generateBucketNames()
	providers := d.config.CloudProviders
	if len(providers) == 0 {
		providers = []string{ProviderS3, ProviderGCS, ProviderAzure}
	}

	sem := make(chan struct{}, d.config.Threads)
	var wg sync.WaitGroup

	for _, provider := range providers {
		endpointPattern, ok := CloudEndpoints[provider]
		if !ok {
			continue
		}

		for _, name := range bucketNames {
			select {
			case <-ctx.Done():
				return
			default:
			}

			wg.Add(1)
			go func(prov, pattern, bucket string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				d.checkCloudResource(prov, pattern, bucket)
			}(provider, endpointPattern, name)
		}
	}
	wg.Wait()
}

func (d *Discovery) generateBucketNames() []string {
	var names []string
	seen := make(map[string]bool)

	addName := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}

	if len(d.config.CloudBucketNames) > 0 {
		for _, n := range d.config.CloudBucketNames {
			addName(n)
		}
	}

	for _, domain := range d.config.Domains {
		base := sanitizeBucketName(domain)
		if base == "" {
			continue
		}
		addName(base)
		for _, suffix := range DefaultCloudBucketSuffixes {
			addName(base + suffix)
		}
	}

	return names
}

func sanitizeBucketName(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	if idx := strings.Index(domain, "/"); idx > 0 {
		domain = domain[:idx]
	}
	if idx := strings.Index(domain, ":"); idx > 0 {
		domain = domain[:idx]
	}
	domain = strings.ReplaceAll(domain, ".", "-")
	domain = strings.ToLower(domain)
	domain = strings.Trim(domain, "-")
	if len(domain) < 3 || len(domain) > 63 {
		return ""
	}
	return domain
}

func (d *Discovery) checkCloudResource(provider, pattern, bucketName string) {
	endpoint := fmt.Sprintf(pattern, bucketName)

	client := &http.Client{
		Timeout: d.config.HTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("stopped after 3 redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", d.config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "connection refused") {
			return
		}
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	exists, public := false, false
	if val, ok := CloudExistenceCodes[resp.StatusCode]; ok {
		exists = val
	} else {
		exists = resp.StatusCode < 500
	}

	if exists && resp.StatusCode == 200 {
		public = true
	}

	if !exists {
		return
	}

	region := extractRegion(provider, resp)

	d.addCloudResult(CloudResource{
		Provider: provider,
		Name:     bucketName,
		URL:      endpoint,
		Status:   resp.StatusCode,
		Exists:   exists,
		Public:   public,
	})

	_ = region
}

func extractRegion(provider string, resp *http.Response) string {
	switch provider {
	case ProviderS3:
		if v := resp.Header.Get("x-amz-bucket-region"); v != "" {
			return v
		}
	case ProviderAzure:
		if v := resp.Header.Get("x-ms-version"); v != "" {
			return v
		}
	}
	return ""
}

// CheckSingleBucket checks a single bucket — exported for testing
func (d *Discovery) CheckSingleBucket(ctx context.Context, provider, bucketName string) CloudResource {
	pattern, ok := CloudEndpoints[provider]
	if !ok {
		return CloudResource{Provider: provider, Name: bucketName}
	}
	endpoint := fmt.Sprintf(pattern, bucketName)

	client := &http.Client{Timeout: d.config.HTTPTimeout}
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return CloudResource{Provider: provider, Name: bucketName, URL: endpoint}
	}
	req.Header.Set("User-Agent", d.config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return CloudResource{Provider: provider, Name: bucketName, URL: endpoint}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	exists, public := false, false
	if val, ok := CloudExistenceCodes[resp.StatusCode]; ok {
		exists = val
	}
	if resp.StatusCode == 200 {
		public = true
	}

	return CloudResource{
		Provider: provider,
		Name:     bucketName,
		URL:      endpoint,
		Status:   resp.StatusCode,
		Exists:   exists,
		Public:   public,
	}
}

var _ = time.Now
