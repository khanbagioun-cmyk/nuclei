// Package webhook implements a webhook exporter for nuclei findings.
// It sends each finding as a JSON payload to an HTTP endpoint (Slack,
// Discord, Teams, SIEM, custom API, etc.)
package webhook

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Exporter implements the webhook exporter
type Exporter struct {
	options    *Options
	httpClient *http.Client
}

// Options contains the configuration options for the webhook exporter
type Options struct {
	// URL is the webhook endpoint to send findings to
	URL string `yaml:"url" json:"url"`
	// Headers contains custom HTTP headers to send
	Headers map[string]string `yaml:"headers" json:"headers"`
	// SeverityFilter only sends findings matching these severities (empty = all)
	SeverityFilter []string `yaml:"severity-filter" json:"severity-filter"`
	// Timeout is the HTTP client timeout in seconds
	Timeout int `yaml:"timeout" json:"timeout"`
	// OmitRaw excludes raw request/response from payload
	OmitRaw bool `yaml:"omit-raw" json:"omit-raw"`
	// SSLVerification disables SSL verification when false
	SSLVerification bool `yaml:"ssl-verification" json:"ssl-verification"`
	// HttpClient is the shared HTTP client (injected)
	HttpClient *retryablehttp.Client `yaml:"-"`
}

// findingPayload is the JSON structure sent to the webhook
type findingPayload struct {
	TemplateID  string `json:"template_id"`
	TemplatePath string `json:"template_path"`
	InfoName    string `json:"info_name"`
	InfoAuthor  string `json:"info_author"`
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	Host        string `json:"host"`
	Matched     string `json:"matched"`
	Description string `json:"description,omitempty"`
	Reference   string `json:"reference,omitempty"`
	Timestamp   string `json:"timestamp"`
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
	CURLCommand string `json:"curl_command,omitempty"`
}

// New creates a new webhook exporter
func New(options *Options) (*Exporter, error) {
	if options.URL == "" {
		return nil, fmt.Errorf("webhook url is required")
	}
	if options.Timeout == 0 {
		options.Timeout = 10
	}

	var client *http.Client
	if options.HttpClient != nil {
		client = options.HttpClient.HTTPClient
	} else {
		client = &http.Client{
			Timeout: time.Duration(options.Timeout) * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: !options.SSLVerification},
			},
		}
	}

	return &Exporter{
		options:    options,
		httpClient: client,
	}, nil
}

// Export sends a finding to the webhook endpoint
func (e *Exporter) Export(event *output.ResultEvent) error {
	severityStr := event.Info.SeverityHolder.Severity.String()

	// Apply severity filter
	if len(e.options.SeverityFilter) > 0 {
		matched := false
		for _, s := range e.options.SeverityFilter {
			if strings.EqualFold(s, severityStr) {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}
	}

	payload := e.buildPayload(event, severityStr)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, e.options.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nuclei-dev-webhook-exporter")

	for k, v := range e.options.Headers {
		req.Header.Set(k, v)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		gologger.Warning().Msgf("webhook export failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		gologger.Warning().Msgf("webhook returned status %d for %s: %s", resp.StatusCode, e.options.URL, string(respBody))
	}
	return nil
}

// buildPayload converts a ResultEvent to a webhook payload
func (e *Exporter) buildPayload(event *output.ResultEvent, severityStr string) findingPayload {
	payload := findingPayload{
		TemplateID:   event.TemplateID,
		TemplatePath: event.TemplatePath,
		InfoName:     event.Info.Name,
		Severity:     severityStr,
		Type:         event.Type,
		Host:         event.Host,
		Matched:      event.Matched,
		Description:  event.Info.Description,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}

	if !event.Info.Authors.IsEmpty() {
		payload.InfoAuthor = event.Info.Authors.String()
	}
	if event.Info.Reference != nil && !event.Info.Reference.IsEmpty() {
		refs := event.Info.Reference.ToSlice()
		payload.Reference = strings.Join(refs, ", ")
	}

	if event.CURLCommand != "" {
		payload.CURLCommand = event.CURLCommand
	}

	if !e.options.OmitRaw && event.Request != "" {
		payload.RawRequest = event.Request
	}
	if !e.options.OmitRaw && event.Response != "" {
		payload.RawResponse = event.Response
	}

	return payload
}

// Close cleans up the exporter
func (e *Exporter) Close() error {
	return nil
}
