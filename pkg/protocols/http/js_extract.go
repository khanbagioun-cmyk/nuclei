package http

import (
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	stringslicetype "github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
)

// jsContentTypePrefixes are content-type prefixes that indicate a JavaScript response.
var jsContentTypePrefixes = []string{
	"text/javascript",
	"application/javascript",
	"application/x-javascript",
	"application/ecmascript",
	"text/ecmascript",
}

// isJavaScriptResponse checks if the response content-type indicates JavaScript.
func isJavaScriptResponse(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	for _, prefix := range jsContentTypePrefixes {
		if ct == prefix || strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

// processJSExtraction runs the JS extractor on the response body and emits
// findings for any discovered endpoints or secrets via the callback.
func (request *Request) processJSExtraction(bodyStr, sourceURL string, callback protocols.OutputEventCallback) {
	if request.options.JSExtractor == nil {
		return
	}

	result := request.options.JSExtractor.Extract(bodyStr, sourceURL)
	if len(result.Endpoints) == 0 && len(result.Secrets) == 0 {
		return
	}

	for _, ep := range result.Endpoints {
		info := model.Info{
			Name:        "JS Endpoint Extraction",
			Authors:     stringslicetype.New("nuclei-dev"),
			Description: "Endpoint discovered in JavaScript: " + ep.Path,
			SeverityHolder: severity.Holder{
				Severity: severity.Info,
			},
			Tags: stringslicetype.New("js,extract,endpoint"),
		}
		resultEvent := &output.ResultEvent{
			TemplateID:       "js-extract-endpoints",
			TemplatePath:     "built-in/js-extract",
			Info:             info,
			Type:             "http",
			Host:             sourceURL,
			URL:              sourceURL,
			Matched:          sourceURL,
			MatcherName:      "js-endpoint",
			ExtractedResults: []string{ep.Path},
			Metadata: map[string]interface{}{
				"method": ep.Method,
				"path":   ep.Path,
				"source": ep.Source,
			},
			Timestamp:    time.Now(),
			MatcherStatus: true,
		}
		wrappedEvent := &output.InternalWrappedEvent{
			InternalEvent: map[string]interface{}{
				"template-id":   "js-extract-endpoints",
				"template-path": "built-in/js-extract",
				"host":          sourceURL,
				"matched":       sourceURL,
				"type":          "http",
				"template-info": info,
			},
			OperatorsResult: &operators.Result{
				Matched: true,
				Matches: map[string][]string{"js-endpoint": {ep.Method + " " + ep.Path}},
			},
			Results: []*output.ResultEvent{resultEvent},
		}
		callback(wrappedEvent)
	}

	for _, secret := range result.Secrets {
		maskedValue := maskSecret(secret.Value)

		info := model.Info{
			Name:        "JS Secret Extraction",
			Authors:     stringslicetype.New("nuclei-dev"),
			Description: "Secret discovered in JavaScript: " + secret.Type,
			SeverityHolder: severity.Holder{
				Severity: severity.High,
			},
			Tags: stringslicetype.New("js,extract,secret," + secret.Type),
		}
		resultEvent := &output.ResultEvent{
			TemplateID:  "js-extract-secrets",
			TemplatePath: "built-in/js-extract",
			Info:        info,
			Type:        "http",
			Host:        sourceURL,
			URL:         sourceURL,
			Matched:     sourceURL,
			MatcherName: "js-secret",
			Metadata: map[string]interface{}{
				"secret_type":  secret.Type,
				"secret_value": maskedValue,
				"source":       secret.Source,
			},
			Timestamp:     time.Now(),
			MatcherStatus: true,
		}
		wrappedEvent := &output.InternalWrappedEvent{
			InternalEvent: map[string]interface{}{
				"template-id":   "js-extract-secrets",
				"template-path": "built-in/js-extract",
				"host":          sourceURL,
				"matched":       sourceURL,
				"type":          "http",
				"template-info": info,
			},
			OperatorsResult: &operators.Result{
				Matched: true,
				Matches: map[string][]string{"js-secret": {secret.Type + ":" + maskedValue}},
			},
			Results: []*output.ResultEvent{resultEvent},
		}
		callback(wrappedEvent)

		gologger.Info().Msgf("[js-extract] %s secret found in %s: %s", secret.Type, sourceURL, maskedValue)
	}

	if len(result.Endpoints) > 0 {
		gologger.Info().Msgf("[js-extract] %d endpoints extracted from %s", len(result.Endpoints), sourceURL)
	}
}

// maskSecret partially masks a secret value for safe display.
func maskSecret(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}
