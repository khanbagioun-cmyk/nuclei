package protodeep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GraphQLScanner performs GraphQL introspection and security checks
type GraphQLScanner struct {
	client  *http.Client
	timeout time.Duration
}

// GraphQLConfig configures the GraphQL scanner
type GraphQLConfig struct {
	Timeout time.Duration
	Headers map[string]string
}

// DefaultGraphQLConfig returns sensible defaults
func DefaultGraphQLConfig() GraphQLConfig {
	return GraphQLConfig{
		Timeout: 15 * time.Second,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}
}

// NewGraphQLScanner creates a new GraphQL scanner
func NewGraphQLScanner(config GraphQLConfig) *GraphQLScanner {
	if config.Timeout == 0 {
		config.Timeout = 15 * time.Second
	}
	return &GraphQLScanner{
		client:  &http.Client{Timeout: config.Timeout},
		timeout: config.Timeout,
	}
}

// GraphQLResult holds the scan result
type GraphQLResult struct {
	URL             string                 `json:"url"`
	EndpointFound   bool                   `json:"endpoint_found"`
	Introspection   bool                   `json:"introspection_enabled"`
	Schema          string                 `json:"schema,omitempty"`
	Types           []GraphQLType          `json:"types,omitempty"`
	Queries         []string               `json:"queries,omitempty"`
	Mutations       []string               `json:"mutations,omitempty"`
	Subscriptions   []string               `json:"subscriptions,omitempty"`
	Enums           []GraphQLEnum          `json:"enums,omitempty"`
	FieldSuggestions bool                  `json:"field_suggestions"`
	Suggestions     []string               `json:"suggestions,omitempty"`
	RawResponse     map[string]interface{} `json:"raw_response,omitempty"`
	Error           string                 `json:"error,omitempty"`
}

// GraphQLType represents a GraphQL type
type GraphQLType struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Fields []string `json:"fields,omitempty"`
}

// GraphQLEnum represents a GraphQL enum
type GraphQLEnum struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// Common GraphQL endpoint paths to probe
var graphqlPaths = []string{
	"/graphql",
	"/api/graphql",
	"/query",
	"/api/query",
	"/v1/graphql",
	"/api/v1/graphql",
	"/graphql.php",
	"/graphiql",
	"/api",
	"/playground",
}

// introspectionQuery is the standard GraphQL introspection query
const introspectionQuery = `{
  "__schema": {
    "queryType": { "name": "name" },
    "mutationType": { "name": "name" },
    "subscriptionType": { "name": "name" },
    "types": {
      "name": "name",
      "kind": "kind",
      "description": "description",
      "fields(includeDeprecated: true)": {
        "name": "name",
        "description": "description",
        "type": {
          "name": "name",
          "kind": "kind"
        }
      },
      "enumValues(includeDeprecated: true)": {
        "name": "name",
        "description": "description"
      }
    }
  }
}`

// fieldSuggestionQuery is a query that triggers field suggestions
const fieldSuggestionQuery = `{
  "__type(name: "Query") {
    fields {
      name
    }
  }
  __invalidFieldTriggerSuggestions
}`

// Scan performs a full GraphQL scan against a target
func (s *GraphQLScanner) Scan(ctx context.Context, baseURL string, headers map[string]string) (*GraphQLResult, error) {
	result := &GraphQLResult{URL: baseURL}

	// Find the GraphQL endpoint
	endpoint, found := s.findEndpoint(ctx, baseURL, headers)
	if !found {
		result.Error = "GraphQL endpoint not found"
		return result, nil
	}
	result.EndpointFound = true
	result.URL = endpoint

	// Try introspection
	schema, err := s.introspect(ctx, endpoint, headers)
	if err != nil {
		result.Error = fmt.Sprintf("introspection failed: %v", err)
		return result, nil
	}

	if schema != nil {
		result.Introspection = true
		result.RawResponse = schema
		s.parseSchema(schema, result)
		result.Schema = s.formatSchema(result)
	}

	// Check for field suggestions (information disclosure)
	s.checkFieldSuggestions(ctx, endpoint, headers, result)

	return result, nil
}

// findEndpoint probes common GraphQL paths
func (s *GraphQLScanner) findEndpoint(ctx context.Context, baseURL string, headers map[string]string) (string, bool) {
	baseURL = strings.TrimSuffix(baseURL, "/")

	for _, path := range graphqlPaths {
		url := baseURL + path
		body := map[string]string{"query": "{__typename}"}
		jsonBody, _ := json.Marshal(body)

		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
		if err != nil {
			continue
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Check if response looks like GraphQL
		bodyStr := string(respBody)
		if resp.StatusCode == 200 && (strings.Contains(bodyStr, "data") ||
			strings.Contains(bodyStr, "errors") ||
			strings.Contains(bodyStr, "__typename")) {
			return url, true
		}
	}
	return "", false
}

// introspect sends the introspection query
func (s *GraphQLScanner) introspect(ctx context.Context, endpoint string, headers map[string]string) (map[string]interface{}, error) {
	body := map[string]string{"query": introspectionQuery}
	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Check for errors
	if errs, ok := result["errors"]; ok {
		return nil, fmt.Errorf("GraphQL errors: %v", errs)
	}

	return result, nil
}

// parseSchema extracts types, queries, mutations, enums from introspection result
func (s *GraphQLScanner) parseSchema(schema map[string]interface{}, result *GraphQLResult) {
	data, ok := schema["data"].(map[string]interface{})
	if !ok {
		return
	}
	__schema, ok := data["__schema"].(map[string]interface{})
	if !ok {
		return
	}

	// Extract query type name
	queryType, _ := __schema["queryType"].(map[string]interface{})
	queryTypeName, _ := queryType["name"].(string)

	// Extract mutation type name
	mutationType, _ := __schema["mutationType"].(map[string]interface{})
	mutationTypeName, _ := mutationType["name"].(string)

	// Extract subscription type name
	subscriptionType, _ := __schema["subscriptionType"].(map[string]interface{})
	subscriptionTypeName, _ := subscriptionType["name"].(string)

	// Parse types
	types, ok := __schema["types"].([]interface{})
	if !ok {
		return
	}

	for _, t := range types {
		typeMap, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := typeMap["name"].(string)
		kind, _ := typeMap["kind"].(string)

		// Skip internal types
		if strings.HasPrefix(name, "__") {
			continue
		}

		gt := GraphQLType{Name: name, Kind: kind}

		// Extract fields
		if fields, ok := typeMap["fields"].([]interface{}); ok {
			for _, f := range fields {
				fieldMap, ok := f.(map[string]interface{})
				if !ok {
					continue
				}
				fname, _ := fieldMap["name"].(string)
				if fname != "" {
					gt.Fields = append(gt.Fields, fname)
				}
			}
		}

		// Categorize by type name
		if name == queryTypeName {
			result.Queries = gt.Fields
		} else if name == mutationTypeName {
			result.Mutations = gt.Fields
		} else if name == subscriptionTypeName {
			result.Subscriptions = gt.Fields
		}

		// Extract enums
		if kind == "ENUM" {
			var enumValues []string
			if vals, ok := typeMap["enumValues"].([]interface{}); ok {
				for _, v := range vals {
					valMap, ok := v.(map[string]interface{})
					if !ok {
						continue
					}
					valName, _ := valMap["name"].(string)
					if valName != "" {
						enumValues = append(enumValues, valName)
					}
				}
			}
			result.Enums = append(result.Enums, GraphQLEnum{Name: name, Values: enumValues})
		}

		result.Types = append(result.Types, gt)
	}
}

// checkFieldSuggestions tests if the server reveals field name suggestions
func (s *GraphQLScanner) checkFieldSuggestions(ctx context.Context, endpoint string, headers map[string]string, result *GraphQLResult) {
	body := map[string]string{"query": fieldSuggestionQuery}
	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	bodyStr := string(respBody)

	// Check for suggestion messages like "Did you mean ..."
	if strings.Contains(bodyStr, "Did you mean") || strings.Contains(bodyStr, "did you mean") {
		result.FieldSuggestions = true
		// Extract suggestions
		lines := strings.Split(bodyStr, "\\n")
		for _, line := range lines {
			if idx := strings.Index(line, "Did you mean"); idx >= 0 {
				result.Suggestions = append(result.Suggestions, line[idx:])
			}
		}
	}
}

// formatSchema generates a human-readable schema summary
func (s *GraphQLScanner) formatSchema(result *GraphQLResult) string {
	var sb strings.Builder
	sb.WriteString("GraphQL Schema Summary:\n")
	if len(result.Queries) > 0 {
		sb.WriteString(fmt.Sprintf("  Queries (%d):\n", len(result.Queries)))
		for _, q := range result.Queries {
			sb.WriteString(fmt.Sprintf("    - %s\n", q))
		}
	}
	if len(result.Mutations) > 0 {
		sb.WriteString(fmt.Sprintf("  Mutations (%d):\n", len(result.Mutations)))
		for _, m := range result.Mutations {
			sb.WriteString(fmt.Sprintf("    - %s\n", m))
		}
	}
	if len(result.Subscriptions) > 0 {
		sb.WriteString(fmt.Sprintf("  Subscriptions (%d):\n", len(result.Subscriptions)))
		for _, sub := range result.Subscriptions {
			sb.WriteString(fmt.Sprintf("    - %s\n", sub))
		}
	}
	if len(result.Enums) > 0 {
		sb.WriteString(fmt.Sprintf("  Enums (%d):\n", len(result.Enums)))
		for _, e := range result.Enums {
			sb.WriteString(fmt.Sprintf("    - %s: %v\n", e.Name, e.Values))
		}
	}
	if len(result.Types) > 0 {
		sb.WriteString(fmt.Sprintf("  Total Types: %d\n", len(result.Types)))
	}
	return sb.String()
}
