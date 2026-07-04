package protodeep

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ============= GraphQL Tests =============

func TestGraphQLScanner_FindEndpoint(t *testing.T) {
	// Create a mock GraphQL server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == "POST" {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if strings.Contains(body["query"], "__typename") {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"data":{"__typename":"Query"}}`))
				return
			}
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	s := NewGraphQLScanner(DefaultGraphQLConfig())
	result, err := s.Scan(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if !result.EndpointFound {
		t.Error("expected endpoint to be found")
	}
	if result.URL == "" {
		t.Error("expected URL to be set")
	}
}

func TestGraphQLScanner_Introspection(t *testing.T) {
	// Create a mock GraphQL server with introspection enabled
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return a minimal introspection response
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"__schema": map[string]interface{}{
					"queryType":        map[string]interface{}{"name": "Query"},
					"mutationType":     map[string]interface{}{"name": "Mutation"},
					"subscriptionType": nil,
					"types": []interface{}{
						map[string]interface{}{
							"name":   "Query",
							"kind":   "OBJECT",
							"fields": []interface{}{
								map[string]interface{}{"name": "users"},
								map[string]interface{}{"name": "user"},
							},
						},
						map[string]interface{}{
							"name":   "Mutation",
							"kind":   "OBJECT",
							"fields": []interface{}{
								map[string]interface{}{"name": "createUser"},
								map[string]interface{}{"name": "deleteUser"},
							},
						},
						map[string]interface{}{
							"name":       "Role",
							"kind":       "ENUM",
							"enumValues": []interface{}{
								map[string]interface{}{"name": "ADMIN"},
								map[string]interface{}{"name": "USER"},
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	s := NewGraphQLScanner(DefaultGraphQLConfig())
	result, err := s.Scan(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if !result.EndpointFound {
		t.Error("expected endpoint found")
	}
	if !result.Introspection {
		t.Error("expected introspection enabled")
	}
	if len(result.Queries) != 2 {
		t.Errorf("expected 2 queries, got %d", len(result.Queries))
	}
	if len(result.Mutations) != 2 {
		t.Errorf("expected 2 mutations, got %d", len(result.Mutations))
	}
	if len(result.Enums) != 1 {
		t.Errorf("expected 1 enum, got %d", len(result.Enums))
	}
	if result.Enums[0].Name != "Role" {
		t.Errorf("expected enum name Role, got %s", result.Enums[0].Name)
	}
}

func TestGraphQLScanner_NoEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer server.Close()

	s := NewGraphQLScanner(DefaultGraphQLConfig())
	result, err := s.Scan(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.EndpointFound {
		t.Error("expected endpoint not found")
	}
	if result.Error == "" {
		t.Error("expected error message")
	}
}

func TestGraphQLScanner_FieldSuggestions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)

		if strings.Contains(body["query"], "__schema") {
			// Return valid introspection
			w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"subscriptionType":null,"types":[{"name":"Query","kind":"OBJECT","fields":[{"name":"hello"}]}]}}}`))
			return
		}
		// Return field suggestion error
		w.Write([]byte(`{"errors":[{"message":"Cannot query field \"__invalidFieldTriggerSuggestions\" on type \"Query\". Did you mean \"hello\"?"}]}`))
	}))
	defer server.Close()

	s := NewGraphQLScanner(DefaultGraphQLConfig())
	result, err := s.Scan(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if !result.FieldSuggestions {
		t.Error("expected field suggestions to be detected")
	}
}

func TestGraphQLScanner_CustomHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer server.Close()

	s := NewGraphQLScanner(DefaultGraphQLConfig())
	headers := map[string]string{"Authorization": "Bearer test-token"}
	result, err := s.Scan(context.Background(), server.URL, headers)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if !result.EndpointFound {
		t.Error("expected endpoint found with auth header")
	}
}

func TestGraphQLScanner_FormatSchema(t *testing.T) {
	s := NewGraphQLScanner(DefaultGraphQLConfig())
	result := &GraphQLResult{
		Queries:   []string{"users", "user"},
		Mutations: []string{"createUser"},
		Enums:     []GraphQLEnum{{Name: "Role", Values: []string{"ADMIN", "USER"}}},
		Types:     []GraphQLType{{Name: "Query", Kind: "OBJECT"}},
	}
	schema := s.formatSchema(result)
	if !strings.Contains(schema, "Queries") {
		t.Error("expected Queries in schema")
	}
	if !strings.Contains(schema, "Mutations") {
		t.Error("expected Mutations in schema")
	}
	if !strings.Contains(schema, "Enums") {
		t.Error("expected Enums in schema")
	}
}

// ============= gRPC Tests =============

func TestReadVarint(t *testing.T) {
	tests := []struct {
		data   []byte
		expect uint64
		n      int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x01}, 1, 1},
		{[]byte{0x7F}, 127, 1},
		{[]byte{0x80, 0x01}, 128, 2},
		{[]byte{0xFF, 0x01}, 255, 2},
	}
	for _, tt := range tests {
		val, n := readVarint(tt.data)
		if val != tt.expect {
			t.Errorf("readVarint(%v) = %d, want %d", tt.data, val, tt.expect)
		}
		if n != tt.n {
			t.Errorf("readVarint(%v) n = %d, want %d", tt.data, n, tt.n)
		}
	}
}

func TestGRPCScanner_NoServer(t *testing.T) {
	s := NewGRPCScanner(DefaultGRPCConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := s.Scan(ctx, "127.0.0.1:9999", false)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.ReflectionEnabled {
		t.Error("expected reflection disabled")
	}
	if result.Error == "" {
		t.Error("expected error message")
	}
}

func TestGRPCScanner_ParseReflectionResponse(t *testing.T) {
	s := NewGRPCScanner(DefaultGRPCConfig())

	// Build a minimal ServerReflectionResponse with list_services_response
	// list_services_response (field 7) contains ServiceResponse entries
	// ServiceResponse { string name = 1; }

	// ServiceResponse for "grpc.health.v1.Health"
	svc1Name := "grpc.health.v1.Health"
	svc1 := []byte{0x0a, byte(len(svc1Name))} // field 1 (name), length
	svc1 = append(svc1, []byte(svc1Name)...)

	// ServiceResponse for "my.Service"
	svc2Name := "my.Service"
	svc2 := []byte{0x0a, byte(len(svc2Name))} // field 1 (name), length
	svc2 = append(svc2, []byte(svc2Name)...)

	// list_services_response (field 1 in the response, but we're looking at field 7 in outer)
	// ListServiceResponse { repeated ServiceResponse services = 1; }
	lsr := []byte{0x0a, byte(len(svc1))} // field 1, length
	lsr = append(lsr, svc1...)
	lsr = append(lsr, []byte{0x0a, byte(len(svc2))}...) // field 1, length
	lsr = append(lsr, svc2...)

	// ServerReflectionResponse { list_services_response = 7; }
	msg := []byte{0x3a, byte(len(lsr))} // field 7, length
	msg = append(msg, lsr...)

	services := s.parseReflectionResponse(msg)
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
	if services[0].Name != "grpc.health.v1.Health" {
		t.Errorf("expected grpc.health.v1.Health, got %s", services[0].Name)
	}
	if services[1].Name != "my.Service" {
		t.Errorf("expected my.Service, got %s", services[1].Name)
	}
}

func TestGRPCScanner_ParseServiceName(t *testing.T) {
	s := NewGRPCScanner(DefaultGRPCConfig())

	// ServiceResponse { string name = 1; }
	name := "test.Service"
	msg := []byte{0x0a, byte(len(name))} // field 1, length
	msg = append(msg, []byte(name)...)

	svc := s.parseServiceName(msg)
	if svc.Name != "test.Service" {
		t.Errorf("expected test.Service, got %s", svc.Name)
	}
}

func TestGRPCScanner_ParseMethodName(t *testing.T) {
	s := NewGRPCScanner(DefaultGRPCConfig())

	// MethodDescriptorProto { string name = 1; }
	name := "SayHello"
	msg := []byte{0x0a, byte(len(name))}
	msg = append(msg, []byte(name)...)

	methodName := s.parseMethodName(msg)
	if methodName != "SayHello" {
		t.Errorf("expected SayHello, got %s", methodName)
	}
}

func TestGRPCScanner_ParseServiceMethods(t *testing.T) {
	s := NewGRPCScanner(DefaultGRPCConfig())

	// Build a ServiceDescriptorProto:
	// { string name = 1; repeated MethodDescriptorProto method = 2; }
	svcName := "Greeter"
	method1 := "SayHello"
	method2 := "SayGoodbye"

	// MethodDescriptorProto for SayHello
	m1 := []byte{0x0a, byte(len(method1))}
	m1 = append(m1, []byte(method1)...)
	// MethodDescriptorProto for SayGoodbye
	m2 := []byte{0x0a, byte(len(method2))}
	m2 = append(m2, []byte(method2)...)

	// ServiceDescriptorProto
	msg := []byte{0x0a, byte(len(svcName))} // field 1 (name)
	msg = append(msg, []byte(svcName)...)
	msg = append(msg, []byte{0x12, byte(len(m1))}...) // field 2 (method)
	msg = append(msg, m1...)
	msg = append(msg, []byte{0x12, byte(len(m2))}...) // field 2 (method)
	msg = append(msg, m2...)

	methods := s.parseServiceMethods(msg, "")
	if len(methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(methods))
	}
	if methods[0] != "SayHello" {
		t.Errorf("expected SayHello, got %s", methods[0])
	}
	if methods[1] != "SayGoodbye" {
		t.Errorf("expected SayGoodbye, got %s", methods[1])
	}
}

func TestGRPCScanner_ParseFileDescriptorMethods(t *testing.T) {
	s := NewGRPCScanner(DefaultGRPCConfig())

	// Build a FileDescriptorProto:
	// { repeated DescriptorProto service = 6; }
	svcName := "Greeter"
	method1 := "SayHello"

	// MethodDescriptorProto
	m1 := []byte{0x0a, byte(len(method1))}
	m1 = append(m1, []byte(method1)...)

	// ServiceDescriptorProto
	svc := []byte{0x0a, byte(len(svcName))}
	svc = append(svc, []byte(svcName)...)
	svc = append(svc, []byte{0x12, byte(len(m1))}...)
	svc = append(svc, m1...)

	// FileDescriptorProto with service field (field 6)
	fd := []byte{0x32, byte(len(svc))} // field 6, length
	fd = append(fd, svc...)

	methods := s.parseFileDescriptorMethods(fd, "")
	if len(methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(methods))
	}
	if methods[0] != "SayHello" {
		t.Errorf("expected SayHello, got %s", methods[0])
	}
}

func TestGRPCScanner_ExtractFileDescriptorBytes(t *testing.T) {
	s := NewGRPCScanner(DefaultGRPCConfig())

	// FileDescriptorResponse { repeated bytes file_descriptor_proto = 1; }
	rawProto := []byte{0x01, 0x02, 0x03, 0x04} // dummy bytes
	msg := []byte{0x0a, byte(len(rawProto))}   // field 1, length
	msg = append(msg, rawProto...)

	result := s.extractFileDescriptorBytes(msg)
	if len(result) != len(rawProto) {
		t.Errorf("expected %d bytes, got %d", len(rawProto), len(result))
	}
}

// ============= WebSocket Tests =============

func TestWebSocketScanner_NormalizeURL(t *testing.T) {
	// Test URL normalization indirectly through Scan error
	s := NewWebSocketScanner(WebSocketConfig{Timeout: 500 * time.Millisecond})

	tests := []struct {
		input  string
		expect string
	}{
		{"http://example.com/ws", "ws://example.com/ws"},
		{"https://example.com/ws", "wss://example.com/ws"},
		{"ws://example.com/ws", "ws://example.com/ws"},
		{"wss://example.com/ws", "wss://example.com/ws"},
		{"example.com/ws", "ws://example.com/ws"},
	}

	for _, tt := range tests {
		result, _ := s.Scan(context.Background(), tt.input, nil)
		// The URL in the result should be the normalized form
		if result.URL != tt.expect {
			t.Errorf("URL normalization: input %q → got %q, expect %q", tt.input, result.URL, tt.expect)
		}
	}
}

func TestWebSocketScanner_ConnectionFailure(t *testing.T) {
	s := NewWebSocketScanner(WebSocketConfig{Timeout: 2 * time.Second})
	result, err := s.Scan(context.Background(), "ws://127.0.0.1:9999", nil)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Connected {
		t.Error("expected connection failure")
	}
	if result.Error == "" {
		t.Error("expected error message")
	}
}

func TestDefaultSequences(t *testing.T) {
	seqs := DefaultSequences()
	if len(seqs) != 3 {
		t.Fatalf("expected 3 default sequences, got %d", len(seqs))
	}

	names := map[string]bool{}
	for _, seq := range seqs {
		names[seq.Name] = true
		if len(seq.Steps) == 0 {
			t.Errorf("sequence %s has no steps", seq.Name)
		}
	}

	expected := []string{"basic-connect", "auth-probe", "fuzz-basic"}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("missing sequence: %s", name)
		}
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 100) != "short" {
		t.Error("expected short string unchanged")
	}
	result := truncate(strings.Repeat("A", 200), 100)
	if len(result) != 100+len("...[truncated]") {
		t.Errorf("expected truncated length %d, got %d", 100+len("...[truncated]"), len(result))
	}
	if !strings.Contains(result, "...[truncated]") {
		t.Error("expected truncated suffix")
	}
}

func TestGraphQLPaths(t *testing.T) {
	if len(graphqlPaths) == 0 {
		t.Error("expected GraphQL paths to be defined")
	}
	found := false
	for _, p := range graphqlPaths {
		if p == "/graphql" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected /graphql in paths")
	}
}

func TestWebSocketSecIssue(t *testing.T) {
	result := &WebSocketResult{
		Messages: []WebSocketMessage{
			{Direction: "received", Data: `{"error":"unauthorized: token required"}`},
		},
	}
	s := NewWebSocketScanner(DefaultWebSocketConfig())
	s.checkSecurityIssues(result)
	if !result.AuthRequired {
		t.Error("expected auth required to be detected")
	}
}

func TestWebSocketSecIssue_AuthBypass(t *testing.T) {
	// "token" in a non-error context should NOT trigger auth detection
	result := &WebSocketResult{
		Messages: []WebSocketMessage{
			{Direction: "received", Data: `{"type":"welcome","token":"abc123","data":"hello"}`},
		},
	}
	s := NewWebSocketScanner(DefaultWebSocketConfig())
	s.checkSecurityIssues(result)
	if result.AuthRequired {
		t.Error("expected auth NOT to be triggered by benign token mention")
	}
}

func TestWebSocketSecIssue_XSS(t *testing.T) {
	result := &WebSocketResult{
		Messages: []WebSocketMessage{
			{Direction: "sent", Data: `<script>alert(1)</script>`},
			{Direction: "received", SentPayload: `<script>alert(1)</script>`, Data: `<script>alert(1)</script>`},
		},
	}
	s := NewWebSocketScanner(DefaultWebSocketConfig())
	s.checkSecurityIssues(result)
	found := false
	for _, issue := range result.SecurityIssues {
		if issue.Type == "xss-reflection" {
			found = true
		}
	}
	if !found {
		t.Error("expected XSS reflection to be detected")
	}
}

func TestWebSocketSecIssue_XSS_NoFalsePositive(t *testing.T) {
	// Server sends <script> as part of normal content, but we didn't send an XSS probe
	result := &WebSocketResult{
		Messages: []WebSocketMessage{
			{Direction: "sent", Data: `{"type":"hello"}`},
			{Direction: "received", SentPayload: `{"type":"hello"}`, Data: `<script>app.init()</script>`},
		},
	}
	s := NewWebSocketScanner(DefaultWebSocketConfig())
	s.checkSecurityIssues(result)
	for _, issue := range result.SecurityIssues {
		if issue.Type == "xss-reflection" {
			t.Error("expected NO XSS FP for server-originated script tag")
		}
	}
}

func TestWebSocketSecIssue_SQLError(t *testing.T) {
	result := &WebSocketResult{
		Messages: []WebSocketMessage{
			{Direction: "received", Data: `{"error":"SQL syntax error at or near 'FROM'"}`},
		},
	}
	s := NewWebSocketScanner(DefaultWebSocketConfig())
	s.checkSecurityIssues(result)
	found := false
	for _, issue := range result.SecurityIssues {
		if issue.Type == "sql-error-leakage" {
			found = true
		}
	}
	if !found {
		t.Error("expected SQL error leakage to be detected")
	}
}

func TestWebSocketSecIssue_SQLError_NoFalsePositive(t *testing.T) {
	// "sql" in a benign context (e.g., field name) should NOT trigger
	result := &WebSocketResult{
		Messages: []WebSocketMessage{
			{Direction: "received", Data: `{"type":"data","sql_query":"SELECT 1","result":"ok"}`},
		},
	}
	s := NewWebSocketScanner(DefaultWebSocketConfig())
	s.checkSecurityIssues(result)
	for _, issue := range result.SecurityIssues {
		if issue.Type == "sql-error-leakage" {
			t.Error("expected NO SQL error FP for benign sql mention")
		}
	}
}

func TestWebSocketSecIssue_NoAuth(t *testing.T) {
	result := &WebSocketResult{
		Messages: []WebSocketMessage{
			{Direction: "received", Data: `{"type":"hello","data":"welcome"}`},
		},
	}
	s := NewWebSocketScanner(DefaultWebSocketConfig())
	s.checkSecurityIssues(result)
	found := false
	for _, issue := range result.SecurityIssues {
		if issue.Type == "no-authentication" {
			found = true
		}
	}
	if !found {
		t.Error("expected no-authentication issue")
	}
}
