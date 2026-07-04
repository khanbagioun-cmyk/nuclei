package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

const binaryPath = "/Users/WorkMain/nuclei-fork/bin/nuclei-protodeep"

func runCLI(args ...string) (string, int, error) {
	cmd := exec.Command(binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), cmd.ProcessState.ExitCode(), err
}

func TestCLI_NoTarget(t *testing.T) {
	_, code, _ := runCLI("-silent")
	if code == 0 {
		t.Error("expected non-zero exit code")
	}
}

func TestCLI_GraphQLText(t *testing.T) {
	// Start mock GraphQL server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/graphql" {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if strings.Contains(body["query"], "__typename") {
				w.Write([]byte(`{"data":{"__typename":"Query"}}`))
				return
			}
			if strings.Contains(body["query"], "__schema") {
				w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"subscriptionType":null,"types":[{"name":"Query","kind":"OBJECT","fields":[{"name":"hello"}]}]}}}`))
				return
			}
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	out, code, err := runCLI("-t", server.URL, "-proto", "graphql", "-json", "-silent")
	if err != nil && code != 0 {
		t.Fatalf("CLI failed: %v\n%s", err, out)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	gql, ok := result["graphql"]
	if !ok {
		t.Fatal("expected graphql key in result")
	}
	gqlMap := gql.(map[string]interface{})
	if gqlMap["endpoint_found"] != true {
		t.Error("expected endpoint_found true")
	}
}

func TestCLI_GraphQLNoEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer server.Close()

	out, _, err := runCLI("-t", server.URL, "-proto", "graphql", "-json", "-silent")
	if err != nil {
		t.Fatalf("CLI failed: %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal([]byte(out), &result)
	gql := result["graphql"].(map[string]interface{})
	if gql["endpoint_found"] == true {
		t.Error("expected endpoint_found false")
	}
}

func TestCLI_GRPCNoServer(t *testing.T) {
	out, _, err := runCLI("-t", "127.0.0.1:9999", "-proto", "grpc", "-json", "-silent", "-timeout", "2s")
	if err != nil {
		t.Fatalf("CLI failed: %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal([]byte(out), &result)
	grpc := result["grpc"].(map[string]interface{})
	if grpc["reflection_enabled"] == true {
		t.Error("expected reflection disabled")
	}
}

func TestCLI_WebSocketFailure(t *testing.T) {
	out, _, err := runCLI("-t", "ws://127.0.0.1:9999", "-proto", "websocket", "-json", "-silent", "-timeout", "2s")
	if err != nil {
		t.Fatalf("CLI failed: %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal([]byte(out), &result)
	ws := result["websocket"].(map[string]interface{})
	if ws["connected"] == true {
		t.Error("expected connection failure")
	}
}

func TestCLI_AllProtocols(t *testing.T) {
	out, code, err := runCLI("-t", "http://127.0.0.1:9999", "-proto", "all", "-json", "-silent", "-timeout", "2s")
	if err != nil && code != 0 {
		t.Fatalf("CLI failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	// Should have all three protocol results
	for _, proto := range []string{"graphql", "grpc", "websocket"} {
		if _, ok := result[proto]; !ok {
			t.Errorf("expected %s key in result", proto)
		}
	}
}

func TestCLI_TextOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer server.Close()

	out, _, err := runCLI("-t", server.URL, "-proto", "graphql", "-silent")
	if err != nil {
		t.Fatalf("CLI failed: %v", err)
	}
	if !strings.Contains(out, "GraphQL Scan") {
		t.Error("expected 'GraphQL Scan' in text output")
	}
}

func TestCLI_ParseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer server.Close()

	out, _, err := runCLI("-t", server.URL, "-proto", "graphql", "-json", "-silent",
		"-headers", "Authorization:Bearer test")
	if err != nil {
		t.Fatalf("CLI failed: %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal([]byte(out), &result)
	gql := result["graphql"].(map[string]interface{})
	if gql["endpoint_found"] != true {
		t.Error("expected endpoint found with auth header")
	}
}

func TestCLI_UnknownProtocol(t *testing.T) {
	_, code, _ := runCLI("-t", "http://example.com", "-proto", "ftp", "-silent")
	if code == 0 {
		t.Error("expected non-zero exit for unknown protocol")
	}
}
