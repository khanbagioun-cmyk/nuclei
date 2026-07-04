package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protodeep"
)

const banner = `
    _   __           ____                            _   _       _       
   / | / /___ ______/ __/___  _________ ___  ___    / \ | | ___ | |_ ___ 
  /  |/ / __  / ___/ /_/ __ \/ ___/ __  __  _ \   /  \| |/ _ \| __/ _ \
 / /|  / /_/ (__  ) __/ /_/ / /  / /_/ / /_/ // /  / /\  | | (_) | ||  __/
/_/ |_|\__,_/____/_/  \____/_/   \__,_/\___/(_)  /_/  \_|\___/ \__\___|
                                                                
              Protocol Deep Scanner (GraphQL / gRPC / WebSocket)`

func main() {
	var (
		target     string
		protocol   string
		jsonOutput bool
		timeout    time.Duration
		headers    string
		useTLS     bool
		quiet      bool
	)

	flag.StringVar(&target, "target", "", "target URL (e.g., http://example.com, grpc-server:50051, ws://example.com/ws)")
	flag.StringVar(&target, "t", "", "shorthand for -target")
	flag.StringVar(&protocol, "proto", "all", "protocol to scan: graphql, grpc, websocket, all")
	flag.BoolVar(&jsonOutput, "json", false, "output JSON report")
	flag.DurationVar(&timeout, "timeout", 15*time.Second, "scan timeout")
	flag.StringVar(&headers, "headers", "", "custom headers (format: 'Key:Value,Key2:Value2')")
	flag.BoolVar(&useTLS, "tls", false, "use TLS for gRPC (default: false/plaintext)")
	flag.BoolVar(&quiet, "silent", false, "suppress banner")

	flag.Parse()

	if !quiet && !jsonOutput {
		fmt.Println(banner)
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: -target is required")
		flag.Usage()
		os.Exit(1)
	}

	// Parse headers
	headerMap := parseHeaders(headers)

	ctx, cancel := context.WithTimeout(context.Background(), timeout*3)
	defer cancel()

	result := make(map[string]interface{})

	switch strings.ToLower(protocol) {
	case "graphql", "gql":
		result["graphql"] = scanGraphQL(ctx, target, headerMap, timeout)
	case "grpc":
		result["grpc"] = scanGRPC(ctx, target, useTLS, timeout)
	case "websocket", "ws":
		result["websocket"] = scanWebSocket(ctx, target, headerMap, timeout)
	case "all":
		result["graphql"] = scanGraphQL(ctx, target, headerMap, timeout)
		result["grpc"] = scanGRPC(ctx, target, useTLS, timeout)
		// For WebSocket, try to convert HTTP URL to WS
		wsTarget := target
		if strings.HasPrefix(wsTarget, "http://") {
			wsTarget = "ws://" + strings.TrimPrefix(wsTarget, "http://")
		} else if strings.HasPrefix(wsTarget, "https://") {
			wsTarget = "wss://" + strings.TrimPrefix(wsTarget, "https://")
		}
		result["websocket"] = scanWebSocket(ctx, wsTarget, headerMap, timeout)
	default:
		fmt.Fprintf(os.Stderr, "Unknown protocol: %s (use: graphql, grpc, websocket, all)\n", protocol)
		os.Exit(1)
	}

	if jsonOutput {
		printJSON(result)
	} else {
		printText(result)
	}
}

func scanGraphQL(ctx context.Context, target string, headers map[string]string, timeout time.Duration) *protodeep.GraphQLResult {
	scanner := protodeep.NewGraphQLScanner(protodeep.GraphQLConfig{
		Timeout: timeout,
		Headers: headers,
	})
	result, err := scanner.Scan(ctx, target, headers)
	if err != nil {
		return &protodeep.GraphQLResult{Error: err.Error()}
	}
	return result
}

func scanGRPC(ctx context.Context, target string, useTLS bool, timeout time.Duration) *protodeep.GRPCResult {
	scanner := protodeep.NewGRPCScanner(protodeep.GRPCConfig{Timeout: timeout})
	result, err := scanner.Scan(ctx, target, useTLS)
	if err != nil {
		return &protodeep.GRPCResult{Error: err.Error()}
	}
	return result
}

func scanWebSocket(ctx context.Context, target string, headers map[string]string, timeout time.Duration) *protodeep.WebSocketResult {
	scanner := protodeep.NewWebSocketScanner(protodeep.WebSocketConfig{
		Timeout: timeout,
		Headers: headers,
	})
	result, err := scanner.Scan(ctx, target, headers)
	if err != nil {
		return &protodeep.WebSocketResult{Error: err.Error()}
	}
	return result
}

func parseHeaders(headerStr string) map[string]string {
	headers := map[string]string{}
	if headerStr == "" {
		return headers
	}
	pairs := strings.Split(headerStr, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) == 2 {
			headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return headers
}

func printJSON(result map[string]interface{}) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func printText(result map[string]interface{}) {
	if gql, ok := result["graphql"]; ok {
		fmt.Println("=== GraphQL Scan ===")
		printGraphQLText(gql)
		fmt.Println()
	}
	if grpc, ok := result["grpc"]; ok {
		fmt.Println("=== gRPC Scan ===")
		printGRPCText(grpc)
		fmt.Println()
	}
	if ws, ok := result["websocket"]; ok {
		fmt.Println("=== WebSocket Scan ===")
		printWebSocketText(ws)
		fmt.Println()
	}
}

func printGraphQLText(result interface{}) {
	data, _ := json.Marshal(result)
	var r protodeep.GraphQLResult
	json.Unmarshal(data, &r)

	fmt.Printf("URL:             %s\n", r.URL)
	fmt.Printf("Endpoint Found:  %v\n", r.EndpointFound)
	fmt.Printf("Introspection:   %v\n", r.Introspection)
	if r.Error != "" {
		fmt.Printf("Error:           %s\n", r.Error)
	}
	if r.FieldSuggestions {
		fmt.Printf("Field Suggestions: %v\n", r.FieldSuggestions)
	}
	if len(r.Queries) > 0 {
		fmt.Printf("Queries (%d):\n", len(r.Queries))
		for _, q := range r.Queries {
			fmt.Printf("  - %s\n", q)
		}
	}
	if len(r.Mutations) > 0 {
		fmt.Printf("Mutations (%d):\n", len(r.Mutations))
		for _, m := range r.Mutations {
			fmt.Printf("  - %s\n", m)
		}
	}
	if len(r.Enums) > 0 {
		fmt.Printf("Enums (%d):\n", len(r.Enums))
		for _, e := range r.Enums {
			fmt.Printf("  - %s: %v\n", e.Name, e.Values)
		}
	}
	if r.Schema != "" {
		fmt.Printf("\n%s\n", r.Schema)
	}
}

func printGRPCText(result interface{}) {
	data, _ := json.Marshal(result)
	var r protodeep.GRPCResult
	json.Unmarshal(data, &r)

	fmt.Printf("Target:            %s\n", r.Target)
	fmt.Printf("Reflection Enabled: %v\n", r.ReflectionEnabled)
	fmt.Printf("Health Checked:    %v\n", r.HealthChecked)
	if r.HealthStatus != "" {
		fmt.Printf("Health Status:     %s\n", r.HealthStatus)
	}
	if r.Error != "" {
		fmt.Printf("Error:             %s\n", r.Error)
	}
	if len(r.Services) > 0 {
		fmt.Printf("Services (%d):\n", len(r.Services))
		for _, svc := range r.Services {
			fmt.Printf("  - %s\n", svc.Name)
			for _, m := range svc.Methods {
				fmt.Printf("      · %s\n", m)
			}
		}
	}
}

func printWebSocketText(result interface{}) {
	data, _ := json.Marshal(result)
	var r protodeep.WebSocketResult
	json.Unmarshal(data, &r)

	fmt.Printf("URL:           %s\n", r.URL)
	fmt.Printf("Connected:     %v\n", r.Connected)
	if r.Error != "" {
		fmt.Printf("Error:         %s\n", r.Error)
	}
	if r.AuthRequired {
		fmt.Printf("Auth Required: %v\n", r.AuthRequired)
	}
	if len(r.Messages) > 0 {
		fmt.Printf("Messages (%d):\n", len(r.Messages))
		for i, msg := range r.Messages {
			if i >= 20 {
				fmt.Printf("  ... and %d more\n", len(r.Messages)-20)
				break
			}
			fmt.Printf("  [%s] %s: %s\n", msg.Direction, msg.OpCode, truncate(msg.Data, 100))
		}
	}
	if len(r.SecurityIssues) > 0 {
		fmt.Printf("Security Issues (%d):\n", len(r.SecurityIssues))
		for _, issue := range r.SecurityIssues {
			fmt.Printf("  [%s] %s: %s\n", issue.Severity, issue.Type, issue.Description)
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
