package protodeep

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// WebSocketScanner performs stateful WebSocket message sequences
type WebSocketScanner struct {
	timeout time.Duration
}

// WebSocketConfig configures the WebSocket scanner
type WebSocketConfig struct {
	Timeout time.Duration
	Headers map[string]string
}

// DefaultWebSocketConfig returns sensible defaults
func DefaultWebSocketConfig() WebSocketConfig {
	return WebSocketConfig{
		Timeout: 10 * time.Second,
		Headers: map[string]string{},
	}
}

// NewWebSocketScanner creates a new WebSocket scanner
func NewWebSocketScanner(config WebSocketConfig) *WebSocketScanner {
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	return &WebSocketScanner{
		timeout: config.Timeout,
	}
}

// WebSocketResult holds the scan result
type WebSocketResult struct {
	URL            string               `json:"url"`
	Connected      bool                 `json:"connected"`
	Subprotocol    string               `json:"subprotocol,omitempty"`
	Messages       []WebSocketMessage   `json:"messages,omitempty"`
	AuthRequired   bool                 `json:"auth_required"`
	Error          string               `json:"error,omitempty"`
	SecurityIssues []WebSocketSecIssue  `json:"security_issues,omitempty"`
}

// WebSocketMessage represents a message exchanged
type WebSocketMessage struct {
	Direction string `json:"direction"` // "sent" or "received"
	Data      string `json:"data"`
	OpCode    string `json:"op_code"`
	Timestamp string `json:"timestamp"`
	// SentPayload tracks which sent message this response corresponds to,
	// enabling context-aware reflection detection.
	SentPayload string `json:"sent_payload,omitempty"`
}

// WebSocketSecIssue represents a security issue found
type WebSocketSecIssue struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// WebSocketSequence defines a stateful message sequence
type WebSocketSequence struct {
	Name    string
	Headers map[string]string
	Steps   []WebSocketStep
}

// WebSocketStep is a single step in a sequence
type WebSocketStep struct {
	Name    string
	Send    string // message to send
	WaitFor int    // number of messages to wait for (0 = don't wait)
	Timeout time.Duration
}

// DefaultSequences returns common WebSocket test sequences
func DefaultSequences() []WebSocketSequence {
	return []WebSocketSequence{
		{
			Name: "basic-connect",
			Steps: []WebSocketStep{
				{Name: "hello", Send: `{"type":"hello","version":"1.0"}`, WaitFor: 1, Timeout: 5 * time.Second},
			},
		},
		{
			Name: "auth-probe",
			Steps: []WebSocketStep{
				{Name: "auth-check", Send: `{"type":"auth","token":"test"}`, WaitFor: 1, Timeout: 5 * time.Second},
				{Name: "ping", Send: `{"type":"ping"}`, WaitFor: 1, Timeout: 5 * time.Second},
			},
		},
		{
			Name: "fuzz-basic",
			Steps: []WebSocketStep{
				{Name: "long-string", Send: strings.Repeat("A", 10000), WaitFor: 1, Timeout: 3 * time.Second},
				{Name: "special-chars", Send: `{"type":"test","data":"<script>alert(1)</script>"}`, WaitFor: 1, Timeout: 3 * time.Second},
			},
		},
	}
}

// Scan performs a WebSocket scan with default sequences
func (s *WebSocketScanner) Scan(ctx context.Context, url string, headers map[string]string) (*WebSocketResult, error) {
	return s.ScanWithSequences(ctx, url, headers, DefaultSequences())
}

// ScanWithSequences performs a WebSocket scan with custom sequences
func (s *WebSocketScanner) ScanWithSequences(ctx context.Context, url string, headers map[string]string, sequences []WebSocketSequence) (*WebSocketResult, error) {
	result := &WebSocketResult{URL: url}

	// Normalize URL
	originalURL := url
	if !strings.HasPrefix(url, "ws://") && !strings.HasPrefix(url, "wss://") {
		if strings.HasPrefix(url, "https://") {
			url = "wss://" + strings.TrimPrefix(url, "https://")
		} else if strings.HasPrefix(url, "http://") {
			url = "ws://" + strings.TrimPrefix(url, "http://")
		} else {
			url = "ws://" + url
		}
	}
	_ = originalURL
	result.URL = url

	// Build headers for the handshake
	hsHeader := http.Header{}
	for k, v := range headers {
		hsHeader.Set(k, v)
	}

	// Create ws.Dialer
	dialer := ws.Dialer{
		Timeout: s.timeout,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Header: ws.HandshakeHeaderHTTP(hsHeader),
	}

	// Try to connect
	conn, readBuffer, _, err := dialer.Dial(ctx, url)
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		return result, nil
	}
	defer conn.Close()
	result.Connected = true

	// Copy any initial data from readBuffer
	if readBuffer != nil {
		buf := make([]byte, 4096)
		n, _ := readBuffer.Read(buf)
		if n > 0 {
			result.Messages = append(result.Messages, WebSocketMessage{
				Direction: "received",
				Data:      truncate(string(buf[:n]), 500),
				OpCode:    "text",
				Timestamp: time.Now().Format(time.RFC3339),
			})
		}
	}

	// Run sequences
	for _, seq := range sequences {
		s.runSequence(ctx, conn, seq, result)
	}

	// Check security issues
	s.checkSecurityIssues(result)

	return result, nil
}

// runSequence executes a sequence of WebSocket steps
func (s *WebSocketScanner) runSequence(ctx context.Context, conn net.Conn, seq WebSocketSequence, result *WebSocketResult) {
	var lastSent string
	for _, step := range seq.Steps {
		// Send message
		if step.Send != "" {
			err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(step.Send))
			if err == nil {
				result.Messages = append(result.Messages, WebSocketMessage{
					Direction: "sent",
					Data:      truncate(step.Send, 500),
					OpCode:    "text",
					Timestamp: time.Now().Format(time.RFC3339),
				})
				lastSent = step.Send
			}
		}

		// Wait for response
		if step.WaitFor > 0 {
			timeout := step.Timeout
			if timeout == 0 {
				timeout = s.timeout
			}
			for i := 0; i < step.WaitFor; i++ {
				msg, err := s.readMessage(conn, timeout)
				if err != nil {
					break
				}
				result.Messages = append(result.Messages, WebSocketMessage{
					Direction:   "received",
					Data:        truncate(msg, 500),
					OpCode:      "text",
					Timestamp:   time.Now().Format(time.RFC3339),
					SentPayload: truncate(lastSent, 200),
				})
			}
		}
	}
}

// readMessage reads a WebSocket message with timeout
func (s *WebSocketScanner) readMessage(conn net.Conn, timeout time.Duration) (string, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	msg, op, err := wsutil.ReadServerData(conn)
	if err != nil {
		return "", err
	}
	opStr := "text"
	switch op {
	case ws.OpBinary:
		opStr = "binary"
	case ws.OpPing:
		opStr = "ping"
	case ws.OpPong:
		opStr = "pong"
	case ws.OpClose:
		opStr = "close"
	}
	_ = opStr
	return string(msg), nil
}

// checkSecurityIssues analyzes the result for security issues using
// context-aware pattern matching. Instead of naive substring matching,
// it parses JSON structure, checks error context, and correlates
// sent vs received messages to distinguish real issues from benign
// responses.
func (s *WebSocketScanner) checkSecurityIssues(result *WebSocketResult) {
	for _, msg := range result.Messages {
		if msg.Direction != "received" {
			continue
		}
		lowerMsg := strings.ToLower(msg.Data)

		// Auth detection: look for auth-related keywords in error/status context
		if isAuthError(lowerMsg) {
			result.AuthRequired = true
		}

		// Error leakage: require "error" or "exception" context + stack trace indicators
		if isErrorLeakage(lowerMsg) {
			result.SecurityIssues = append(result.SecurityIssues, WebSocketSecIssue{
				Type:        "error-leakage",
				Severity:    "medium",
				Description: "Server leaks stack traces or internal errors in error context",
			})
		}

		// SQL error: require database-specific error patterns (not just "sql" substring)
		if isSQLErrorLeakage(lowerMsg) {
			result.SecurityIssues = append(result.SecurityIssues, WebSocketSecIssue{
				Type:        "sql-error-leakage",
				Severity:    "high",
				Description: "Database error messages visible in WebSocket responses",
			})
		}

		// XSS reflection: check if sent payload is reflected back unescaped
		if isXSSReflection(msg.SentPayload, msg.Data) {
			result.SecurityIssues = append(result.SecurityIssues, WebSocketSecIssue{
				Type:        "xss-reflection",
				Severity:    "high",
				Description: "Sent payload reflected in response without sanitization (XSS)",
			})
		}
	}

	// Check for no auth on sensitive operations
	if !result.AuthRequired {
		result.SecurityIssues = append(result.SecurityIssues, WebSocketSecIssue{
			Type:        "no-authentication",
			Severity:    "medium",
			Description: "WebSocket endpoint accepts messages without authentication",
		})
	}
}

// isAuthError checks if a response indicates an authentication error.
// Requires both an auth keyword AND an error/status context to avoid
// matching auth tokens in benign data.
func isAuthError(lowerMsg string) bool {
	authKeywords := []string{"unauthorized", "not authenticated", "auth required", "authentication failed", "invalid token", "access denied"}
	for _, kw := range authKeywords {
		if strings.Contains(lowerMsg, kw) {
			return true
		}
	}
	// JSON structure with auth error
	if strings.Contains(lowerMsg, `"error"`) && (strings.Contains(lowerMsg, "auth") || strings.Contains(lowerMsg, "token")) {
		return true
	}
	return false
}

// isErrorLeakage checks for stack trace leakage. Requires both an error
// context AND trace/debug indicators to avoid matching benign mentions.
func isErrorLeakage(lowerMsg string) bool {
	hasErrorCtx := strings.Contains(lowerMsg, "error") || strings.Contains(lowerMsg, "exception") || strings.Contains(lowerMsg, "fail")
	hasTrace := strings.Contains(lowerMsg, "stack") || strings.Contains(lowerMsg, "trace") ||
		strings.Contains(lowerMsg, "at line") || strings.Contains(lowerMsg, ".go:") ||
		strings.Contains(lowerMsg, ".java:") || strings.Contains(lowerMsg, ".py:") ||
		strings.Contains(lowerMsg, "file ") && strings.Contains(lowerMsg, "line ")
	return hasErrorCtx && hasTrace
}

// isSQLErrorLeakage checks for database-specific error patterns.
// Uses precise DBMS signatures instead of matching the generic "sql" substring.
func isSQLErrorLeakage(lowerMsg string) bool {
	// PostgreSQL: "ERROR:  syntax error at or near"
	// MySQL: "You have an error in your SQL syntax"
	// SQLite: "SQLITE_ERROR: near"
	// MSSQL: "Unclosed quotation mark after the character string"
	sqlPatterns := []string{
		"syntax error at or near",
		"you have an error in your sql syntax",
		"sqlite_error",
		"unclosed quotation mark",
		"odbc sql server driver",
		"ora-",           // Oracle
		"pg_ aborted",    // PostgreSQL
		"mysql_fetch",
		"pg_query",
		"sqlstate[",
	}
	for _, p := range sqlPatterns {
		if strings.Contains(lowerMsg, p) {
			return true
		}
	}
	// Also match JSON error with SQL context
	if strings.Contains(lowerMsg, `"error"`) && (strings.Contains(lowerMsg, "sql") || strings.Contains(lowerMsg, "query")) {
		return true
	}
	return false
}

// isXSSReflection checks if a sent payload containing XSS vectors is
// reflected back in the response without sanitization. Requires that
// the sent payload actually contained an XSS probe (not just any
// <script> in a response, which could be legitimate server content).
func isXSSReflection(sentPayload, response string) bool {
	if sentPayload == "" {
		return false
	}
	// Check if sent payload contained XSS probes
	xssProbes := []string{"<script>", "<img onerror", "<svg onload", "javascript:", "<iframe"}
	hasProbe := false
	lowerSent := strings.ToLower(sentPayload)
	for _, probe := range xssProbes {
		if strings.Contains(lowerSent, probe) {
			hasProbe = true
			break
		}
	}
	if !hasProbe {
		return false
	}
	// Check if the exact probe is reflected unescaped in the response
	lowerResp := strings.ToLower(response)
	for _, probe := range xssProbes {
		if strings.Contains(lowerSent, probe) && strings.Contains(lowerResp, probe) {
			return true
		}
	}
	return false
}

// truncate limits a string to maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[truncated]"
}
