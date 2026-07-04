// Package banner provides a multi-protocol banner grabber.
// It connects to a TCP service and reads the initial banner (if any)
// without sending any data, then optionally sends a probe and reads
// the response. Supports common protocols: SSH, FTP, SMTP, Redis,
// MySQL, MSSQL, RDP, VNC, and generic TCP.
package banner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// Grabber connects to TCP services and captures banners.
type Grabber struct {
	// Timeout per connection (default 5s)
	Timeout time.Duration
	// MaxBannerBytes limits how much data to read (default 4096)
	MaxBannerBytes int
	// TLSEnabled attempts TLS handshake before reading
	TLSEnabled bool
	// TLSSkipVerify disables certificate verification
	TLSSkipVerify bool
}

// Result contains the grabbed banner and metadata.
type Result struct {
	// Address is the host:port that was probed
	Address string
	// Banner is the raw banner text
	Banner string
	// Protocol is the detected protocol (if any)
	Protocol string
	// Service is the detected service name
	Service string
	// TLS indicates if TLS was used
	TLS bool
	// Error is any error that occurred
	Error error
}

// Default returns a Grabber with sensible defaults.
func Default() *Grabber {
	return &Grabber{
		Timeout:        5 * time.Second,
		MaxBannerBytes: 4096,
		TLSSkipVerify:  true,
	}
}

// Grab connects to the given address and reads the banner.
// If probe is non-empty, it sends the probe first, then reads the response.
func (g *Grabber) Grab(ctx context.Context, address, probe string) (*Result, error) {
	if g.Timeout == 0 {
		g.Timeout = 5 * time.Second
	}
	if g.MaxBannerBytes == 0 {
		g.MaxBannerBytes = 4096
	}

	result := &Result{Address: address, TLS: g.TLSEnabled}

	dialer := &net.Dialer{Timeout: g.Timeout}

	var conn net.Conn
	var err error

	if g.TLSEnabled {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: g.TLSSkipVerify,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		result.Error = err
		return result, err
	}
	defer conn.Close()

	// Set deadline
	deadline := time.Now().Add(g.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	// If a probe is specified, send it
	if probe != "" {
		_, err = conn.Write([]byte(probe))
		if err != nil {
			result.Error = fmt.Errorf("send probe: %w", err)
			return result, result.Error
		}
	}

	// Read banner
	buf := make([]byte, g.MaxBannerBytes)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		result.Error = fmt.Errorf("read banner: %w", err)
		return result, result.Error
	}

	banner := string(buf[:n])
	result.Banner = strings.TrimSpace(banner)
	result.Protocol = DetectProtocol(result.Banner)
	result.Service = ProtocolToService(result.Protocol)

	return result, nil
}

// GrabBatch grabs banners from multiple addresses concurrently.
func (g *Grabber) GrabBatch(ctx context.Context, addresses []string, probe string) []*Result {
	results := make([]*Result, len(addresses))
	sem := make(chan struct{}, 50) // concurrency limit

	for i, addr := range addresses {
		sem <- struct{}{}
		go func(idx int, address string) {
			defer func() { <-sem }()
			r, _ := g.Grab(ctx, address, probe)
			results[idx] = r
		}(i, addr)
	}

	// Wait for all
	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}

	return results
}

// DetectProtocol attempts to identify the protocol from the banner text.
func DetectProtocol(banner string) string {
	lower := strings.ToLower(banner)

	switch {
	case strings.HasPrefix(lower, "ssh-"):
		return "ssh"
	case strings.HasPrefix(lower, "+ok"):
		return "pop3"
	case strings.HasPrefix(lower, "* ok"):
		return "imap"
	case strings.HasPrefix(lower, "redis"):
		return "redis"
	case strings.Contains(lower, "mysql"):
		return "mysql"
	case strings.Contains(lower, "microsoft sql") || strings.Contains(lower, "mssql"):
		return "mssql"
	case strings.HasPrefix(lower, "rdp"):
		return "rdp"
	case strings.HasPrefix(lower, "rfb "):
		return "vnc"
	case strings.HasPrefix(lower, "smb"):
		return "smb"
	case strings.HasPrefix(lower, "memcached"):
		return "memcached"
	case strings.Contains(lower, "elasticsearch"):
		return "elasticsearch"
	case strings.Contains(lower, "mongodb"):
		return "mongodb"
	// SMTP: "220 ... ESMTP/SMTP/Postfix/Exim"
	case strings.HasPrefix(lower, "220") && (strings.Contains(lower, "smtp") || strings.Contains(lower, "esmtp") || strings.Contains(lower, "postfix") || strings.Contains(lower, "exim")):
		return "smtp"
	// FTP: "220 ... ftp/vsftpd/proftpd/filezilla"
	case strings.HasPrefix(lower, "220") && (strings.Contains(lower, "ftp") || strings.Contains(lower, "vsftpd") || strings.Contains(lower, "proftpd") || strings.Contains(lower, "filezilla")):
		return "ftp"
	// Generic "220" fallback — likely FTP
	case strings.HasPrefix(lower, "220"):
		return "ftp"
	case strings.Contains(lower, "nginx") || strings.Contains(lower, "apache"):
		return "http"
	default:
		return "unknown"
	}
}

// ProtocolToService maps a detected protocol to a common service name.
func ProtocolToService(protocol string) string {
	switch protocol {
	case "ssh":
		return "SSH Server"
	case "ftp":
		return "FTP Server"
	case "smtp":
		return "SMTP Mail Server"
	case "pop3":
		return "POP3 Mail Server"
	case "imap":
		return "IMAP Mail Server"
	case "redis":
		return "Redis Cache"
	case "mysql":
		return "MySQL Database"
	case "mssql":
		return "Microsoft SQL Server"
	case "rdp":
		return "Remote Desktop"
	case "vnc":
		return "VNC Remote Desktop"
	case "http":
		return "HTTP Server"
	case "smb":
		return "SMB File Server"
	case "memcached":
		return "Memcached Cache"
	case "elasticsearch":
		return "Elasticsearch"
	case "mongodb":
		return "MongoDB Database"
	default:
		return "Unknown Service"
	}
}

// CommonProbes contains protocol-specific probes that trigger banners
// for services that don't send banners on connect.
var CommonProbes = map[string]string{
	"http":       "GET / HTTP/1.0\r\nHost: {{host}}\r\n\r\n",
	"redis":      "INFO\r\n",
	"memcached":  "version\r\n",
	"mysql":      "", // MySQL sends banner on connect
	"smtp":       "", // SMTP sends banner on connect
	"ftp":        "", // FTP sends banner on connect
	"ssh":        "", // SSH sends banner on connect
	"pop3":       "", // POP3 sends banner on connect
	"imap":       "", // IMAP sends banner on connect
	"vnc":        "", // VNC sends banner on connect
	"elasticsearch": "GET / HTTP/1.0\r\n\r\n",
	"mongodb":    "", // MongoDB requires binary protocol
}
