package discovery

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortServiceMap maps common ports to service names
var PortServiceMap = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 81: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
	139: "netbios", 143: "imap", 443: "https", 445: "smb",
	993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
	2049: "nfs", 2181: "zookeeper", 2375: "docker", 3306: "mysql",
	3389: "rdp", 5432: "postgresql", 5900: "vnc", 5984: "couchdb",
	6379: "redis", 6443: "k8s-api", 7474: "neo4j", 8000: "http",
	8080: "http-proxy", 8081: "http-proxy", 8443: "https-alt",
	8888: "http-proxy", 9000: "http", 9090: "http",
	9200: "elasticsearch", 9300: "elasticsearch", 9418: "git",
	11211: "memcached", 15672: "rabbitmq", 27017: "mongodb", 50070: "hadoop",
}

// runPortScan executes port scanning on all configured hosts
func (d *Discovery) runPortScan(ctx context.Context) {
	hosts := d.collectScanTargets()
	if len(hosts) == 0 {
		return
	}

	ports := d.config.Ports
	if len(ports) == 0 {
		ports = DefaultPorts
	}

	sem := make(chan struct{}, d.config.Threads)
	var wg sync.WaitGroup

	for _, host := range hosts {
		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d.scanHost(ctx, h, ports)
		}(host)
	}
	wg.Wait()
}

func (d *Discovery) collectScanTargets() []string {
	var hosts []string
	seen := make(map[string]bool)

	addHost := func(h string) {
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}

	for _, ip := range d.config.IPs {
		addHost(ip)
	}

	for _, domain := range d.config.Domains {
		ips := d.resolveHost(domain)
		if len(ips) > 0 {
			addHost(ips[0])
		} else {
			addHost(domain)
		}
	}

	for _, cidr := range d.config.CIDRs {
		ips := expandCIDR(cidr)
		for _, ip := range ips {
			addHost(ip)
		}
	}

	if !d.config.SkipDNS {
		d.mu.Lock()
		for _, dr := range d.result.Domains {
			for _, sub := range dr.Subdomains {
				ips := d.resolveHost(sub)
				if len(ips) > 0 {
					addHost(ips[0])
				}
			}
		}
		d.mu.Unlock()
	}

	return hosts
}

func expandCIDR(cidr string) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
		if len(ips) > 65536 {
			break
		}
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (d *Discovery) scanHost(ctx context.Context, host string, ports []int) {
	result := HostResult{Host: host, IP: host}

	portSem := make(chan struct{}, d.config.Threads)
	var portWg sync.WaitGroup
	var portMu sync.Mutex

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
		}

		portWg.Add(1)
		go func(p int) {
			defer portWg.Done()
			portSem <- struct{}{}
			defer func() { <-portSem }()

			open, banner := d.connectAndGrab(host, p)
			if !open {
				return
			}

			service := PortServiceMap[p]
			if service == "" {
				service = "unknown"
			}

			pr := PortResult{Port: p, Service: service, Banner: banner}
			portMu.Lock()
			result.OpenPorts = append(result.OpenPorts, pr)
			portMu.Unlock()

			d.addServiceResult(ServiceResult{
				Host: host, Port: p, Service: service,
				Banner: banner, Protocol: "tcp",
			})
		}(port)
	}
	portWg.Wait()

	if len(result.OpenPorts) > 0 {
		d.addHostResult(result)
	}
}

func (d *Discovery) connectAndGrab(host string, port int) (bool, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, d.config.Timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	switch port {
	case 80, 8080, 8081, 8000, 8888, 9000, 9090:
		conn.Write([]byte("GET / HTTP/1.0\r\nHost: " + host + "\r\n\r\n"))
	case 443, 8443:
		return true, ""
	default:
		// For non-HTTP ports, try to read a banner passively
	}

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n > 0 {
		banner := strings.TrimSpace(string(buf[:n]))
		if len(banner) > 256 {
			banner = banner[:256]
		}
		return true, banner
	}

	return true, ""
}

// ScanSingleHost scans a single host — exported for testing and external use
func (d *Discovery) ScanSingleHost(host string, ports []int) HostResult {
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	result := HostResult{Host: host, IP: host}

	portSem := make(chan struct{}, d.config.Threads)
	var portWg sync.WaitGroup
	var portMu sync.Mutex

	for _, port := range ports {
		portWg.Add(1)
		go func(p int) {
			defer portWg.Done()
			portSem <- struct{}{}
			defer func() { <-portSem }()

			open, banner := d.connectAndGrab(host, p)
			if !open {
				return
			}
			service := PortServiceMap[p]
			if service == "" {
				service = "unknown"
			}
			portMu.Lock()
			result.OpenPorts = append(result.OpenPorts, PortResult{Port: p, Service: service, Banner: banner})
			portMu.Unlock()
		}(port)
	}
	portWg.Wait()
	return result
}

// FormatHost returns a human-readable string for a HostResult
func FormatHost(h HostResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s (%s)\n", h.Host, h.IP))
	for _, p := range h.OpenPorts {
		sb.WriteString(fmt.Sprintf("  %d/%s — %s", p.Port, "tcp", p.Service))
		if p.Banner != "" {
			banner := p.Banner
			if idx := strings.Index(banner, "\n"); idx > 0 {
				banner = banner[:idx]
			}
			sb.WriteString(fmt.Sprintf(" — %s", banner))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
