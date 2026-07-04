package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/intelligence"
)

func main() {
	var (
		version  string
		cveID    string
		from     string
		to       string
		distro   string
		product  string
		header   string
		bodyRe   string
		jsonOut  bool
	)

	flag.StringVar(&version, "v", "", "detected version to check")
	flag.StringVar(&cveID, "cve", "", "CVE ID (for reporting)")
	flag.StringVar(&from, "from", "", "affected range start (inclusive)")
	flag.StringVar(&to, "to", "", "affected range end (exclusive)")
	flag.StringVar(&distro, "distro", "", "OS distro for backport awareness (debian, ubuntu, rhel, fedora, amazon, suse)")
	flag.StringVar(&product, "product", "", "product name for distro fix lookup (e.g., apache, nginx, openssl)")
	flag.StringVar(&header, "header", "", "HTTP header value to extract version from (e.g., 'Apache/2.4.41')")
	flag.StringVar(&bodyRe, "body-regex", "", "regex to extract version from response body")
	flag.BoolVar(&jsonOut, "json", false, "output as JSON")
	flag.Parse()

	if version == "" && header == "" && bodyRe == "" {
		fmt.Fprintln(os.Stderr, "Usage: nuclei-versioncheck -v <version> -from <start> -to <end> [-cve <id>] [-distro <d>] [-product <p>]")
		fmt.Fprintln(os.Stderr, "       nuclei-versioncheck -header 'Apache/2.4.41' -from 2.4.0 -to 2.4.57 -product apache -distro debian")
		fmt.Fprintln(os.Stderr, "       nuclei-versioncheck -body-regex 'WordPress\\s+([0-9.]+)' -from 6.0 -to 6.4.2")
		os.Exit(1)
	}

	// Extract version if needed
	if version == "" && header != "" {
		version = intelligence.ExtractVersionFromHeader(header)
		if version == "" {
			fmt.Fprintln(os.Stderr, "Error: could not extract version from header")
			os.Exit(1)
		}
	}
	if version == "" && bodyRe != "" {
		// Read body from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			fmt.Fprintln(os.Stderr, "Error: -body-regex requires piping response body via stdin")
			os.Exit(1)
		}
		buf := make([]byte, 65536)
		n, _ := os.Stdin.Read(buf)
		version = intelligence.ExtractVersionFromBody(string(buf[:n]), bodyRe)
		if version == "" {
			fmt.Fprintln(os.Stderr, "Error: could not extract version from body")
			os.Exit(1)
		}
	}

	if from == "" && to == "" {
		fmt.Fprintln(os.Stderr, "Error: must specify -from and/or -to")
		os.Exit(1)
	}

	ranges := []intelligence.VersionRange{
		{From: from, To: to},
	}

	vc := intelligence.NewVersionChecker()

	var result intelligence.VersionCheckResult
	if distro != "" || product != "" {
		result = vc.CheckVersionWithDistro(version, distro, product, ranges, cveID)
	} else {
		result = vc.CheckVersion(version, ranges, cveID)
	}

	if jsonOut {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		status := "NOT VULNERABLE"
		if result.Vulnerable {
			status = "VULNERABLE"
		}
		fmt.Printf("Version: %s\n", result.Detected)
		fmt.Printf("Status:  %s\n", status)
		fmt.Printf("Confidence: %.0f%%\n", result.Confidence*100)
		if cveID != "" {
			fmt.Printf("CVE:     %s\n", result.CVEID)
		}
		if result.Reason != "" {
			fmt.Printf("Reason:  %s\n", result.Reason)
		}
	}

	if result.Vulnerable {
		os.Exit(2)
	}
}

// Ensure VersionRange is exported from the intelligence package
var _ = strings.TrimSpace
