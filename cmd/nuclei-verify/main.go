package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/verify"
)

const banner = `
    _   __           ____                            
   / | / /___ ______/ __/___  _________ ___  ___      
  /  |/ / __  / ___/ /_/ __ \/ ___/ __  __  _ \   
 / /|  / /_/ (__  ) __/ /_/ / /  / /_/ / /_/ // /   
/_/ |_/\__,_/____/_/  \____/_/   \__,_/\___/(_)    
                                                    
              Active Exploit Verifier`

func main() {
	var (
		host       string
		vulnType   string
		templateID string
		param      string
		path       string
		jsonlFile  string
		oastDomain string
		oastToken  string
		timeout    time.Duration
		safeMode   bool
		jsonOut    bool
	)

	flag.StringVar(&host, "host", "", "Target host URL (e.g., http://example.com)")
	flag.StringVar(&vulnType, "type", "", "Vulnerability type (xss, sqli, ssrf, rce, lfi, open-redirect, xxe)")
	flag.StringVar(&templateID, "template", "", "Template ID")
	flag.StringVar(&param, "param", "", "Vulnerable parameter name")
	flag.StringVar(&path, "path", "/", "Vulnerable path")
	flag.StringVar(&jsonlFile, "jsonl", "", "Nuclei JSONL output file to verify (batch mode)")
	flag.StringVar(&oastDomain, "oast-domain", "", "Interactsh OAST domain for SSRF/XXE verification")
	flag.StringVar(&oastToken, "oast-token", "", "Interactsh OAST auth token")
	flag.DurationVar(&timeout, "timeout", 15*time.Second, "HTTP timeout per request")
	flag.BoolVar(&safeMode, "safe", true, "Safe mode (non-destructive checks only)")
	flag.BoolVar(&jsonOut, "json", false, "Output JSON format")
	flag.Parse()

	if !jsonOut {
		fmt.Println(banner)
	}

	v := verify.NewVerifier(verify.VerifierConfig{
		OastDomain: oastDomain,
		OastToken:  oastToken,
		Timeout:    timeout,
		SafeMode:   safeMode,
	})

	if jsonlFile != "" {
		var data []byte
		var err error
		if jsonlFile == "-" || jsonlFile == "/dev/stdin" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(jsonlFile)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			os.Exit(1)
		}
		results := v.VerifyFromJSONL(data)
		fmt.Printf("Verified %d findings:\n\n", len(results))
		for _, r := range results {
			if jsonOut {
				b, _ := json.Marshal(r)
				fmt.Println(string(b))
			} else {
				printResult(r)
			}
		}
		verified := 0
		for _, r := range results {
			if r.Verified {
				verified++
			}
		}
		if !jsonOut {
			fmt.Printf("\nSummary: %d/%d verified (%.0f%%)\n", verified, len(results), pct(verified, len(results)))
		}
		return
	}

	if host == "" || vulnType == "" {
		fmt.Fprintln(os.Stderr, "Usage: nuclei-verify -host <url> -type <vuln-type> [-param <name>] [-path /]")
		fmt.Fprintln(os.Stderr, "       nuclei-verify -jsonl <nuclei-output.jsonl> [-json]")
		fmt.Fprintln(os.Stderr, "\nSupported types: xss, sqli, ssrf, rce, lfi/path-traversal, open-redirect, xxe")
		os.Exit(1)
	}

	if templateID == "" {
		templateID = "manual-verify"
	}

	extra := map[string]string{
		"template_id": templateID,
	}
	if param != "" {
		extra["param"] = param
	}
	if path != "" {
		extra["path"] = path
	}

	result := v.VerifyFinding(templateID, host, vulnType, extra)

	if jsonOut {
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
	} else {
		printResult(result)
	}

	if result.Verified {
		os.Exit(0)
	}
	os.Exit(1)
}

func printResult(r verify.VerificationResult) {
	status := "NOT VERIFIED"
	icon := "[!]"
	if r.Verified {
		status = "VERIFIED"
		icon = "[+]"
	}
	fmt.Printf("%s %s — %s/%s\n", icon, status, r.TemplateID, r.VulnType)
	fmt.Printf("    Host:       %s\n", r.Host)
	fmt.Printf("    Confidence: %.0f%%\n", r.Confidence*100)
	fmt.Printf("    Method:     %s\n", r.Method)
	fmt.Printf("    Evidence:   %s\n", r.Evidence)
	fmt.Printf("    Time:       %s\n", r.Timestamp.Format(time.RFC3339))
	fmt.Println()
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d) * 100
}
