package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/attackchain"
)

const banner = `
    _   __           ____                            _   _       _       
   / | / /___ ______/ __/___  _________ ___  ___    / \ | | ___ | |_ ___ 
  /  |/ / __  / ___/ /_/ __ \/ ___/ __  __  _ \   /  \| |/ _ \| __/ _ \
 / /|  / /_/ (__  ) __/ /_/ / /  / /_/ / /_/ // /  / /\  | | (_) | ||  __/
/_/ |_|\__,_/____/_/  \____/_/   \__,_/\___/(_)  /_/  \_|\___/ \__\___|
                                                                
              Multi-Stage Attack Chain Analyzer`

func main() {
	var (
		inputFile  string
		jsonOutput bool
		textOutput bool
		maxDepth   int
		minConf    float64
		topN       int
		quiet      bool
	)

	flag.StringVar(&inputFile, "input", "", "nuclei JSONL output file (use - for stdin)")
	flag.StringVar(&inputFile, "i", "", "shorthand for -input")
	flag.BoolVar(&jsonOutput, "json", false, "output JSON report")
	flag.BoolVar(&textOutput, "text", true, "output text report (default)")
	flag.IntVar(&maxDepth, "max-depth", 5, "maximum chain depth")
	flag.Float64Var(&minConf, "min-confidence", 0.5, "minimum edge confidence (0.0-1.0)")
	flag.IntVar(&topN, "top", 0, "show only top N chains (0 = all)")
	flag.BoolVar(&quiet, "silent", false, "suppress banner")

	flag.Parse()

	if !quiet && !jsonOutput {
		fmt.Println(banner)
	}

	if inputFile == "" {
		fmt.Fprintln(os.Stderr, "Error: -input is required (nuclei JSONL file or - for stdin)")
		flag.Usage()
		os.Exit(1)
	}

	// Read findings
	var reader io.Reader
	if inputFile == "-" {
		reader = os.Stdin
	} else {
		f, err := os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		reader = f
	}

	// Configure analyzer
	config := attackchain.AnalyzerConfig{
		MaxDepth:      maxDepth,
		MinConfidence: minConf,
	}
	analyzer := attackchain.NewAnalyzer(config)

	count, err := analyzer.LoadFindings(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing findings: %v\n", err)
		os.Exit(1)
	}

	if count == 0 {
		if jsonOutput {
			fmt.Println(`{"summary":{"total_chains":0},"chains":[]}`)
		} else {
			fmt.Println("No findings to analyze.")
		}
		return
	}

	// Find chains
	chains := analyzer.Analyze()

	if topN > 0 && len(chains) > topN {
		chains = attackchain.TopChains(chains, topN)
	}

	// Generate report
	report := analyzer.GenerateReport(chains)

	if jsonOutput {
		printJSON(report)
	} else if textOutput {
		printText(report, count)
	}
}

func printJSON(report attackchain.Report) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func printText(report attackchain.Report, findingCount int) {
	s := report.Summary

	fmt.Printf("Findings loaded:     %d\n", findingCount)
	fmt.Printf("Graph:               %d nodes, %d edges\n", report.GraphStats.Nodes, report.GraphStats.Edges)
	fmt.Printf("Attack chains found: %d\n", s.TotalChains)
	fmt.Printf("  Critical: %d  High: %d  Medium: %d  Low: %d\n",
		s.CriticalChains, s.HighChains, s.MediumChains, s.LowChains)
	fmt.Printf("  Avg chain length:  %.1f steps\n", s.AvgChainLength)
	fmt.Printf("  Max chain length:  %d steps\n", s.MaxChainLength)
	fmt.Printf("  Avg risk score:    %.1f/100\n", s.AvgRiskScore)
	fmt.Printf("  Max risk score:    %.1f/100\n", s.MaxRiskScore)
	fmt.Println()

	if s.TotalChains == 0 {
		fmt.Println("No attack chains detected. Findings are isolated.")
		return
	}

	// Group by severity
	grouped := groupChainsBySeverity(report.Chains)

	for _, sev := range []string{attackchain.SeverityCritical, attackchain.SeverityHigh, attackchain.SeverityMedium, attackchain.SeverityLow} {
		chains := grouped[sev]
		if len(chains) == 0 {
			continue
		}
		sevLabel := strings.ToUpper(sev[:1]) + sev[1:]
		fmt.Printf("=== %s Chains (%d) ===\n", sevLabel, len(chains))
		for i, c := range chains {
			fmt.Printf("\n[%s-%d] Risk: %.1f/100 | Confidence: %.0f%% | Severity: %s\n",
				sevLabel, i+1, c.RiskScore, c.Confidence*100, c.FinalSeverity)
			fmt.Printf("  Chain: %s\n", c.Description)
			fmt.Printf("  Steps:\n")
			for j, step := range c.Steps {
				fmt.Printf("    %d. %s [%s] → %s [%s]\n",
					j+1,
					step.FromFinding.TemplateID,
					step.FromFinding.VulnType,
					step.ToFinding.TemplateID,
					step.ToFinding.VulnType,
				)
				fmt.Printf("       Relation: %s (confidence: %.0f%%)\n", step.Relation, step.Confidence*100)
				fmt.Printf("       Reason:   %s\n", step.Reason)
				if step.FromFinding.Host != "" {
					fmt.Printf("       Host:     %s\n", step.FromFinding.Host)
				}
			}
		}
		fmt.Println()
	}

	// Findings summary
	fmt.Println("=== Findings Summary ===")
	for _, f := range report.Findings {
		fmt.Printf("  [%s] %s (%s) — %s\n",
			strings.ToUpper(f.Severity[:1])+f.Severity[1:],
			f.TemplateID,
			f.VulnType,
			f.Host,
		)
	}
}

func groupChainsBySeverity(chains []attackchain.ChainReport) map[string][]attackchain.ChainReport {
	result := map[string][]attackchain.ChainReport{
		attackchain.SeverityCritical: {},
		attackchain.SeverityHigh:     {},
		attackchain.SeverityMedium:   {},
		attackchain.SeverityLow:      {},
		attackchain.SeverityInfo:     {},
	}
	for _, c := range chains {
		sev := strings.ToLower(c.FinalSeverity)
		if _, ok := result[sev]; ok {
			result[sev] = append(result[sev], c)
		} else {
			result[attackchain.SeverityInfo] = append(result[attackchain.SeverityInfo], c)
		}
	}
	return result
}
