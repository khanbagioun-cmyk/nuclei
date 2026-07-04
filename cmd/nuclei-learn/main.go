package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/templatelearn"
)

const banner = `
     _   _                     _               _   
  __| | | | ___   _ _ __ _ __ (_)_ __   __ _| |  
 / _' | | |/ / | | | '__| '_ \| | '_ \ / _' | |  
| (_| | |   <| |_| | |  | | | | | | | | (_| | |  
 \__,_|_|_|\_\\__, |_|  |_| |_|_|_| |_|\__,_|_|  
                 _|
                 v1.0.0 - Template Learning Engine`

func main() {
	var (
		storePath    string
		mode         string
		templateID   string
		host         string
		matcherName  string
		vulnType     string
		feedbackType string
		reason       string
		note         string
		threshold    int
		ruleID       string
		jsonOut      bool
	)

	flag.StringVar(&storePath, "store", "", "Path to feedback store JSON file")
	flag.StringVar(&mode, "mode", "", "Mode: mark, suppress, unsuppress, filter, report, fn-check")
	flag.StringVar(&templateID, "template", "", "Template ID (for mark/suppress)")
	flag.StringVar(&host, "host", "", "Target host (for mark/suppress)")
	flag.StringVar(&matcherName, "matcher", "", "Matcher name (for mark/suppress)")
	flag.StringVar(&vulnType, "vuln-type", "", "Vulnerability type (for mark/suppress)")
	flag.StringVar(&feedbackType, "type", "fp", "Feedback type: fp, tp, fn (for mark mode)")
	flag.StringVar(&reason, "reason", "", "Reason for feedback/suppression")
	flag.StringVar(&note, "note", "", "User note (for mark mode)")
	flag.IntVar(&threshold, "threshold", 3, "Auto-suppression threshold (FP marks before auto-suppress)")
	flag.StringVar(&ruleID, "rule-id", "", "Suppression rule ID (for unsuppress mode)")
	flag.BoolVar(&jsonOut, "json", false, "JSON output (for report mode)")
	flag.Parse()

	if !jsonOut && mode != "filter" {
		fmt.Println(banner)
	}

	if storePath == "" {
		storePath = os.ExpandEnv("$HOME/.config/nuclei-dev/feedback-store.json")
	}

	store := templatelearn.NewFeedbackStore(storePath, threshold)
	if err := store.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading store: %v\n", err)
		os.Exit(1)
	}

	switch mode {
	case "mark":
		if templateID == "" {
			fmt.Fprintln(os.Stderr, "Error: --template is required for mark mode")
			os.Exit(1)
		}
		var ftype templatelearn.FeedbackType
		switch strings.ToLower(feedbackType) {
		case "fp", "false_positive":
			ftype = templatelearn.FeedbackFalsePositive
		case "tp", "true_positive":
			ftype = templatelearn.FeedbackTruePositive
		case "fn", "false_negative":
			ftype = templatelearn.FeedbackFalseNegative
		default:
			fmt.Fprintf(os.Stderr, "Error: invalid feedback type %q (use fp, tp, or fn)\n", feedbackType)
			os.Exit(1)
		}
		fb := store.MarkFeedback(templateID, host, matcherName, vulnType, ftype, reason, note)
		if err := store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving store: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Marked feedback: %s\n", fb.ID)
		fmt.Printf("  Template: %s\n", fb.TemplateID)
		fmt.Printf("  Host: %s\n", fb.Host)
		fmt.Printf("  Type: %s\n", fb.Type)
		fmt.Printf("  Count: %d\n", fb.Count)
		fmt.Printf("  Auto-suppressed: %v\n", fb.AutoSuppressed)

	case "suppress":
		if templateID == "" && vulnType == "" {
			fmt.Fprintln(os.Stderr, "Error: --template or --vuln-type required for suppress mode")
			os.Exit(1)
		}
		rule := &templatelearn.SuppressionRule{
			TemplateID:  templateID,
			Host:        host,
			MatcherName: matcherName,
			VulnType:    vulnType,
			Reason:      reason,
		}
		store.AddSuppressionRule(rule)
		if err := store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving store: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Added suppression rule: %s\n", rule.ID)
		fmt.Printf("  Template: %s\n", templateID)
		fmt.Printf("  Host: %s\n", host)
		fmt.Printf("  Matcher: %s\n", matcherName)
		fmt.Printf("  VulnType: %s\n", vulnType)
		fmt.Printf("  Reason: %s\n", reason)

	case "unsuppress":
		if ruleID == "" {
			fmt.Fprintln(os.Stderr, "Error: --rule-id required for unsuppress mode")
			os.Exit(1)
		}
		if !store.RemoveSuppression(ruleID) {
			fmt.Fprintf(os.Stderr, "Error: rule %s not found\n", ruleID)
			os.Exit(1)
		}
		if err := store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving store: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Removed suppression rule: %s\n", ruleID)

	case "filter":
		// Read JSONL from stdin, filter, write to stdout
		total, suppressed, err := templatelearn.FilterJSONL(store, os.Stdin, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error filtering: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Filtered: %d total, %d suppressed, %d passed\n", total, suppressed, total-suppressed)

	case "report":
		report := store.GenerateReport()
		if jsonOut {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(report); err != nil {
				fmt.Fprintf(os.Stderr, "Error encoding report: %v\n", err)
				os.Exit(1)
			}
		} else {
			printReport(report)
		}

	case "fn-check":
		// Read JSONL from stdin, check for false negatives
		findings, err := readFindings(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading findings: %v\n", err)
			os.Exit(1)
		}
		scannedHosts := extractHosts(findings)
		detector := templatelearn.NewFNDetector(store)
		results := detector.CheckFalseNegatives(scannedHosts, findings)

		if jsonOut {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			encoder.Encode(results)
		} else {
			if len(results) == 0 {
				fmt.Println("No false negatives detected.")
			} else {
				fmt.Printf("Potential false negatives (%d):\n", len(results))
				for _, r := range results {
					fmt.Printf("  [%s] %s — %s (confidence: %.0f%%)\n",
						r.VulnType, r.Host, r.Reason, r.Confidence*100)
				}
			}
		}

	default:
		fmt.Fprintln(os.Stderr, "Error: --mode is required (mark, suppress, unsuppress, filter, report, fn-check)")
		flag.Usage()
		os.Exit(1)
	}
}

func printReport(report templatelearn.LearningReport) {
	fmt.Println("=== Template Learning Report ===")
	fmt.Printf("Generated: %s\n\n", report.GeneratedAt.Format(time.RFC3339))

	fmt.Println("--- Stats ---")
	fmt.Printf("Total feedback:     %d\n", report.Stats.TotalFeedback)
	fmt.Printf("False positives:    %d\n", report.Stats.FalsePositives)
	fmt.Printf("True positives:     %d\n", report.Stats.TruePositives)
	fmt.Printf("False negatives:    %d\n", report.Stats.FalseNegatives)
	fmt.Printf("Auto-suppressed:    %d\n", report.Stats.AutoSuppressed)
	fmt.Printf("Manual suppressions: %d\n", report.Stats.ManualSuppressions)
	fmt.Printf("Unique templates:   %d\n", report.Stats.UniqueTemplates)
	fmt.Printf("Unique hosts:       %d\n\n", report.Stats.UniqueHosts)

	if len(report.TopFPTemplates) > 0 {
		fmt.Println("--- Top FP Templates ---")
		for i, t := range report.TopFPTemplates {
			if i >= 10 {
				break
			}
			fmt.Printf("  %s — FP: %d, TP: %d, rate: %.1f%%\n",
				t.TemplateID, t.FPCount, t.TPCount, t.FPRate*100)
		}
	}

	if len(report.SuppressionRules) > 0 {
		fmt.Println("\n--- Suppression Rules ---")
		for _, r := range report.SuppressionRules {
			label := "manual"
			if r.AutoGenerated {
				label = "auto"
			}
			fmt.Printf("  [%s] %s — template=%s host=%s vuln=%s\n",
				label, r.ID, r.TemplateID, r.Host, r.VulnType)
			if r.Reason != "" {
				fmt.Printf("    reason: %s\n", r.Reason)
			}
		}
	}
}

func readFindings(reader io.Reader) ([]*templatelearn.NucleiJSONLFinding, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024*10)

	var findings []*templatelearn.NucleiJSONLFinding
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var f templatelearn.NucleiJSONLFinding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			continue
		}
		findings = append(findings, &f)
	}
	return findings, scanner.Err()
}

func extractHosts(findings []*templatelearn.NucleiJSONLFinding) []string {
	seen := make(map[string]bool)
	var hosts []string
	for _, f := range findings {
		h := strings.ToLower(f.Host)
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, f.Host)
		}
	}
	return hosts
}
