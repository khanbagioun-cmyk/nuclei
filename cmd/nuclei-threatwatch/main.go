package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/intelligence"
)

func main() {
	pollInterval := flag.Duration("interval", 15*time.Minute, "poll interval (e.g. 15m, 1h)")
	nvdKey := flag.String("nvd-key", "", "NVD API key (optional, increases rate limit)")
	vulncheckToken := flag.String("vulncheck-token", "", "VulnCheck API token for VulnCheck KEV feed (or set VULNCHECK_API_TOKEN env var)")
	outputDir := flag.String("o", "", "template output dir (default: ~/.local/nuclei-templates-dev/cvesync)")
	validateBin := flag.String("bin", "", "nuclei binary for validation (default: ~/nuclei-fork/bin/nuclei-dev)")
	minScore := flag.Float64("min-score", 7.0, "minimum CVSS score to process")
	minConf := flag.Float64("min-confidence", 0.3, "minimum confidence to write template")
	kevOnly := flag.Bool("kev-only", false, "only process CISA KEV entries (ransomware priority)")
	maxPerPoll := flag.Int("max-per-poll", 50, "max CVEs to process per poll cycle")
	once := flag.Bool("once", false, "run a single poll cycle and exit")
	stateFile := flag.String("state", "", "state file path (default: ~/.config/nuclei-dev/threatwatch-state.json)")
	verbose := flag.Bool("v", false, "verbose output")
	flag.Parse()

	cfg := intelligence.DefaultThreatWatchConfig()
	if *nvdKey != "" {
		cfg.NVDAPIKey = *nvdKey
	}
	if *vulncheckToken != "" {
		cfg.VulnCheckAPIToken = *vulncheckToken
	} else if envToken := os.Getenv("VULNCHECK_API_TOKEN"); envToken != "" {
		cfg.VulnCheckAPIToken = envToken
	}
	if *outputDir != "" {
		cfg.TemplateOutputDir = *outputDir
	}
	if *validateBin != "" {
		cfg.ValidateBinary = *validateBin
	}
	if *stateFile != "" {
		cfg.StateFile = *stateFile
	}
	cfg.PollInterval = *pollInterval
	cfg.MinCVSSScore = *minScore
	cfg.MinConfidence = *minConf
	cfg.EnableKEVOnly = *kevOnly
	cfg.MaxPerPoll = *maxPerPoll

	tw, err := intelligence.NewThreatWatch(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[threatwatch] error: %v\n", err)
		os.Exit(1)
	}

	if *once {
		fmt.Println("[threatwatch] running single poll cycle...")
		events, err := tw.PollOnce()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[threatwatch] poll error: %v\n", err)
		}

		generated := 0
		skipped := 0
		errors := 0
		for _, event := range events {
			if event.Error != "" {
				if event.TemplatePath == "" {
					skipped++
					if *verbose {
						fmt.Printf("  [SKIP] %s (%s): %s\n", event.CVEID, event.Source, event.Error)
					}
				} else {
					errors++
					fmt.Printf("  [ERR]  %s (%s): %s\n", event.CVEID, event.Source, event.Error)
				}
			} else {
				generated++
				tags := ""
				if event.IsKEV {
					tags += " [KEV]"
				}
				if event.IsVulnCheckKEV {
					tags += " [VKEV]"
				}
				fmt.Printf("  [GEN]%s %s (%s) score=%.1f conf=%.2f -> %s\n",
					tags, event.CVEID, event.Source, event.CVSSScore, event.Confidence, event.TemplatePath)
			}
		}

		stats := tw.GetStats()
		fmt.Println()
		fmt.Printf("[threatwatch] cycle complete: %d generated, %d skipped, %d errors\n",
			generated, skipped, errors)
		fmt.Printf("[threatwatch] total: %d generated, %d skipped, %d KEV, %d VKEV, %d processed\n",
			stats["generated_count"], stats["skipped_count"],
			stats["kev_count"], stats["vulncheck_kev_count"], stats["processed_count"])
		return
	}

	// Daemon mode
	fmt.Printf("[threatwatch] starting daemon (poll every %s)\n", cfg.PollInterval)
	fmt.Printf("[threatwatch] output: %s\n", cfg.TemplateOutputDir)
	fmt.Printf("[threatwatch] state: %s\n", cfg.StateFile)
	if cfg.NVDAPIKey != "" {
		fmt.Printf("[threatwatch] NVD API key: provided\n")
	} else {
		fmt.Printf("[threatwatch] NVD API key: none (5 req/30min limit)\n")
	}
	if cfg.VulnCheckAPIToken != "" {
		fmt.Printf("[threatwatch] VulnCheck KEV: enabled (API)\n")
	} else {
		fmt.Printf("[threatwatch] VulnCheck KEV: API disabled (set -vulncheck-token or VULNCHECK_API_TOKEN env)\n")
	}

	// Report local VKEV index status
	stats := tw.GetStats()
	if localCount, ok := stats["local_vkev_count"]; ok {
		fmt.Printf("[threatwatch] Local VKEV index: %d CVEs from community templates\n", localCount)
	}
	if *kevOnly {
		fmt.Printf("[threatwatch] KEV-only mode: ransomware priority\n")
	}
	fmt.Println()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go tw.Run()

	for {
		select {
		case event := <-tw.Events():
			if event.Error != "" && event.TemplatePath == "" {
				if *verbose {
					fmt.Printf("[%s] [SKIP] %s: %s\n",
						event.Timestamp.Format("15:04:05"), event.CVEID, event.Error)
				}
			} else if event.Error != "" {
				fmt.Printf("[%s] [ERR]  %s: %s\n",
					event.Timestamp.Format("15:04:05"), event.CVEID, event.Error)
			} else {
				tags := ""
				if event.IsKEV {
					tags += " [KEV]"
				}
				if event.IsVulnCheckKEV {
					tags += " [VKEV]"
				}
				fmt.Printf("[%s] [GEN]%s %s (%s) score=%.1f conf=%.2f -> %s\n",
					event.Timestamp.Format("15:04:05"),
					tags, event.CVEID, event.Source, event.CVSSScore, event.Confidence,
					event.TemplatePath)
			}
		case <-sigChan:
			fmt.Println("\n[threatwatch] shutting down...")
			tw.Stop()
			stats := tw.GetStats()
			fmt.Printf("[threatwatch] final stats: %d generated, %d skipped, %d KEV, %d VKEV\n",
				stats["generated_count"], stats["skipped_count"],
				stats["kev_count"], stats["vulncheck_kev_count"])
			return
		}
	}
}
