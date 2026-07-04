// Example: Using the nuclei orchestrator for multi-stage scanning
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/lib/orchestrator"
)

func main() {
	targets := os.Args[1:]
	if len(targets) == 0 {
		targets = []string{"scanme.sh"}
	}

	config := orchestrator.DefaultConfig().
		SetTargets(targets...).
		SetStages(orchestrator.StageBannerGrab, orchestrator.StageVulnScan).
		SetRateLimit(50).
		SetConcurrency(10).
		SetTimeout(5 * time.Minute)

	config.TemplateFilters = nuclei.TemplateFilters{
		Severity: "low,medium,high,critical",
	}

	if err := config.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	orch := orchestrator.New(config)
	result, err := orch.Run(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
	}

	fmt.Println("\n" + result.Summary())
	fmt.Println("\n" + result.Profile())
}
