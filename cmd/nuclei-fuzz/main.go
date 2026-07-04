package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzzorch"
)

const banner = `
    _   __           ____            _     ___              
   / | / /___ ______/ __/___  ____  (_)___/ (_)___  ___ 
  /  |/ / __  / ___/ /_/ __ \/ __ \/ / __  / / __ \/ _ \
 / /|  / /_/ (__  ) __/ /_/ / / / / / /_/ / / / / /  __/
/_/ |_/\__,_/____/_/  \____/_/ /_/_/\__,_/_/_/ /_/\___/   
                                                          
              Automated Fuzzing Orchestrator`

func main() {
	var (
		targets      string
		tech         string
		vulnTypes    string
		outputDir    string
		nucleiBin    string
		timeout      time.Duration
		genOnly      bool
		listPayloads bool
		jsonOut      bool
	)

	flag.StringVar(&targets, "u", "", "Target URLs (comma-separated)")
	flag.StringVar(&tech, "tech", "", "Technologies (comma-separated, e.g. PHP,MySQL)")
	flag.StringVar(&vulnTypes, "vuln-types", "", "Override vuln types to fuzz (comma-separated: sqli,xss,ssrf,lfi,rce,redirect)")
	flag.StringVar(&outputDir, "output-dir", "", "Output directory for templates and results")
	flag.StringVar(&nucleiBin, "bin", "nuclei-dev", "Nuclei binary path")
	flag.DurationVar(&timeout, "timeout", 10*time.Minute, "Scan timeout")
	flag.BoolVar(&genOnly, "gen-only", false, "Only generate templates, don't run nuclei")
	flag.BoolVar(&listPayloads, "list-payloads", false, "List available payload sets and exit")
	flag.BoolVar(&jsonOut, "json", false, "Output JSON format")
	flag.Parse()

	if !jsonOut {
		fmt.Println(banner)
	}

	// List payloads mode
	if listPayloads {
		lib := fuzzorch.NewPayloadLibrary()
		sets := lib.AllPayloadSets()
		if jsonOut {
			b, _ := json.Marshal(sets)
			fmt.Println(string(b))
		} else {
			fmt.Printf("Available payload sets (%d):\n\n", len(sets))
			for _, ps := range sets {
				fmt.Printf("  %s (%s): %d payloads\n", ps.VulnType, ps.Name, len(ps.Payloads))
			}
		}
		return
	}

	if targets == "" {
		fmt.Fprintln(os.Stderr, "Error: -u required (or use -list-payloads)")
		os.Exit(1)
	}

	// Parse targets
	var fuzzTargets []fuzzorch.FuzzTarget
	for _, rawURL := range strings.Split(targets, ",") {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL != "" {
			fuzzTargets = append(fuzzTargets, fuzzorch.TargetFromURL(rawURL))
		}
	}

	// Parse technologies
	var technologies []string
	if tech != "" {
		for _, t := range strings.Split(tech, ",") {
			technologies = append(technologies, strings.TrimSpace(t))
		}
	}

	// Create orchestrator
	orch := fuzzorch.NewOrchestrator(nucleiBin, outputDir, timeout)

	// Determine vuln types
	var selectedTypes []string
	if vulnTypes != "" {
		for _, vt := range strings.Split(vulnTypes, ",") {
			selectedTypes = append(selectedTypes, strings.TrimSpace(vt))
		}
	} else {
		selectedTypes = orch.GetLibrary().SelectPayloadTypes(technologies)
	}

	if !jsonOut {
		fmt.Printf("Targets:     %d\n", len(fuzzTargets))
		fmt.Printf("Technologies: %v\n", technologies)
		fmt.Printf("Vuln types:  %v\n", selectedTypes)
	}

	// Generate templates
	paths, err := orch.GetGenerator().GenerateTemplates(fuzzTargets, selectedTypes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating templates: %v\n", err)
		os.Exit(1)
	}

	if !jsonOut {
		fmt.Printf("Templates:   %d generated\n", len(paths))
		for _, p := range paths {
			fmt.Printf("  - %s\n", p)
		}
	}

	if genOnly {
		if jsonOut {
			result := map[string]interface{}{
				"templates": paths,
				"count":     len(paths),
			}
			b, _ := json.Marshal(result)
			fmt.Println(string(b))
		}
		return
	}

	// Run fuzzing
	result, err := orch.Run(fuzzTargets, technologies)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if jsonOut {
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
	} else {
		fmt.Printf("\n[+] Fuzzing complete\n")
		fmt.Printf("    %s\n", result.Stats.String())
		if len(result.Findings) > 0 {
			fmt.Printf("\n  Findings:\n")
			for _, f := range result.Findings {
				fmt.Printf("    [%s] %s — %s (param: %s)\n", strings.ToUpper(f.VulnType), f.Target, f.TemplateID, f.Param)
				if f.Evidence != "" {
					fmt.Printf("      Evidence: %s\n", f.Evidence)
				}
			}
		}
		if result.OutputFile != "" {
			fmt.Printf("\n  Raw output: %s\n", result.OutputFile)
		}
	}
}
