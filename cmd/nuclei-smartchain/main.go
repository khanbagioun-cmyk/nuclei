package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/intelligence"
	"github.com/projectdiscovery/nuclei/v3/pkg/templatelearn"
)

func main() {
	targetsFile := flag.String("l", "", "targets file (one per line)")
	targetURL := flag.String("u", "", "single target URL")
	inputMode := flag.String("im", "list", "input file mode (list, burp, jsonl, yaml, openapi, swagger)")
	nucleiBin := flag.String("bin", "", "nuclei binary path (default: auto-detect)")
	templatesDir := flag.String("t", "", "templates directory")
	tags := flag.String("tags", "", "tags for phase 2 (comma-separated, overrides smart-chain)")
	severity := flag.String("sv", "", "severity filter (comma-separated)")
	priorityTags := flag.String("priority-tags", "kev,vkev,exploit,exposure,cve", "priority tags always included in phase 2 (comma-separated, set empty to disable)")
	profileOnly := flag.Bool("profile-only", false, "only run phase 1 (profiling), print profile and exit")
	profileFile := flag.String("profile-file", "", "load pre-built profile from JSON file (skip phase 1)")
	outputJSON := flag.String("oJ", "", "output JSON file for results")
	concurrency := flag.Int("c", 25, "concurrency")
	timeout := flag.Duration("timeout", 10*time.Minute, "total timeout")
	profileTimeout := flag.Duration("profile-timeout", 60*time.Second, "phase 1 timeout")
	runWorkflows := flag.Bool("workflows", true, "run native nuclei workflows after phase 2 (conditional template chaining)")
	runDast := flag.Bool("dast", true, "run DAST community templates (phase 2.5)")
	runVersionCheck := flag.Bool("version-check", true, "run version-based CVE check (phase 2.6)")
	followRedirects := flag.Bool("fr", true, "follow HTTP redirects (enables scope:final-only template feature; default true)")
	qualityFilter := flag.Bool("qf", true, "enable quality filter (suppress FP-prone templates using learning store; default true)")
	qualityMinScore := flag.Float64("qf-min-score", 0.3, "minimum quality score for reporting (0.0-1.0, lower=more permissive)")
	qualityStore := flag.String("qf-store", "", "path to learning store JSON (default: ~/.config/nuclei-dev/learn.json)")
	profileName := flag.String("profile", "", "use a built-in scan profile (e.g., critical-cve-sweep, quick-kev-sweep, full-exposure-audit, wordpress-deep, tech-discovery-only, dast-injection)")
	listProfiles := flag.Bool("list-profiles", false, "list available built-in scan profiles")
	help := flag.Bool("h", false, "show help")
	flag.Parse()

	// List profiles and exit
	if *listProfiles {
		fmt.Println("Available scan profiles:")
		for _, p := range intelligence.BuiltInProfiles() {
			fmt.Printf("  %-25s %s\n", p.Name, p.Description)
			if len(p.Tags) > 0 {
				fmt.Printf("  %-25s tags: %s\n", "", p.Tags)
			}
			if len(p.Severity) > 0 {
				fmt.Printf("  %-25s severity: %s\n", "", p.Severity)
			}
			fmt.Println()
		}
		os.Exit(0)
	}

	// Apply built-in profile overrides
	if *profileName != "" {
		p, err := intelligence.GetProfileByName(*profileName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[smartchain] using profile: %s — %s\n", p.Name, p.Description)
		if len(p.Tags) > 0 {
			*tags = p.Tags[0] // tags is comma-separated string
		}
		if len(p.Severity) > 0 {
			*severity = strings.Join(p.Severity, ",")
		}
		*runDast = !p.SkipDAST
		*runWorkflows = !p.SkipWorkflows
		if p.ProfileOnly {
			*profileOnly = true
		}
	}

	if *help || (len(os.Args) == 1) {
		fmt.Println(`nuclei-smartchain — two-phase conditional template chaining

Phase 1: Run tech-detection templates → build TechProfile per host
Phase 2: Filter vulnerability templates by detected tech → run only relevant ones
Phase 2.5: Run DAST community templates (fuzzing/injection)
Phase 3: Run native nuclei workflows for product-specific chaining (optional)

Usage:
  nuclei-smartchain [options]

Options:
  -u <url>             Single target URL
  -l <file>            Targets file (one per line)
  -im <mode>           Input file mode: list, burp, jsonl, yaml, openapi, swagger (default: list)
  -bin <path>          Nuclei binary path (default: auto-detect)
  -t <dir>             Templates directory
  -tags <tags>         Override: run these tags in phase 2 (skip smart filtering)
  -sv <severity>       Severity filter (e.g., critical,high,medium)
  -priority-tags <tags> Priority tags always included in phase 2 (default: kev,vkev,exploit,exposure,cve)
  -profile-only        Only run phase 1, print profiles and exit
  -profile-file <path> Load pre-built profile JSON (skip phase 1)
  -oJ <file>           Output JSON results file
  -c <n>               Concurrency (default 25)
  -timeout <dur>       Total timeout (default 10m)
  -profile-timeout <dur> Phase 1 timeout (default 60s)
  -workflows           Run native nuclei workflows (default: true)
  -dast                Run DAST community templates (default: true)
  -profile <name>      Use a built-in scan profile (e.g., critical-cve-sweep, quick-kev-sweep)
  -list-profiles       List available scan profiles

Examples:
  nuclei-smartchain -u http://example.com
  nuclei-smartchain -l targets.txt -sv critical,high
  nuclei-smartchain -u http://example.com -profile-only
  nuclei-smartchain -l targets.txt -profile-file profiles.json
  nuclei-smartchain -u http://example.com -profile quick-kev-sweep
  nuclei-smartchain -l burp-export.xml -im burp -profile full-exposure-audit
  nuclei-smartchain -l openapi-spec.json -im openapi
  nuclei-smartchain -list-profiles`)
		os.Exit(0)
	}

	bin := *nucleiBin
	if bin == "" {
		bin = detectNuclei()
	}
	if bin == "" {
		fmt.Fprintln(os.Stderr, "[ERR] nuclei binary not found. Use -bin to specify.")
		os.Exit(1)
	}

	templatesPath := *templatesDir
	if templatesPath == "" {
		home, _ := os.UserHomeDir()
		templatesPath = filepath.Join(home, ".local", "nuclei-templates-dev")
	}

	targets := collectTargets(*targetsFile, *targetURL)
	usesMultiFormat := *inputMode != "list" && *targetsFile != ""
	if usesMultiFormat {
		// For burp/openapi/swagger/jsonl/yaml, nuclei parses the file directly
		// We can't expand targets to -u flags, so pass file + mode to nuclei
		fmt.Printf("[smartchain] input mode: %s, file: %s\n", *inputMode, *targetsFile)
	}
	if len(targets) == 0 && !usesMultiFormat {
		fmt.Fprintln(os.Stderr, "[ERR] no targets. Use -u or -l")
		os.Exit(1)
	}
	if usesMultiFormat && *targetURL == "" {
		// For phase 1 profiling with multi-format, we still need to extract URLs
		// nuclei will handle the format, but we pass -l with -im
		targets = []string{*targetsFile} // placeholder so len check passes
	}

	fmt.Printf("[smartchain] %d targets, nuclei=%s, templates=%s\n", len(targets), bin, templatesPath)

	chainer := intelligence.NewChainer()

	// === Phase 1: Profiling ===
	if *profileFile != "" {
		fmt.Println("[smartchain] loading pre-built profiles...")
		if err := loadProfiles(chainer, *profileFile); err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] loading profiles: %s\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("[smartchain] phase 1: running tech-detection templates...")
		phase1Start := time.Now()

		ctx, cancel := context.WithTimeout(context.Background(), *profileTimeout)
		defer cancel()

		profileResultFile := filepath.Join(os.TempDir(), fmt.Sprintf("smartchain-profile-%d.jsonl", time.Now().UnixNano()))
		args := []string{
			"-jsonl", "-o", profileResultFile, "-nc",
			"-tags", "tech-detect,tech,fingerprint",
			"-c", fmt.Sprintf("%d", *concurrency),
		}
		args = maybeAddRedirectFlag(args, *followRedirects)
		args = append(args, buildTargetArgs(targets, *targetURL, *targetsFile, *inputMode)...)
		if _, err := os.Stat(templatesPath); err == nil {
			args = append(args, "-t", templatesPath)
		}

		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[smartchain] phase 1 warning: %s\n", err)
		}

		// Parse phase 1 results
		profileCount := parseProfileResults(chainer, profileResultFile)
		os.Remove(profileResultFile)

		chainer.SetPhase1Stats(time.Since(phase1Start), profileCount)
		fmt.Printf("[smartchain] phase 1 complete: %d profiles in %s\n", profileCount, time.Since(phase1Start))
	}

	if *profileOnly {
		printProfiles(chainer)
		return
	}

	// === Phase 2: Filtered scanning ===
	fmt.Println("[smartchain] phase 2: running filtered vulnerability scan...")

	// Collect trigger tags across all hosts
	allTriggerTags := make(map[string]bool)
	for _, profile := range chainer.GetAllProfiles() {
		snap := profile.Snapshot()
		fmt.Printf("  %s: techs=%v ports=%v\n", snap.Host, snap.Technologies, snap.OpenPorts)
		ce := intelligence.NewChainEngine(nil)
		for _, tag := range ce.GetTriggerTagsFromSnapshot(snap) {
			allTriggerTags[tag] = true
		}
	}

	// Merge priority tags (KEV, exploit, exposure, CVE) — always scan these
	if *priorityTags != "" {
		for _, pt := range strings.Split(*priorityTags, ",") {
			pt = strings.TrimSpace(pt)
			if pt != "" {
				allTriggerTags[pt] = true
			}
		}
	}

	var phase2Tags []string
	for tag := range allTriggerTags {
		phase2Tags = append(phase2Tags, tag)
	}

	if *tags != "" {
		phase2Tags = strings.Split(*tags, ",")
		for i := range phase2Tags {
			phase2Tags[i] = strings.TrimSpace(phase2Tags[i])
		}
	}

	if len(phase2Tags) == 0 {
		fmt.Println("[smartchain] no trigger tags detected — running default scan")
		phase2Tags = []string{"exposure", "misconfig"}
	}

	fmt.Printf("[smartchain] trigger tags (%d): %s\n", len(phase2Tags), strings.Join(phase2Tags, ", "))

	phase2Start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resultFile := *outputJSON
	if resultFile == "" {
		resultFile = filepath.Join(os.TempDir(), fmt.Sprintf("smartchain-results-%d.jsonl", time.Now().UnixNano()))
	}

	args := []string{
		"-jsonl", "-o", resultFile, "-nc",
		"-tags", strings.Join(phase2Tags, ","),
		"-c", fmt.Sprintf("%d", *concurrency),
	}
	args = maybeAddRedirectFlag(args, *followRedirects)
	if *severity != "" {
		args = append(args, "-severity", *severity)
	}
	args = append(args, buildTargetArgs(targets, *targetURL, *targetsFile, *inputMode)...)
	if _, err := os.Stat(templatesPath); err == nil {
		args = append(args, "-t", templatesPath)
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[smartchain] phase 2 error: %s\n", err)
	}

	phase2Count := countResults(resultFile)
	chainer.SetPhase2Stats(time.Since(phase2Start), phase2Count, 0)
	fmt.Printf("[smartchain] phase 2 complete: %d findings in %s\n", phase2Count, time.Since(phase2Start))

	// === Phase 2.5: DAST community templates ===
	dastCount := 0
	if *runDast {
		dastDir := filepath.Join(templatesPath, "dast")
		// Also check http/dast as fallback
		if _, err := os.Stat(dastDir); err != nil {
			dastDir = filepath.Join(templatesPath, "http", "dast")
		}
		if _, err := os.Stat(dastDir); err == nil {
			fmt.Println("[smartchain] phase 2.5: running DAST community templates...")
			dastStart := time.Now()

			dastResultFile := filepath.Join(os.TempDir(), fmt.Sprintf("smartchain-dast-results-%d.jsonl", time.Now().UnixNano()))

			dastArgs := []string{
				"-jsonl", "-o", dastResultFile, "-nc",
				"-c", fmt.Sprintf("%d", *concurrency),
				"-dast",
				"-t", dastDir,
			}
			dastArgs = maybeAddRedirectFlag(dastArgs, *followRedirects)
			dastArgs = append(dastArgs, buildTargetArgs(targets, *targetURL, *targetsFile, *inputMode)...)

			dastCtx, dastCancel := context.WithTimeout(context.Background(), *timeout)
			defer dastCancel()

			dastCmd := exec.CommandContext(dastCtx, bin, dastArgs...)
			dastCmd.Stderr = os.Stderr
			dastCmd.Stdout = os.Stdout
			if err := dastCmd.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "[smartchain] phase 2.5 warning: %s\n", err)
			}

			dastCount = countResults(dastResultFile)
			if dastCount > 0 {
				mergeResults(resultFile, dastResultFile)
			}
			os.Remove(dastResultFile)

			fmt.Printf("[smartchain] phase 2.5 complete: %d findings in %s\n", dastCount, time.Since(dastStart))
		} else {
			fmt.Println("[smartchain] phase 2.5: no DAST templates directory found, skipping")
		}
	}

	// === Phase 2.6: Version-based CVE check ===
	vcCount := 0
	if *runVersionCheck {
		fmt.Println("[smartchain] phase 2.6: running version-based CVE check...")
		vcStart := time.Now()

		vcResultFile := filepath.Join(os.TempDir(), fmt.Sprintf("smartchain-vc-results-%d.jsonl", time.Now().UnixNano()))
		vcCount = runVersionCheckPhase(bin, templatesPath, resultFile, vcResultFile, targets, *targetURL, *targetsFile, *inputMode)

		if vcCount > 0 {
			mergeResults(resultFile, vcResultFile)
		}
		os.Remove(vcResultFile)

		fmt.Printf("[smartchain] phase 2.6 complete: %d findings in %s\n", vcCount, time.Since(vcStart))
	}

	// === Phase 3: Native workflows ===
	wfCount := 0
	if *runWorkflows {
		workflowsDir := filepath.Join(templatesPath, "workflows")
		matchedWorkflows := matchWorkflows(chainer, workflowsDir)
		if len(matchedWorkflows) > 0 {
			fmt.Printf("[smartchain] phase 3: running %d native workflows...\n", len(matchedWorkflows))
			phase3Start := time.Now()

			wfResultFile := filepath.Join(os.TempDir(), fmt.Sprintf("smartchain-wf-results-%d.jsonl", time.Now().UnixNano()))

			wfArgs := []string{
				"-jsonl", "-o", wfResultFile, "-nc",
				"-c", fmt.Sprintf("%d", *concurrency),
			}
			wfArgs = maybeAddRedirectFlag(wfArgs, *followRedirects)
			for _, wf := range matchedWorkflows {
				wfArgs = append(wfArgs, "-w", wf)
			}
			wfArgs = append(wfArgs, buildTargetArgs(targets, *targetURL, *targetsFile, *inputMode)...)

			wfCtx, wfCancel := context.WithTimeout(context.Background(), *timeout)
			defer wfCancel()

			wfCmd := exec.CommandContext(wfCtx, bin, wfArgs...)
			wfCmd.Stderr = os.Stderr
			if err := wfCmd.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "[smartchain] phase 3 warning: %s\n", err)
			}

			wfCount = countResults(wfResultFile)

			// Merge workflow results into main result file
			if wfCount > 0 {
				mergeResults(resultFile, wfResultFile)
			}
			os.Remove(wfResultFile)

			fmt.Printf("[smartchain] phase 3 complete: %d findings in %s\n", wfCount, time.Since(phase3Start))
		} else {
			fmt.Println("[smartchain] phase 3: no matching workflows for detected tech")
		}
	}

	totalFindings := phase2Count + dastCount + vcCount + wfCount
	fmt.Println()
	fmt.Printf("[smartchain] total findings: %d (phase2=%d + dast=%d + versioncheck=%d + workflows=%d)\n", totalFindings, phase2Count, dastCount, vcCount, wfCount)

	// === Phase 4: Quality filter (suppress FP-prone templates) ===
	if *qualityFilter {
		storePath := *qualityStore
		if storePath == "" {
			storePath = filepath.Join(os.Getenv("HOME"), ".config", "nuclei-dev", "learn.json")
		}
		if _, err := os.Stat(storePath); err == nil {
			fmt.Println("[smartchain] phase 4: applying quality filter...")
			qfStart := time.Now()

			store := templatelearn.NewFeedbackStore(storePath, 3)
			if err := store.Load(); err != nil {
				fmt.Fprintf(os.Stderr, "[smartchain] phase 4 warning: could not load store: %s\n", err)
			} else {
				qf := templatelearn.NewQualityFilter(store, *qualityMinScore)
				filtered, suppressed := filterResults(resultFile, qf)
				fmt.Printf("[smartchain] phase 4 complete: %d/%d findings retained (%d suppressed) in %s\n",
					filtered, filtered+suppressed, suppressed, time.Since(qfStart))
				totalFindings = filtered
			}
		} else {
			fmt.Println("[smartchain] phase 4: no learning store found, skipping quality filter")
		}
	}

	fmt.Print(chainer.Summary())

	if *outputJSON == "" {
		// Print results to stdout
		printResults(resultFile)
		os.Remove(resultFile)
	} else {
		fmt.Printf("[smartchain] results written to %s\n", *outputJSON)
	}
}

// runVersionCheckPhase parses existing results for version findings,
// then checks detected versions against known-safe versions from distro
// security trackers to identify potentially vulnerable software.
func runVersionCheckPhase(bin, templatesPath, resultFile, outputFile string, targets []string, targetURL, targetsFile, inputMode string) int {
	// Read existing results and extract version findings
	resultData, err := os.ReadFile(resultFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[smartchain] phase 2.6: could not read results: %s\n", err)
		return 0
	}

	type versionFinding struct {
		Host       string   `json:"host"`
		TemplateID string   `json:"template-id"`
		Extracted  []string `json:"extracted-results"`
		Info       struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		} `json:"info"`
	}

	var findings []versionFinding
	for _, line := range strings.Split(string(resultData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var f versionFinding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			continue
		}
		if len(f.Extracted) > 0 {
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		fmt.Println("[smartchain] phase 2.6: no version findings to check")
		return 0
	}

	fmt.Printf("[smartchain] phase 2.6: checking %d version findings against distro security trackers...\n", len(findings))

	// Use the intelligence package's VersionChecker
	vc := intelligence.NewVersionChecker()

	out, err := os.Create(outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[smartchain] phase 2.6: could not create output: %s\n", err)
		return 0
	}
	defer out.Close()

	count := 0
	for _, f := range findings {
		version := strings.Join(f.Extracted, "")
		if version == "" {
			continue
		}

		// Extract product name from tags
		product := ""
		for _, tag := range f.Info.Tags {
			if tag != "tech" && tag != "eol" && tag != "discovery" && tag != "version" && tag != "fingerprint" {
				product = tag
				break
			}
		}
		if product == "" {
			parts := strings.Split(f.TemplateID, "-")
			if len(parts) > 0 {
				product = parts[0]
			}
		}

		// Check against all distros
		distros := []string{"debian", "ubuntu", "rhel"}
		for _, distro := range distros {
			result := vc.CheckBelowSafeVersion(version, distro, product)
			if result.Vulnerable {
				finding := map[string]interface{}{
					"template-id": "versioncheck-" + product,
					"template":    "versioncheck/" + product,
					"info": map[string]interface{}{
						"name":     fmt.Sprintf("%s %s may be vulnerable (below %s safe version on %s)", product, version, result.Reason, distro),
						"severity": "medium",
						"tags":     []string{"versioncheck", product, distro},
					},
					"type":              "http",
					"host":              f.Host,
					"matched-at":        f.Host,
					"extracted-results": f.Extracted,
					"versioncheck": map[string]interface{}{
						"product":   product,
						"version":   version,
						"distro":    distro,
						"reason":    result.Reason,
						"confidence": result.Confidence,
					},
					"timestamp": time.Now().Format(time.RFC3339),
				}
				jsonBytes, _ := json.Marshal(finding)
				out.Write(jsonBytes)
				out.Write([]byte("\n"))
				count++
				break // one finding per product is enough
			}
		}
	}

	return count
}

// matchWorkflows finds workflow YAML files that match detected technologies
func matchWorkflows(chainer *intelligence.Chainer, workflowsDir string) []string {
	if _, err := os.Stat(workflowsDir); err != nil {
		return nil
	}

	// Collect all detected tech tags (lowercased)
	techSet := make(map[string]bool)
	for _, profile := range chainer.GetAllProfiles() {
		snap := profile.Snapshot()
		for _, tech := range snap.Technologies {
			techSet[strings.ToLower(tech)] = true
		}
	}

	if len(techSet) == 0 {
		return nil
	}

	var matched []string
	entries, err := os.ReadDir(workflowsDir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		wfPath := filepath.Join(workflowsDir, entry.Name())
		wfTechs := parseWorkflowTechs(wfPath)

		// Match if any workflow tech overlaps with detected tech
		for _, wfTech := range wfTechs {
			if techSet[strings.ToLower(wfTech)] {
				matched = append(matched, wfPath)
				break
			}
		}
	}

	return matched
}

// parseWorkflowTechs extracts product/tech names from a workflow YAML file
// by looking at the workflow ID, name, and template paths
func parseWorkflowTechs(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var techs []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Extract from id: field (e.g., "id: wordpress-workflow" → "wordpress")
		if strings.HasPrefix(trimmed, "id:") {
			id := strings.TrimSpace(strings.TrimPrefix(trimmed, "id:"))
			id = strings.TrimSuffix(id, "-workflow")
			// Split on dashes to get individual tech words
			for _, part := range strings.Split(id, "-") {
				if part != "" && len(part) > 1 {
					techs = append(techs, part)
				}
			}
		}

		// Extract from template: paths (e.g., "http/technologies/wordpress-detect.yaml" → "wordpress")
		if strings.HasPrefix(trimmed, "- template:") {
			tmplPath := strings.TrimSpace(strings.TrimPrefix(trimmed, "- template:"))
			tmplPath = strings.Trim(tmplPath, "\"'")
			parts := strings.Split(tmplPath, "/")
			for _, p := range parts {
				p = strings.TrimSuffix(p, ".yaml")
				p = strings.TrimSuffix(p, "-detect")
				if p != "" && p != "http" && p != "technologies" && len(p) > 1 {
					techs = append(techs, p)
				}
			}
		}

		// Extract from tags: in subtemplates
		if strings.HasPrefix(trimmed, "- tags:") {
			tagStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "- tags:"))
			for _, tag := range strings.Split(tagStr, ",") {
				tag = strings.TrimSpace(tag)
				if tag != "" {
					techs = append(techs, tag)
				}
			}
		}
	}

	return techs
}

// mergeResults appends workflow results into the main result file
func mergeResults(mainFile, wfFile string) {
	wfData, err := os.ReadFile(wfFile)
	if err != nil {
		return
	}
	mainFileHandle, err := os.OpenFile(mainFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer mainFileHandle.Close()

	mainFileHandle.Write(wfData)
}

func detectNuclei() string {
	candidates := []string{
		os.ExpandEnv("$HOME/nuclei-fork/bin/nuclei-dev"),
		os.ExpandEnv("$HOME/.local/bin/nuclei-dev"),
		"/opt/homebrew/bin/nuclei",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if path, err := exec.LookPath("nuclei-dev"); err == nil {
		return path
	}
	if path, err := exec.LookPath("nuclei"); err == nil {
		return path
	}
	return ""
}

// buildTargetArgs builds nuclei target arguments based on input mode
func buildTargetArgs(targets []string, targetURL string, targetsFile string, inputMode string) []string {
	if inputMode != "list" && targetsFile != "" {
		// Multi-format mode: pass file directly with -im flag
		return []string{"-l", targetsFile, "-im", inputMode}
	}
	// List mode: expand targets as -u flags
	var args []string
	for _, t := range targets {
		args = append(args, "-u", t)
	}
	return args
}

// maybeAddRedirectFlag appends -fr to args if followRedirects is true.
// This enables the scope:final-only template feature for redirect-chain matching.
func maybeAddRedirectFlag(args []string, followRedirects bool) []string {
	if followRedirects {
		return append(args, "-fr")
	}
	return args
}

func collectTargets(file, url string) []string {
	var targets []string
	if url != "" {
		targets = append(targets, url)
	}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] opening targets file: %s\n", err)
			return targets
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}
	return targets
}

func parseProfileResults(chainer *intelligence.Chainer, resultFile string) int {
	f, err := os.Open(resultFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		host, _ := result["host"].(string)
		if host == "" {
			continue
		}

		matcherName, _ := result["matcher-name"].(string)
		templateID, _ := result["template-id"].(string)
		port, _ := result["port"].(string)

		var tags []string
		if info, ok := result["info"].(map[string]interface{}); ok {
			if tagStr, ok := info["tags"].(string); ok {
				tags = strings.Split(tagStr, ",")
			} else if tagArr, ok := info["tags"].([]interface{}); ok {
				for _, t := range tagArr {
					if s, ok := t.(string); ok {
						tags = append(tags, s)
					}
				}
			}
		}

		var extracted []string
		if arr, ok := result["extracted-results"].([]interface{}); ok {
			for _, e := range arr {
				if s, ok := e.(string); ok {
					extracted = append(extracted, s)
				}
			}
		}

		var metadata map[string]interface{}
		if info, ok := result["info"].(map[string]interface{}); ok {
			if md, ok := info["metadata"].(map[string]interface{}); ok {
				metadata = md
			}
		}

		chainer.RecordPhase1Result(host, tags, matcherName, extracted, templateID, port, metadata)
		count++
	}
	return count
}

func loadProfiles(chainer *intelligence.Chainer, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var profiles []struct {
		Host         string   `json:"host"`
		Technologies []string `json:"technologies"`
		Services     []struct {
			Name string `json:"name"`
			Port int    `json:"port"`
		} `json:"services"`
		OpenPorts []int `json:"open_ports"`
		CMS       string `json:"cms"`
	}
	if err := json.Unmarshal(data, &profiles); err != nil {
		return err
	}
	for _, p := range profiles {
		for _, tech := range p.Technologies {
			chainer.RecordPhase1Result(p.Host, []string{tech}, "", nil, "", "", nil)
		}
		for _, svc := range p.Services {
			chainer.RecordPhase1Result(p.Host, nil, svc.Name, nil, "", fmt.Sprintf("%d", svc.Port), nil)
		}
		for _, port := range p.OpenPorts {
			chainer.RecordPhase1Result(p.Host, nil, "", nil, "", fmt.Sprintf("%d", port), nil)
		}
		if p.CMS != "" {
			chainer.RecordPhase1Result(p.Host, []string{p.CMS}, "", nil, "", "", nil)
		}
	}
	return nil
}

func printProfiles(chainer *intelligence.Chainer) {
	profiles := chainer.GetAllProfiles()
	fmt.Println("\n=== Tech Profiles ===")
	for _, p := range profiles {
		snap := p.Snapshot()
		fmt.Printf("\n%s:\n", snap.Host)
		fmt.Printf("  Technologies: %v\n", snap.Technologies)
		if snap.CMS != "" {
			fmt.Printf("  CMS: %s\n", snap.CMS)
		}
		if snap.WebServer != "" {
			fmt.Printf("  Web Server: %s\n", snap.WebServer)
		}
		if snap.Language != "" {
			fmt.Printf("  Language: %s\n", snap.Language)
		}
		if snap.Framework != "" {
			fmt.Printf("  Framework: %s\n", snap.Framework)
		}
		if len(snap.OpenPorts) > 0 {
			fmt.Printf("  Open Ports: %v\n", snap.OpenPorts)
		}
		if len(snap.Services) > 0 {
			fmt.Printf("  Services: ")
			for _, s := range snap.Services {
				fmt.Printf("%s/%d ", s.Name, s.Port)
			}
			fmt.Println()
		}
		ce := intelligence.NewChainEngine(nil)
		tags := ce.GetTriggerTagsFromSnapshot(snap)
		fmt.Printf("  Trigger Tags: %v\n", tags)
	}
}

func countResults(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if scanner.Text() != "" {
			count++
		}
	}
	return count
}

func printResults(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var result map[string]interface{}
		if json.Unmarshal([]byte(line), &result) == nil {
			templateID, _ := result["template-id"].(string)
			host, _ := result["host"].(string)
			severity, _ := result["info"].(map[string]interface{})["severity"].(string)
			matched, _ := result["matched-at"].(string)
			fmt.Printf("  [%s] %s %s — %s\n", severity, templateID, host, matched)
		}
	}
}

// filterResults reads a JSONL results file, applies the quality filter,
// and rewrites the file with only retained findings.
// Returns (retained, suppressed) counts.
func filterResults(path string, qf *templatelearn.QualityFilter) (int, int) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	f.Close()

	retained := 0
	suppressed := 0
	var kept []string

	for _, line := range lines {
		if line == "" {
			continue
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			kept = append(kept, line)
			retained++
			continue
		}

		templateID, _ := result["template-id"].(string)
		host, _ := result["host"].(string)
		matcherName, _ := result["matcher-name"].(string)

		// Infer vuln type from info.tags
		vulnType := ""
		if info, ok := result["info"].(map[string]interface{}); ok {
			if tags, ok := info["tags"].([]interface{}); ok && len(tags) > 0 {
				if t, ok := tags[0].(string); ok {
					vulnType = t
				}
			}
		}

		shouldReport, reason := qf.ShouldReport(templateID, host, matcherName, vulnType)
		if shouldReport {
			kept = append(kept, line)
			retained++
		} else {
			suppressed++
			fmt.Printf("[smartchain]   suppressed: %s (%s)\n", templateID, reason)
		}
	}

	// Rewrite the file with only retained findings
	out, err := os.Create(path)
	if err != nil {
		return retained, suppressed
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	for _, line := range kept {
		w.WriteString(line + "\n")
	}
	w.Flush()

	return retained, suppressed
}
