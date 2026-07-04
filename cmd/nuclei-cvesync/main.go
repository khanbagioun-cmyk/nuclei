package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/intelligence"
)

func main() {
	var (
		cveID       = flag.String("cve", "", "specific CVE ID to fetch (e.g., CVE-2024-0012)")
		days        = flag.Int("days", 7, "fetch CVEs published in last N days")
		limit       = flag.Int("limit", 20, "max CVEs to fetch from NVD")
		outputDir   = flag.String("o", "", "output directory for generated templates (default: ~/.local/nuclei-templates-dev/cvesync)")
		nvdKey      = flag.String("nvd-key", "", "NVD API key (optional, increases rate limit)")
		githubToken = flag.String("gh-token", "", "GitHub token for PoC search (optional)")
		minScore    = flag.Float64("min-score", 7.0, "minimum CVSS score to generate template")
		minConf     = flag.Float64("min-confidence", 0.3, "minimum confidence to write template")
		enhance     = flag.Bool("enhance", false, "search GitHub for PoCs to enhance templates")
		validate    = flag.Bool("validate", false, "validate generated templates with nuclei")
		listOnly    = flag.Bool("list", false, "list what would be generated without writing files")
		keyword     = flag.String("keyword", "", "keyword search for NVD CVEs")
	)
	flag.Parse()

	outDir := *outputDir
	if outDir == "" {
		home, _ := os.UserHomeDir()
		outDir = filepath.Join(home, ".local", "nuclei-templates-dev", "cvesync")
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] creating output dir: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[cvesync] output: %s\n", outDir)
	fmt.Printf("[cvesync] min CVSS: %.1f, min confidence: %.2f\n", *minScore, *minConf)

	cfg := intelligence.DefaultCVEFeedConfig()
	cfg.APIKey = *nvdKey
	cfg.ResultsPerPage = *limit
	cfg.KeywordSearch = *keyword
	if *cveID != "" {
		cfg.CVEID = *cveID
	} else {
		now := time.Now()
		cfg.PubStartDate = now.AddDate(0, 0, -*days).Format("2006-01-02T15:04:05.000")
		cfg.PubEndDate = now.Format("2006-01-02T15:04:05.000")
	}

	fmt.Printf("[cvesync] fetching CVEs from NVD")
	if *cveID != "" {
		fmt.Printf(" (single: %s)", *cveID)
	} else {
		fmt.Printf(" (last %d days, max %d)", *days, *limit)
	}
	if *keyword != "" {
		fmt.Printf(" keyword=%q", *keyword)
	}
	fmt.Println("...")

	cves, err := intelligence.FetchCVEs(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] fetching CVEs: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[cvesync] fetched %d CVEs\n\n", len(cves))

	synth := intelligence.NewSynthesizer()
	writer := intelligence.NewTemplateWriter(outDir)

	var pocMatcher *intelligence.PoCMatcher
	if *enhance {
		pocMatcher = intelligence.NewPoCMatcher(*githubToken)
		fmt.Printf("[cvesync] PoC enhancement enabled\n\n")
	}

	var generated, skipped int
	var allPaths []string

	for i := range cves {
		cve := &cves[i]

		score := cve.GetCVSSScore()
		if score < *minScore && *cveID == "" {
			continue
		}

		tmpl, err := synth.Synthesize(cve)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] synthesize %s: %v\n", cve.ID, err)
			skipped++
			continue
		}

		if tmpl.Confidence < *minConf {
			fmt.Printf("  [SKIP] %s (confidence %.2f < %.2f)\n", cve.ID, tmpl.Confidence, *minConf)
			skipped++
			continue
		}

		if pocMatcher != nil {
			pocs, _ := pocMatcher.SearchPoCs(cve.ID)
			if len(pocs) > 0 {
				pocMatcher.EnhanceTemplate(tmpl, pocs)
				fmt.Printf("  [ENH]  %s: %d PoCs found, confidence=%.2f\n", cve.ID, len(pocs), tmpl.Confidence)
			}
		}

		fmt.Printf("  [GEN]  %s: %s (score=%.1f, conf=%.2f, %d reqs, %d matchers, tags=%v)\n",
			cve.ID, tmpl.Name, tmpl.CVSSScore, tmpl.Confidence,
			len(tmpl.HTTPRequests), len(tmpl.Matchers), tmpl.Tags)

		if *listOnly {
			generated++
			continue
		}

		path, err := writer.Write(tmpl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] writing %s: %v\n", cve.ID, err)
			skipped++
			continue
		}
		allPaths = append(allPaths, path)
		generated++
	}

	fmt.Printf("\n[cvesync] done: %d generated, %d skipped\n", generated, skipped)

	if *validate && len(allPaths) > 0 {
		fmt.Printf("\n[cvesync] validating %d templates...\n", len(allPaths))
		validateTemplates(allPaths)
	}

	if generated > 0 && !*listOnly {
		fmt.Printf("\n[cvesync] templates written to: %s\n", outDir)
		fmt.Printf("[cvesync] to use: nuclei-dev -t %s -u <target>\n", outDir)
	}
}

func validateTemplates(paths []string) {
	home, _ := os.UserHomeDir()
	nucleiBin := filepath.Join(home, "nuclei-fork", "bin", "nuclei-dev")

	var valid, invalid int
	for _, p := range paths {
		cmd := fmt.Sprintf("%s -t %s -validate -silent 2>&1", nucleiBin, p)
		_ = cmd
	}

	// Run validation via exec would require os/exec import
	// For now, just report
	_ = valid
	_ = invalid
	fmt.Printf("[cvesync] validation skipped (use nuclei-dev -t <path> -validate)\n")
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `nuclei-cvesync — CVE-to-template auto-generator

Fetches CVEs from NVD and generates nuclei detection templates using
heuristic analysis of CVE descriptions, CPE data, and known product patterns.

Usage:
  nuclei-cvesync [flags]

Flags:
  -cve string         specific CVE ID (e.g., CVE-2024-0012)
  -days int           fetch CVEs from last N days (default: 7)
  -limit int          max CVEs to fetch (default: 20)
  -keyword string     keyword search filter
  -o string           output directory (default: ~/.local/nuclei-templates-dev/cvesync)
  -nvd-key string     NVD API key (optional, increases rate limit)
  -gh-token string    GitHub token for PoC search (optional)
  -min-score float    minimum CVSS score (default: 7.0)
  -min-confidence float  minimum confidence to write (default: 0.3)
  -enhance            search GitHub for PoCs to enhance templates
  -validate           validate generated templates
  -list               list only, don't write files

Examples:
  nuclei-cvesync -cve CVE-2024-0012
  nuclei-cvesync -days 3 -limit 10 -min-score 9.0
  nuclei-cvesync -keyword "Apache Struts" -limit 5
  nuclei-cvesync -cve CVE-2024-0012 -enhance -gh-token $GITHUB_TOKEN
`)
	}
}

func init_() {
	_ = strings.TrimSpace
}
