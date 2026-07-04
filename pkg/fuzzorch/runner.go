package fuzzorch

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RunResult contains the results of a fuzzing run
type RunResult struct {
	Stats        *FuzzStats     `json:"stats"`
	Findings     []FuzzResult   `json:"findings"`
	TemplateDir  string         `json:"template_dir"`
	OutputFile   string         `json:"output_file"`
}

// Run generates fuzzing templates for the targets and executes them with nuclei.
// It selects payload types based on the given technologies.
func (o *Orchestrator) Run(targets []FuzzTarget, technologies []string) (*RunResult, error) {
	startTime := time.Now()
	stats := NewFuzzStats()
	stats.TotalTargets = len(targets)

	// Count total params
	for _, t := range targets {
		stats.TotalParams += len(t.Params)
	}

	// Select payload types based on tech profile
	vulnTypes := o.library.SelectPayloadTypes(technologies)

	// Generate templates
	templatePaths, err := o.generator.GenerateTemplates(targets, vulnTypes)
	if err != nil {
		return nil, fmt.Errorf("template generation failed: %w", err)
	}

	if len(templatePaths) == 0 {
		return &RunResult{
			Stats:       stats,
			Findings:    nil,
			TemplateDir: o.generator.outputDir,
		}, nil
	}

	// Run nuclei with the generated templates
	outputFile := filepath.Join(o.generator.outputDir, fmt.Sprintf("fuzz-results-%d.jsonl", time.Now().UnixNano()))
	findings, totalRequests, err := o.runNuclei(templatePaths, targets, outputFile)
	if err != nil {
		return nil, fmt.Errorf("nuclei execution failed: %w", err)
	}

	stats.TotalRequests = totalRequests
	stats.Duration = time.Since(startTime).String()

	// Convert findings to FuzzResult
	for _, f := range findings {
		vulnType := extractVulnType(f.TemplateID)
		stats.AddFinding(vulnType)
	}

	return &RunResult{
		Stats:       stats,
		Findings:    findings,
		TemplateDir: o.generator.outputDir,
		OutputFile:  outputFile,
	}, nil
}

// runNuclei executes nuclei with the generated templates and parses the output
func (o *Orchestrator) runNuclei(templatePaths []string, targets []FuzzTarget, outputFile string) ([]FuzzResult, int, error) {
	// Write target URLs to a file
	targetFile := filepath.Join(o.generator.outputDir, "targets.txt")
	var targetURLs []string
	for _, t := range targets {
		targetURLs = append(targetURLs, t.URL)
	}
	if err := os.WriteFile(targetFile, []byte(strings.Join(targetURLs, "\n")), 0644); err != nil {
		return nil, 0, err
	}

	// Build nuclei command
	args := []string{
		"-jsonl",
		"-silent",
		"-nc",
		"-dast",
		"-o", outputFile,
		"-l", targetFile,
		"-tags", "fuzzorch",
	}

	// Add template paths
	for _, tp := range templatePaths {
		args = append(args, "-t", tp)
	}

	// Execute
	cmd := exec.Command(o.nucleiBin, args...)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// nuclei may return non-zero on findings
		if _, statErr := os.Stat(outputFile); statErr != nil {
			return nil, 0, fmt.Errorf("nuclei failed: %w", err)
		}
	}

	// Parse output
	data, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, 0, nil // no output file = no findings
	}

	findings := parseFuzzFindings(data)
	// Estimate requests: templates * targets * payloads (rough)
	totalRequests := len(templatePaths) * len(targetURLs)
	return findings, totalRequests, nil
}

// NucleiFinding represents a nuclei JSONL finding
type NucleiFinding struct {
	TemplateID string `json:"template-id"`
	Host       string `json:"host"`
	URL        string `json:"url"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Matcher    string `json:"matcher-name"`
	MatchedAt  string `json:"matched-at"`
}

// parseFuzzFindings parses nuclei JSONL output into FuzzResult structs
func parseFuzzFindings(data []byte) []FuzzResult {
	var results []FuzzResult
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var nf NucleiFinding
		if err := json.Unmarshal([]byte(line), &nf); err != nil {
			continue
		}
		if nf.TemplateID == "" {
			continue
		}
		vulnType := extractVulnType(nf.TemplateID)
		result := FuzzResult{
			Target:     nf.URL,
			VulnType:   vulnType,
			Payload:    "", // not directly available from nuclei output
			Confidence: 0.8,
			Evidence:   nf.Matcher,
			TemplateID: nf.TemplateID,
			Timestamp:  time.Now().UTC(),
		}
		results = append(results, result)
	}
	return results
}

// extractVulnType extracts the vuln type from a fuzz template ID
// Template ID format: fuzz-{vulntype}-{param}-{url}
func extractVulnType(templateID string) string {
	if !strings.HasPrefix(templateID, "fuzz-") {
		return "unknown"
	}
	rest := strings.TrimPrefix(templateID, "fuzz-")
	parts := strings.SplitN(rest, "-", 2)
	if len(parts) < 1 {
		return "unknown"
	}
	return parts[0]
}

// TargetFromURL creates a FuzzTarget from a URL with common query parameters
func TargetFromURL(rawURL string) FuzzTarget {
	target := FuzzTarget{
		URL:    rawURL,
		Method: "GET",
	}

	// Parse URL to extract query params
	if idx := strings.Index(rawURL, "?"); idx >= 0 {
		queryStr := rawURL[idx+1:]
		for _, param := range strings.Split(queryStr, "&") {
			kv := strings.SplitN(param, "=", 2)
			name := kv[0]
			value := ""
			if len(kv) > 1 {
				value = kv[1]
			}
			if name != "" {
				target.Params = append(target.Params, Param{
					Name:     name,
					Value:    value,
					Position: "query",
					Type:     "string",
				})
			}
		}
	}

	// If no params found, add a default "q" param for fuzzing
	if len(target.Params) == 0 {
		target.Params = append(target.Params, Param{
			Name:     "q",
			Value:    "test",
			Position: "query",
			Type:     "string",
		})
	}

	return target
}

// TargetsFromForms creates FuzzTargets from discovered HTML forms
func TargetsFromForms(baseURL string, forms []FormInfo) []FuzzTarget {
	var targets []FuzzTarget
	for _, form := range forms {
		target := FuzzTarget{
			URL:    form.Action,
			Method: form.Method,
		}
		if target.Method == "" {
			target.Method = "GET"
		}
		if target.URL == "" {
			target.URL = baseURL
		}
		for _, input := range form.Inputs {
			if input.Name != "" {
				target.Params = append(target.Params, Param{
					Name:     input.Name,
					Type:     input.Type,
					Position: "body",
					Value:    "test",
				})
			}
		}
		if len(target.Params) > 0 {
			targets = append(targets, target)
		}
	}
	return targets
}

// FormInfo represents a discovered HTML form (compatible with discovery.FormInfo)
type FormInfo struct {
	Action string      `json:"action"`
	Method string      `json:"method"`
	Inputs []FormField `json:"inputs"`
}

// FormField represents a form input field
type FormField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}
