package intelligence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TemplateWriter writes SynthesizedTemplates to disk as nuclei YAML files
type TemplateWriter struct {
	OutputDir string
}

// NewTemplateWriter creates a writer
func NewTemplateWriter(outputDir string) *TemplateWriter {
	return &TemplateWriter{OutputDir: outputDir}
}

// Write generates and writes a YAML template file
func (w *TemplateWriter) Write(tmpl *SynthesizedTemplate) (string, error) {
	yaml := w.RenderYAML(tmpl)

	year := tmpl.CVEID[4:8]
	yearDir := filepath.Join(w.OutputDir, "http", "cves", year)
	if err := os.MkdirAll(yearDir, 0755); err != nil {
		return "", fmt.Errorf("creating directory: %w", err)
	}

	filename := fmt.Sprintf("%s.yaml", tmpl.CVEID)
	path := filepath.Join(yearDir, filename)

	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		return "", fmt.Errorf("writing file: %w", err)
	}

	return path, nil
}

// RenderYAML generates the YAML content for a template
func (w *TemplateWriter) RenderYAML(tmpl *SynthesizedTemplate) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("id: %s\n\n", tmpl.CVEID))
	b.WriteString("info:\n")
	b.WriteString(fmt.Sprintf("  name: %s\n", escapeYAML(tmpl.Name)))
	b.WriteString(fmt.Sprintf("  author: %s\n", tmpl.Author))
	b.WriteString(fmt.Sprintf("  severity: %s\n", tmpl.Severity))
	if tmpl.Description != "" {
		b.WriteString("  description: |\n")
		for _, line := range strings.Split(tmpl.Description, "\n") {
			b.WriteString(fmt.Sprintf("    %s\n", escapeYAML(line)))
		}
	}
	if tmpl.Remediation != "" {
		b.WriteString("  remediation: |\n")
		b.WriteString(fmt.Sprintf("    %s\n", escapeYAML(tmpl.Remediation)))
	}
	if len(tmpl.References) > 0 {
		b.WriteString("  reference:\n")
		for _, ref := range tmpl.References {
			b.WriteString(fmt.Sprintf("    - %s\n", ref))
		}
	}
	b.WriteString("  classification:\n")
	if tmpl.CVSSMetrics != "" {
		b.WriteString(fmt.Sprintf("    cvss-metrics: %s\n", tmpl.CVSSMetrics))
	}
	if tmpl.CVSSScore > 0 {
		b.WriteString(fmt.Sprintf("    cvss-score: %.1f\n", tmpl.CVSSScore))
	}
	b.WriteString(fmt.Sprintf("    cve-id: %s\n", tmpl.CVEID))
	if tmpl.CWE != "" {
		b.WriteString(fmt.Sprintf("    cwe-id: %s\n", tmpl.CWE))
	}
	if tmpl.Vendor != "" {
		vendor := strings.ReplaceAll(strings.ToLower(tmpl.Vendor), " ", "_")
		product := strings.ReplaceAll(strings.ToLower(tmpl.Product), " ", "_")
		b.WriteString(fmt.Sprintf("    cpe: cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*\n", vendor, product))
	}
	b.WriteString("  metadata:\n")
	b.WriteString("    verified: false\n")
	b.WriteString("    max-request: 1\n")
	if tmpl.Vendor != "" {
		b.WriteString(fmt.Sprintf("    vendor: %s\n", strings.ToLower(tmpl.Vendor)))
	}
	if tmpl.Product != "" {
		b.WriteString(fmt.Sprintf("    product: %s\n", strings.ToLower(tmpl.Product)))
	}
	b.WriteString(fmt.Sprintf("    generated: true\n"))
	b.WriteString(fmt.Sprintf("    confidence: %.2f\n", tmpl.Confidence))
	b.WriteString(fmt.Sprintf("    method: %s\n", tmpl.GenerationMethod))
	if len(tmpl.Tags) > 0 {
		b.WriteString(fmt.Sprintf("  tags: %s\n", strings.Join(tmpl.Tags, ",")))
	}
	b.WriteString("\n")

	if len(tmpl.HTTPRequests) > 0 {
		w.renderHTTP(&b, tmpl)
	}
	if len(tmpl.DNSRequests) > 0 {
		w.renderDNS(&b, tmpl)
	}

	return b.String()
}

func (w *TemplateWriter) renderHTTP(b *strings.Builder, tmpl *SynthesizedTemplate) {
	b.WriteString("http:\n")
	for _, req := range tmpl.HTTPRequests {
		b.WriteString("  - raw:\n")
		method := req.Method
		if method == "" {
			method = "GET"
		}
		path := req.Path
		if path == "" {
			path = "/"
		}
		b.WriteString("      - |\n")
		b.WriteString(fmt.Sprintf("        %s %s HTTP/1.1\n", method, path))
		b.WriteString("        Host: {{Hostname}}\n")
		for k, v := range req.Headers {
			b.WriteString(fmt.Sprintf("        %s: %s\n", k, v))
		}
		if req.Body != "" {
			b.WriteString(fmt.Sprintf("        \n%s\n", req.Body))
		}
		b.WriteString("\n")

		// Matchers
		if len(tmpl.Matchers) > 0 {
			if len(tmpl.Matchers) > 1 {
				b.WriteString("    matchers-condition: and\n")
			}
			b.WriteString("    matchers:\n")
			for _, m := range tmpl.Matchers {
				w.renderMatcher(b, m, "      ")
			}
		}

		// Extractors
		if len(tmpl.Extractors) > 0 {
			b.WriteString("    extractors:\n")
			for _, e := range tmpl.Extractors {
				w.renderExtractor(b, e, "      ")
			}
		}
	}
}

func (w *TemplateWriter) renderDNS(b *strings.Builder, tmpl *SynthesizedTemplate) {
	b.WriteString("dns:\n")
	for _, req := range tmpl.DNSRequests {
		b.WriteString("  - name: {{dn}}\n")
		b.WriteString(fmt.Sprintf("    type: %s\n", req.Type))
	}
	if len(tmpl.Matchers) > 0 {
		if len(tmpl.Matchers) > 1 {
			b.WriteString("    matchers-condition: and\n")
		}
		b.WriteString("    matchers:\n")
		for _, m := range tmpl.Matchers {
			w.renderMatcher(b, m, "      ")
		}
	}
}

func (w *TemplateWriter) renderMatcher(b *strings.Builder, m MatcherSpec, prefix string) {
	b.WriteString(fmt.Sprintf("%s- type: %s\n", prefix, m.Type))
	subPrefix := prefix + "  "
	if m.Part != "" {
		b.WriteString(fmt.Sprintf("%spart: %s\n", subPrefix, m.Part))
	}
	switch m.Type {
	case "word":
		b.WriteString(fmt.Sprintf("%swords:\n", subPrefix))
		for _, w := range m.Words {
			b.WriteString(fmt.Sprintf("%s  - \"%s\"\n", subPrefix, w))
		}
	case "regex":
		b.WriteString(fmt.Sprintf("%sregex:\n", subPrefix))
		for _, r := range m.Regex {
			b.WriteString(fmt.Sprintf("%s  - '%s'\n", subPrefix, r))
		}
	case "dsl":
		b.WriteString(fmt.Sprintf("%sdsl:\n", subPrefix))
		for _, d := range m.DSL {
			b.WriteString(fmt.Sprintf("%s  - %s\n", subPrefix, d))
		}
	case "status":
		b.WriteString(fmt.Sprintf("%sstatus:\n", subPrefix))
		for _, s := range m.Status {
			b.WriteString(fmt.Sprintf("%s  - %d\n", subPrefix, s))
		}
	}
	if m.Condition != "" {
		b.WriteString(fmt.Sprintf("%scondition: %s\n", subPrefix, m.Condition))
	}
	if m.Negative {
		b.WriteString(fmt.Sprintf("%snegative: true\n", subPrefix))
	}
}

func (w *TemplateWriter) renderExtractor(b *strings.Builder, e ExtractorSpec, prefix string) {
	b.WriteString(fmt.Sprintf("%s- type: %s\n", prefix, e.Type))
	subPrefix := prefix + "  "
	if e.Part != "" {
		b.WriteString(fmt.Sprintf("%spart: %s\n", subPrefix, e.Part))
	}
	switch e.Type {
	case "regex":
		b.WriteString(fmt.Sprintf("%sregex:\n", subPrefix))
		for _, r := range e.Regex {
			b.WriteString(fmt.Sprintf("%s  - '%s'\n", subPrefix, r))
		}
	case "word":
		b.WriteString(fmt.Sprintf("%swords:\n", subPrefix))
		for _, w := range e.Words {
			b.WriteString(fmt.Sprintf("%s  - \"%s\"\n", subPrefix, w))
		}
	case "json":
		b.WriteString(fmt.Sprintf("%sjson:\n", subPrefix))
		for _, j := range e.JSON {
			b.WriteString(fmt.Sprintf("%s  - '%s'\n", subPrefix, j))
		}
	case "xpath":
		b.WriteString(fmt.Sprintf("%sxpath:\n", subPrefix))
		for _, x := range e.XPath {
			b.WriteString(fmt.Sprintf("%s  - '%s'\n", subPrefix, x))
		}
	}
	if e.Group > 0 {
		b.WriteString(fmt.Sprintf("%sgroup: %d\n", subPrefix, e.Group))
	}
	if e.Internal {
		b.WriteString(fmt.Sprintf("%sinternal: true\n", subPrefix))
	}
}

func escapeYAML(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}
