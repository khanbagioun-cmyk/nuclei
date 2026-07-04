package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/intelligence"
)

func TestParseWorkflowTechs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a sample workflow file
	wfContent := `id: wordpress-workflow

info:
  name: Wordpress Security Checks
  author: kiblyn11
  description: A simple workflow that runs all wordpress related nuclei templates.
workflows:
  - template: http/technologies/wordpress-detect.yaml
    subtemplates:
      - tags: wordpress
`
	wfPath := filepath.Join(tmpDir, "wordpress-workflow.yaml")
	if err := os.WriteFile(wfPath, []byte(wfContent), 0644); err != nil {
		t.Fatal(err)
	}

	techs := parseWorkflowTechs(wfPath)

	// Should extract "wordpress" from id, template path, and tags
	found := false
	for _, tech := range techs {
		if tech == "wordpress" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find 'wordpress' in techs, got: %v", techs)
	}
}

func TestParseWorkflowTechs_Apache(t *testing.T) {
	tmpDir := t.TempDir()

	wfContent := `id: apache-workflow

info:
  name: Apache workflow
  author: philippedelteil
workflows:
  - template: http/technologies/apache/apache-detect.yaml
    subtemplates:
      - tags: apache
`
	wfPath := filepath.Join(tmpDir, "apache-workflow.yaml")
	if err := os.WriteFile(wfPath, []byte(wfContent), 0644); err != nil {
		t.Fatal(err)
	}

	techs := parseWorkflowTechs(wfPath)

	found := false
	for _, tech := range techs {
		if tech == "apache" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find 'apache' in techs, got: %v", techs)
	}
}

func TestMatchWorkflows(t *testing.T) {
	tmpDir := t.TempDir()
	wfDir := filepath.Join(tmpDir, "workflows")
	if err := os.MkdirAll(wfDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create workflow files
	wfs := map[string]string{
		"wordpress-workflow.yaml": `id: wordpress-workflow
workflows:
  - template: http/technologies/wordpress-detect.yaml
    subtemplates:
      - tags: wordpress
`,
		"apache-workflow.yaml": `id: apache-workflow
workflows:
  - template: http/technologies/apache/apache-detect.yaml
    subtemplates:
      - tags: apache
`,
		"joomla-workflow.yaml": `id: joomla-workflow
workflows:
  - template: http/technologies/joomla-detect.yaml
    subtemplates:
      - tags: joomla
`,
	}

	for name, content := range wfs {
		if err := os.WriteFile(filepath.Join(wfDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Create a chainer with WordPress detected
	chainer := intelligence.NewChainer()
	chainer.RecordPhase1Result("http://example.com", []string{"wordpress"}, "", nil, "", "", nil)

	matched := matchWorkflows(chainer, wfDir)
	if len(matched) != 1 {
		t.Fatalf("expected 1 matching workflow, got %d: %v", len(matched), matched)
	}

	// Verify it's the wordpress workflow
	base := filepath.Base(matched[0])
	if base != "wordpress-workflow.yaml" {
		t.Errorf("expected wordpress-workflow.yaml, got %s", base)
	}
}

func TestMatchWorkflows_NoMatch(t *testing.T) {
	tmpDir := t.TempDir()
	wfDir := filepath.Join(tmpDir, "workflows")
	if err := os.MkdirAll(wfDir, 0755); err != nil {
		t.Fatal(err)
	}

	wfContent := `id: joomla-workflow
workflows:
  - template: http/technologies/joomla-detect.yaml
    subtemplates:
      - tags: joomla
`
	if err := os.WriteFile(filepath.Join(wfDir, "joomla-workflow.yaml"), []byte(wfContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Chainer with no matching tech
	chainer := intelligence.NewChainer()
	chainer.RecordPhase1Result("http://example.com", []string{"nginx"}, "", nil, "", "", nil)

	matched := matchWorkflows(chainer, wfDir)
	if len(matched) != 0 {
		t.Errorf("expected 0 matching workflows, got %d", len(matched))
	}
}

func TestMatchWorkflows_NoTechDetected(t *testing.T) {
	tmpDir := t.TempDir()
	wfDir := filepath.Join(tmpDir, "workflows")
	if err := os.MkdirAll(wfDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Empty chainer — no tech detected
	chainer := intelligence.NewChainer()

	matched := matchWorkflows(chainer, wfDir)
	if len(matched) != 0 {
		t.Errorf("expected 0 matching workflows with no tech, got %d", len(matched))
	}
}

func TestMatchWorkflows_DirNotExist(t *testing.T) {
	chainer := intelligence.NewChainer()
	chainer.RecordPhase1Result("http://example.com", []string{"nginx"}, "", nil, "", "", nil)

	matched := matchWorkflows(chainer, "/nonexistent/path/workflows")
	if len(matched) != 0 {
		t.Errorf("expected 0 matching workflows for nonexistent dir, got %d", len(matched))
	}
}

func TestMergeResults(t *testing.T) {
	tmpDir := t.TempDir()
	mainFile := filepath.Join(tmpDir, "main.jsonl")
	wfFile := filepath.Join(tmpDir, "wf.jsonl")

	mainData := `{"template-id":"test1","host":"http://example.com"}
`
	wfData := `{"template-id":"test2","host":"http://example.com"}
{"template-id":"test3","host":"http://example.com"}
`

	if err := os.WriteFile(mainFile, []byte(mainData), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wfFile, []byte(wfData), 0644); err != nil {
		t.Fatal(err)
	}

	mergeResults(mainFile, wfFile)

	merged, err := os.ReadFile(mainFile)
	if err != nil {
		t.Fatal(err)
	}

	lines := 0
	for _, b := range merged {
		if b == '\n' {
			lines++
		}
	}
	if lines != 3 {
		t.Errorf("expected 3 lines after merge, got %d", lines)
	}
}
