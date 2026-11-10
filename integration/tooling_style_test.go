package integration

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Go source has AST-based checks in style_test.go. The same line measure applies
// to maintained workflows, fixture scripts, container definitions and prose.
func TestToolingAssetStyle(t *testing.T) {
	for _, root := range []string{"../cmd", "../internal", "../integration", "../.github"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == "__pycache__" {
					return filepath.SkipDir
				}
				return nil
			}
			extension := filepath.Ext(path)
			if extension == ".sh" {
				t.Errorf("%s: host orchestration belongs in the Go tooling command", path)
			}
			if extension == ".py" || extension == ".yml" || extension == ".yaml" ||
				extension == ".md" || filepath.Base(path) == "Dockerfile" ||
				filepath.Base(path) == ".dockerignore" {
				checkAssetWidth(t, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"../README.md", "../STYLE.md", "../config.example.json"} {
		checkAssetWidth(t, path)
	}
}

func checkAssetWidth(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for index, line := range strings.Split(string(data), "\n") {
		if utf8.RuneCountInString(line) > 100 {
			t.Errorf("%s:%d: tooling source exceeds 100 columns", path, index+1)
		}
		if strings.ContainsRune(line, '\t') {
			t.Errorf("%s:%d: use spaces in non-Go source", path, index+1)
		}
	}
}

func TestCIUsesPinnedActionsBoundedJobsAndSharedTooling(t *testing.T) {
	var workflow struct {
		Jobs map[string]struct {
			TimeoutMinutes uint32 `yaml:"timeout-minutes"`
			Steps          []struct {
				Uses string `yaml:"uses"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	data, err := os.ReadFile("../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	pinnedAction := regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
	if len(workflow.Jobs) != 3 {
		t.Fatal("unexpected CI job set")
	}
	for name, job := range workflow.Jobs {
		if job.TimeoutMinutes == 0 || job.TimeoutMinutes > 20 {
			t.Errorf("%s: CI job must have a positive bounded timeout", name)
		}
		for _, step := range job.Steps {
			if step.Uses != "" && !pinnedAction.MatchString(step.Uses) {
				t.Errorf("%s: action is not pinned to a full commit: %s", name, step.Uses)
			}
			if step.Run != "" && !strings.HasPrefix(step.Run, "go run ./cmd/dev ") &&
				step.Run != "go install mvdan.cc/gofumpt@v0.12.0" {
				t.Errorf("%s: CI orchestration must use the shared tooling command", name)
			}
			if strings.Contains(step.Run, "\n") {
				t.Errorf("%s: do not hide another script in workflow YAML", name)
			}
		}
	}
}
