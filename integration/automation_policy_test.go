package integration

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDependencyUpdateQueuesAndSchedulesAreBounded(t *testing.T) {
	var configuration struct {
		Updates []struct {
			Ecosystem string `yaml:"package-ecosystem"`
			Directory string `yaml:"directory"`
			Limit     uint32 `yaml:"open-pull-requests-limit"`
			Schedule  struct {
				Interval string `yaml:"interval"`
				Day      string `yaml:"day"`
				Time     string `yaml:"time"`
				Timezone string `yaml:"timezone"`
			} `yaml:"schedule"`
		} `yaml:"updates"`
	}
	data, err := os.ReadFile("../.github/dependabot.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &configuration); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, update := range configuration.Updates {
		if seen[update.Ecosystem] {
			t.Fatal("duplicate dependency update queue", update.Ecosystem)
		}
		seen[update.Ecosystem] = true
		if update.Limit == 0 || update.Limit > 5 {
			t.Fatal("dependency update queue has no explicit bound", update.Ecosystem)
		}
		if update.Schedule.Interval != "weekly" || update.Schedule.Day != "monday" ||
			update.Schedule.Time != "08:00" || update.Schedule.Timezone != "UTC" {
			t.Fatal("dependency updates have an implicit schedule", update.Ecosystem)
		}
	}
	if len(seen) != 3 || !seen["gomod"] || !seen["docker"] || !seen["github-actions"] {
		t.Fatal("unexpected dependency update set", seen)
	}
}

func TestFixtureImagePinAndBuildContext(t *testing.T) {
	data, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	digest := regexp.MustCompile(`(?m)^ARG BASE_DIGEST=sha256:[0-9a-f]{64}$`)
	if !digest.Match(data) || !strings.Contains(string(data), "FROM ${BASE_IMAGE}@${BASE_DIGEST}") {
		t.Fatal("fixture base is not pinned by digest")
	}
	data, err = os.ReadFile(".dockerignore")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "**\n!Dockerfile\n!.dockerignore\n!server.py\n!server_test.py\n" {
		t.Fatal("fixture build context must not include source, binaries or credentials")
	}
}
