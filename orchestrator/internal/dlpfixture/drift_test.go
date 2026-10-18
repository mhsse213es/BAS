package dlpfixture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

// loadRealSteps parses every real scenarios/dlp-exfiltration-*.yaml file
// the same way internal/scenario/engine.go does (yaml.Unmarshal into the
// real scenario.Scenario/scenario.Step types -- never a parallel schema,
// never a blind whole-file string search), and returns every step keyed
// by (ScenarioID, StepName).
func loadRealSteps(t *testing.T) map[Occurrence]scenario.Step {
	t.Helper()
	files, err := filepath.Glob("../../../scenarios/dlp-exfiltration-*.yaml")
	if err != nil {
		t.Fatalf("filepath.Glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no scenario files matched ../../../scenarios/dlp-exfiltration-*.yaml -- path convention broken")
	}
	steps := make(map[Occurrence]scenario.Step)
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("os.ReadFile(%q): %v", path, err)
		}
		var s scenario.Scenario
		if err := yaml.Unmarshal(b, &s); err != nil {
			t.Fatalf("yaml.Unmarshal(%q): %v", path, err)
		}
		for _, step := range s.Steps {
			occ := Occurrence{ScenarioID: s.ID, StepName: step.Name}
			if _, dup := steps[occ]; dup {
				t.Fatalf("real scenario %q has a duplicate step name %q", s.ID, step.Name)
			}
			steps[occ] = step
		}
	}
	return steps
}

// Review Focus: this is the forward-direction semantic drift check --
// every catalog occurrence must be a real step, and every catalog value
// must still appear in that specific step's Command field (never a
// whole-file search, so an unrelated step's content can never produce a
// false match).
func TestDrift_EveryFixtureOccurrenceExistsAndMatchesLiveContent(t *testing.T) {
	real := loadRealSteps(t)
	fixtures, err := AllFixtures()
	if err != nil {
		t.Fatalf("AllFixtures: %v", err)
	}
	for _, f := range fixtures {
		for _, occ := range f.Occurrences {
			step, ok := real[occ]
			if !ok {
				t.Errorf("fixture %q references occurrence (%q, %q), which does not exist in the real scenario files", f.ID, occ.ScenarioID, occ.StepName)
				continue
			}
			for _, v := range f.Values {
				if !strings.Contains(step.Command, v) {
					t.Errorf("fixture %q value %q not found in step (%q, %q)'s real Command", f.ID, v, occ.ScenarioID, occ.StepName)
				}
			}
		}
	}
}

// Review Focus: this is the reverse-direction completeness check -- every
// real step across every scenario file must be claimed by some catalog
// fixture, catching an "unregistered fixture value" (a real step nobody
// has catalogued) rather than only catching a stale catalog entry.
func TestDrift_EveryRealStepIsCatalogued(t *testing.T) {
	real := loadRealSteps(t)
	fixtures, err := AllFixtures()
	if err != nil {
		t.Fatalf("AllFixtures: %v", err)
	}
	catalogued := make(map[Occurrence]bool)
	for _, f := range fixtures {
		for _, occ := range f.Occurrences {
			catalogued[occ] = true
		}
	}
	for occ := range real {
		if !catalogued[occ] {
			t.Errorf("real step (%q, %q) is not claimed by any catalog fixture -- an unregistered fixture value", occ.ScenarioID, occ.StepName)
		}
	}
}
