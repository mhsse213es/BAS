package scenario

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Step contract (ratchet). Every step of a live-runnable scenario should say how it is undone, what detection it
// expects and what telemetry it produces. Existing files predate this contract, so they are grandfathered in
// testdata/step_contract_baseline.json with their current gap counts. The rules are:
//
//   - a NEW executable scenario file must have zero gaps;
//   - an EXISTING file's gap counts may fall but must never rise;
//   - regenerate the baseline (only to record improvements) with STEP_CONTRACT_WRITE=1.
//
// This test changes no runtime behaviour: the loader is untouched, and no score or signature moves.

const stepContractBaseline = "testdata/step_contract_baseline.json"

type contractGaps struct {
	Cleanup   int `json:"cleanup"`
	Detection int `json:"detection"`
	Telemetry int `json:"telemetry"`
}

func (g contractGaps) total() int { return g.Cleanup + g.Detection + g.Telemetry }

// stepMissingCleanup: a step must say how it is undone, or declare itself self-cleaning.
func stepMissingCleanup(s Step) bool {
	return strings.TrimSpace(s.Cleanup) == "" && !s.Reversible
}

func stepMissingDetection(s Step) bool { return len(s.Detection) == 0 }

func stepMissingTelemetry(s Step) bool { return len(s.Telemetry) == 0 }

func stepGapsOf(steps []Step) contractGaps {
	var g contractGaps
	for _, s := range steps {
		if stepMissingCleanup(s) {
			g.Cleanup++
		}
		if stepMissingDetection(s) {
			g.Detection++
		}
		if stepMissingTelemetry(s) {
			g.Telemetry++
		}
	}
	return g
}

// contractScenarioDir is orchestrator/internal/scenario -> repo root -> scenarios/.
const contractScenarioDir = "../../../scenarios"

// measureExecutableScenarios returns gap counts for every file that explicitly declares executable: true and defines
// at least one step, keyed by its path relative to scenarios/ with forward slashes.
func measureExecutableScenarios(t *testing.T) map[string]contractGaps {
	t.Helper()
	out := map[string]contractGaps{}
	err := filepath.Walk(contractScenarioDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var f struct {
			Executable *bool  `yaml:"executable"`
			Steps      []Step `yaml:"steps"`
		}
		if err := yaml.Unmarshal(b, &f); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		if f.Executable == nil || !*f.Executable || len(f.Steps) == 0 {
			return nil
		}
		rel, err := filepath.Rel(contractScenarioDir, path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = stepGapsOf(f.Steps)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", contractScenarioDir, err)
	}
	return out
}

func readContractBaseline(t *testing.T) map[string]contractGaps {
	t.Helper()
	b, err := os.ReadFile(stepContractBaseline)
	if err != nil {
		t.Fatalf("read baseline %s: %v", stepContractBaseline, err)
	}
	var base map[string]contractGaps
	if err := json.Unmarshal(b, &base); err != nil {
		t.Fatalf("parse baseline %s: %v", stepContractBaseline, err)
	}
	return base
}

func writeContractBaseline(t *testing.T, current map[string]contractGaps) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(stepContractBaseline), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	b, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	if err := os.WriteFile(stepContractBaseline, append(b, '\n'), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
}

// TestStepContract_Ratchet enforces the rules above against the real scenarios directory.
func TestStepContract_Ratchet(t *testing.T) {
	current := measureExecutableScenarios(t)
	if len(current) < 90 {
		// Guard against a vacuous pass if the directory moved or the walk found nothing.
		t.Fatalf("found only %d executable scenario files with steps; expected about 108", len(current))
	}
	if os.Getenv("STEP_CONTRACT_WRITE") == "1" {
		writeContractBaseline(t, current)
		t.Logf("baseline written with %d files", len(current))
		return
	}
	base := readContractBaseline(t)

	keys := make([]string, 0, len(current))
	for k := range current {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cur := current[k]
		old, known := base[k]
		if !known {
			if cur.total() > 0 {
				t.Errorf("new scenario %s violates the step contract (cleanup %d, detection %d, telemetry %d steps missing)",
					k, cur.Cleanup, cur.Detection, cur.Telemetry)
			}
			continue
		}
		if cur.Cleanup > old.Cleanup || cur.Detection > old.Detection || cur.Telemetry > old.Telemetry {
			t.Errorf("%s regressed: cleanup %d->%d, detection %d->%d, telemetry %d->%d",
				k, old.Cleanup, cur.Cleanup, old.Detection, cur.Detection, old.Telemetry, cur.Telemetry)
		}
		if cur.total() < old.total() {
			t.Logf("%s improved (gaps %d -> %d); regenerate the baseline to lock this in", k, old.total(), cur.total())
		}
	}
	for k := range base {
		if _, ok := current[k]; !ok {
			t.Logf("baseline entry %s no longer present as an executable scenario; regenerate the baseline", k)
		}
	}
}

// Negative: a step with no cleanup and no self-cleaning declaration is a gap.
func TestStepContract_StepWithoutCleanupIsAGap(t *testing.T) {
	if !stepMissingCleanup(Step{}) {
		t.Error("an empty step should be missing cleanup")
	}
	if stepMissingCleanup(Step{Cleanup: "rm -f /tmp/x"}) {
		t.Error("a step with a cleanup command should not be a gap")
	}
	if stepMissingCleanup(Step{Reversible: true}) {
		t.Error("a self-cleaning (reversible) step should not be a gap")
	}
	if !stepMissingCleanup(Step{Cleanup: "   "}) {
		t.Error("a whitespace-only cleanup must not count as cleanup")
	}
}

// Negative: detection and telemetry are gaps when empty, and satisfied when listed.
func TestStepContract_DetectionAndTelemetry(t *testing.T) {
	if !stepMissingDetection(Step{}) || !stepMissingTelemetry(Step{}) {
		t.Error("an empty step should be missing detection and telemetry")
	}
	full := Step{Detection: []string{"EDR: process tree"}, Telemetry: []string{"Sysmon EID 1"}}
	if stepMissingDetection(full) || stepMissingTelemetry(full) {
		t.Error("a step that lists detection and telemetry should not be a gap")
	}
}

// Positive: gap counting adds up across a mixed step list.
func TestStepContract_CountsAcrossSteps(t *testing.T) {
	g := stepGapsOf([]Step{
		{},
		{Cleanup: "undo", Detection: []string{"d"}, Telemetry: []string{"t"}},
		{Reversible: true, Detection: []string{"d"}},
	})
	want := contractGaps{Cleanup: 1, Detection: 1, Telemetry: 2}
	if g != want {
		t.Errorf("gaps = %+v, want %+v", g, want)
	}
}
