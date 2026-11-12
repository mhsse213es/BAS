package api

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/variant"
)

// A variant of an ART test must carry that test's own cleanup command, so the agent reverts what the test changed.
// Without it, persistence and registry variants are never reverted or checked.
func TestBaseCleanupFor_PicksTheNamedAtomic(t *testing.T) {
	steps := []scenario.ScenarioStep{
		{Name: "first test", Cleanup: "remove first"},
		{Name: "second test", Cleanup: "remove second"},
	}
	if got := baseCleanupFor(steps, "second test"); got != "remove second" {
		t.Errorf("baseCleanupFor = %q, want the second test's cleanup", got)
	}
}

// With no base test named, there is no cleanup to borrow: a guessed cleanup could revert the wrong thing.
func TestBaseCleanupFor_NoBaseIDMeansNoCleanup(t *testing.T) {
	steps := []scenario.ScenarioStep{{Name: "only", Cleanup: "remove only"}}
	if got := baseCleanupFor(steps, ""); got != "" {
		t.Errorf("baseCleanupFor with empty base = %q, want empty", got)
	}
}

func TestBaseCleanupFor_UnknownAtomicMeansNoCleanup(t *testing.T) {
	steps := []scenario.ScenarioStep{{Name: "only", Cleanup: "remove only"}}
	if got := baseCleanupFor(steps, "missing"); got != "" {
		t.Errorf("baseCleanupFor unknown = %q, want empty", got)
	}
}

func TestBuildVariantSteps_CarriesTheCleanupFromTheTemplate(t *testing.T) {
	templates := []variant.Template{
		{TechniqueID: "T1547.001", Executor: "powershell", Command: "run", Encoding: "plain", ExecContext: "powershell_direct", Evasion: "none", BaseID: "run key test", Cleanup: "remove run key"},
	}
	steps := buildVariantSteps(templates)
	if len(steps) != 1 {
		t.Fatalf("steps = %d, want 1", len(steps))
	}
	if steps[0].Cleanup != "remove run key" {
		t.Errorf("step.Cleanup = %q, want the template's cleanup", steps[0].Cleanup)
	}
}
