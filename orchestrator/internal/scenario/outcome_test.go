package scenario

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/models"
)

// Interpret is the single top-level entry point every framework's result
// flows through; the Vetoed check must live there (mirroring exactly how
// TimedOut is already checked before the framework switch), not only
// inside classifyExecution -- which only interpretART calls. Before this
// fix, a vetoed step with framework "custom" (em-07's own framework, and
// every hand-authored scenario in this codebase) fell straight through
// interpretCustom, which has no knowledge of Vetoed at all, and scored
// FAIL -- fabricating a "technique executed and was not stopped" finding
// for a step Audspect never attempted. Asserted for all four framework
// values since each has an independent code path that must not silently
// reintroduce the same class of bug (final whole-branch review, C1).
func TestInterpret_VetoedStepIsNeverPassOrFailAcrossAllFrameworks(t *testing.T) {
	for _, framework := range []string{"art", "caldera", "custom", ""} {
		t.Run("framework="+framework, func(t *testing.T) {
			got := Interpret(
				Step{TechniqueID: "T1490", Name: "VSS Delete", Framework: framework},
				ExecResult{
					ExitCode:             -1,
					Vetoed:               true,
					VetoedActionKey:      "vss_delete",
					VetoedExecutionClass: "destructive",
					VetoedBlockSource:    "catalog",
				},
			)
			if got.Result != models.ResultVetoed {
				t.Fatalf("Result = %v, want ResultVetoed", got.Result)
			}
			if got.Result == models.ResultPass || got.Result == models.ResultBlocked || got.Result == models.ResultFail {
				t.Fatal("a B5 veto must never score as PASS, BLOCKED, or FAIL regardless of framework")
			}
		})
	}
}

func TestClassifyExecution_VetoedStepTakesPriorityOverEverything(t *testing.T) {
	r := ExecResult{
		Vetoed: true, VetoedActionKey: "vss_delete",
		VetoedExecutionClass: "destructive", VetoedBlockSource: "catalog",
		ExitCode: -1,
	}
	outcome, reason, detail := classifyExecution(r, "")
	if outcome != OutcomeVetoed {
		t.Errorf("outcome = %v, want OutcomeVetoed", outcome)
	}
	if reason != ErrNone {
		t.Errorf("reason = %v, want ErrNone -- a veto is not a BAS execution error", reason)
	}
	if !strings.Contains(detail, "VETOED") || !strings.Contains(detail, "not tested") {
		t.Errorf("detail = %q, must clearly state the customer's defenses were not tested", detail)
	}
}
