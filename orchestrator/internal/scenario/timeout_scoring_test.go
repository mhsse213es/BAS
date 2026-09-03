package scenario

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/models"
)

// grepPermissionDeniedOutput reproduces what T1552.001 Test 3
// (`grep -ri password /`) actually writes: thousands of permission errors from
// unreadable paths, interleaved with real matches. Every one of those lines is
// an access-denied signature to a naive content matcher.
const grepPermissionDeniedOutput = `grep: /proc/1/task/1/fd/3: Permission denied
grep: /proc/1/map_files: Permission denied
/etc/shadow-: password hash entry
grep: /root/.ssh: Permission denied
grep: /var/lib/private: Permission denied`

// A step killed at its execute deadline must never be scored PASS.
//
// Live regression, 2026-09-03: this exact step ran 123001ms, was killed at its
// 120s deadline (exit -1), and the report showed PASS -- because
// blockSignature matched "permission denied" in the partial output and read it
// as a security control blocking the technique. A technique that never
// completed was counted as a control success, inflating the prevention score.
//
// Asserted for all three frameworks, since each had its own route to the same
// wrong answer.
func TestInterpret_TimedOutStepIsNeverPass(t *testing.T) {
	for _, framework := range []string{"art", "caldera", "custom", ""} {
		t.Run("framework="+framework, func(t *testing.T) {
			got := Interpret(
				Step{TechniqueID: "T1552.001", Name: "Extract passwords with grep", Framework: framework},
				ExecResult{
					ExitCode:   -1,
					Stderr:     grepPermissionDeniedOutput,
					DurationMs: 123001,
					TimedOut:   true,
				},
			)
			if got.Result == models.ResultPass {
				t.Fatalf("timed-out step scored PASS — a technique that never completed counted as a control success.\ndetails: %s", got.Details)
			}
			if got.Result != models.ResultError {
				t.Errorf("Result = %v, want ResultError (excluded from scoring, not counted for or against the endpoint)", got.Result)
			}
			if !strings.Contains(strings.ToLower(got.Details), "timed out") {
				t.Errorf("details do not say the step timed out: %q", got.Details)
			}
		})
	}
}

// The timeout verdict must not depend on the output happening to contain a
// block signature -- a timed-out step with clean output is equally unmeasurable.
func TestInterpret_TimedOutWithBenignOutputIsError(t *testing.T) {
	got := Interpret(
		Step{TechniqueID: "T1059.004", Name: "Long running", Framework: "art"},
		ExecResult{ExitCode: -1, Stdout: "starting sweep...", DurationMs: 123001, TimedOut: true},
	)
	if got.Result != models.ResultError {
		t.Errorf("Result = %v, want ResultError", got.Result)
	}
}

// Guard against over-correction: a genuine access-denied block that did NOT
// time out must still score PASS. The fix keys on the structured TimedOut flag,
// so real prevention evidence is untouched.
func TestInterpret_RealBlockStillScoresPass(t *testing.T) {
	got := Interpret(
		Step{TechniqueID: "T1003.001", Name: "LSASS dump", Framework: "art"},
		ExecResult{ExitCode: 1, Stderr: "Access is denied.", DurationMs: 240, TimedOut: false},
	)
	if got.Result != models.ResultPass {
		t.Errorf("Result = %v, want ResultPass — a real block must still count as prevention.\ndetails: %s", got.Result, got.Details)
	}
}

// And a technique that genuinely ran must still be a finding.
func TestInterpret_SuccessfulExecutionStillScoresFail(t *testing.T) {
	got := Interpret(
		Step{TechniqueID: "T1082", Name: "System info", Framework: "art"},
		ExecResult{ExitCode: 0, Stdout: "Linux audspecterver 6.8.0", DurationMs: 30, TimedOut: false},
	)
	if got.Result != models.ResultFail {
		t.Errorf("Result = %v, want ResultFail — the control did not stop it", got.Result)
	}
}

// classifyExecution carries the same guard, so the ART path stays correct when
// it is called directly rather than through Interpret.
func TestClassifyExecution_TimedOutBeatsBlockSignature(t *testing.T) {
	outcome, reason, detail := classifyExecution(
		ExecResult{ExitCode: -1, Stderr: grepPermissionDeniedOutput, TimedOut: true},
		grepPermissionDeniedOutput,
	)
	if outcome != OutcomeError {
		t.Errorf("outcome = %v, want OutcomeError (not OutcomeBlocked/PASS)", outcome)
	}
	if reason != ErrTimeout {
		t.Errorf("reason = %q, want %q", reason, ErrTimeout)
	}
	if !strings.Contains(strings.ToLower(detail), "timed out") {
		t.Errorf("detail does not mention the timeout: %q", detail)
	}
}
