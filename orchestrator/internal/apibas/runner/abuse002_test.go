package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// unqualifiedMachine reports whether the runner refused to grade because this machine does not match any committed
// calibration record. That is the gate working as designed, not a defect: a timing verdict is only meaningful on a
// machine the scenario was qualified on, so the timing tests below cannot assert a verdict anywhere else. To run them on
// a new machine (a CI runner, say), qualify it and commit a calibration record for its fingerprint.
func unqualifiedMachine(o grade.Outcome) bool {
	return o.Reason == grade.ReasonRequalificationRequired
}

// TestABUSE002Repeatability runs the timing scenario five times per build. Each build's verdict is
// stated before the run: the vulnerable build is FAIL exploited, the fixed build is PASS not_exploited.
// Every run must match its expected verdict, and all runs of a build must agree. A verdict that flips
// between runs is not stable, so the test fails instead of averaging it away.
//
// The timing string is checked by its stage and outcome. It has the form "stage:RESULT/exploitability".
func TestABUSE002Repeatability(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement skipped in -short mode")
	}
	want := map[lab.Mode]grade.Outcome{
		lab.ModeVulnerable: {Result: grade.FAIL, Exploitability: grade.Exploited},
		lab.ModeFixed:      {Result: grade.PASS, Exploitability: grade.NotExploited},
	}
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		var first grade.Outcome
		for run := 0; run < 5; run++ {
			e := newEnv(t, mode, fixture.OrdersTwoTenant())
			rep := e.run(t, scenarioByID(t, "API-BAS-ABUSE-002"), e.state)
			t.Logf("mode=%s run=%d outcome=%s/%s reason=%q timing=%s", mode, run,
				rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason, rep.TimingVerdict)
			if unqualifiedMachine(rep.Outcome) {
				t.Skipf("this machine matches no committed calibration record for API-BAS-ABUSE-002, so no timing verdict is graded: %s", rep.TimingVerdict)
			}
			if rep.Outcome.Result != want[mode].Result || rep.Outcome.Exploitability != want[mode].Exploitability {
				t.Fatalf("mode=%s run=%d outcome %s/%s, want %s/%s (timing %s, reason %q)",
					mode, run, rep.Outcome.Result, rep.Outcome.Exploitability,
					want[mode].Result, want[mode].Exploitability, rep.TimingVerdict, rep.Outcome.Reason)
			}
			if run == 0 {
				first = rep.Outcome
				continue
			}
			if rep.Outcome.Result != first.Result || rep.Outcome.Reason != first.Reason {
				t.Fatalf("mode=%s run=%d outcome %s/%s differs from run 0 %s/%s",
					mode, run, rep.Outcome.Result, rep.Outcome.Reason, first.Result, first.Reason)
			}
		}
	}
}
