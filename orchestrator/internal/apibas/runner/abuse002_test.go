package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// ABUSE-002 repeatability: each variant is measured three times on this machine.
// The outcome must be the same on every run, and the summaries are logged so the
// frozen ceiling can be checked against the numbers. Skipped under -short.
func TestABUSE002Repeatability(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement skipped in -short mode")
	}
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		var first grade.Outcome
		for run := 0; run < 3; run++ {
			e := newEnv(t, mode, fixture.OrdersTwoTenant())
			rep := e.run(t, scenarioByID(t, "API-BAS-ABUSE-002"), e.state)
			for i, sum := range rep.Latency {
				t.Logf("mode=%s run=%d round=%d median_attack=%.2fms p95_attack=%.2fms median_baseline=%.2fms ratio=%.1f cv=%.3f",
					mode, run, i, sum.MedianAttackMs, sum.P95AttackMs, sum.MedianBaselineMs, sum.Ratio, sum.CV)
			}
			t.Logf("mode=%s run=%d outcome=%s/%s reason=%s timing=%s", mode, run,
				rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason, rep.TimingVerdict)
			if mode == lab.ModeVulnerable && rep.TimingVerdict != "FAIL/exploited" {
				t.Fatalf("vulnerable timing verdict = %q, want FAIL/exploited", rep.TimingVerdict)
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
