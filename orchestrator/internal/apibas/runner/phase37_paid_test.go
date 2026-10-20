package runner_test

import (
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/runner"
)

// Phase 37 expectations, written before the run:
//   - ABUSE-006 (validator limit 5 per run): vulnerable accepts all 10 attack requests, each of which calls the
//     downstream validator, and FAILs exploited. Fixed accepts 5 and refuses 5 with 429, and PASSes.
//   - ABUSE-007 (send limit 3 per run): vulnerable accepts all 10 sends (paid units consumed) and FAILs
//     exploited. Fixed accepts 3 and refuses 7 with 429, and PASSes.
// Accepted attempts are counted from the attack exchanges, so the downstream and paid work is observed, not
// assumed from the verdict.

func countAttackStatuses(rep runner.Report, stepID string) map[int]int {
	out := map[int]int{}
	for _, x := range rep.Exchanges {
		if x.StepID == stepID {
			out[x.Status]++
		}
	}
	return out
}

func TestPhase37_ExpensiveAndPaidAbuse(t *testing.T) {
	cases := []struct {
		id, step     string
		acceptStatus int
		wantAccepted int
		wantRefused  int
	}{
		{"API-BAS-ABUSE-006", "attack-unbounded-validation", http.StatusOK, 5, 5},
		{"API-BAS-ABUSE-007", "attack-unbounded-otp-send", http.StatusAccepted, 3, 7},
	}
	for _, c := range cases {
		s := scenarioByID(t, c.id)
		fx := fixture.OrdersTwoTenant()

		vuln := newEnv(t, lab.ModeVulnerable, fx)
		rv := vuln.run(t, s, vuln.state)
		if rv.Outcome.Result != grade.FAIL || rv.Outcome.Exploitability != grade.Exploited {
			t.Fatalf("%s vulnerable = %s/%s (%s), want FAIL/exploited", c.id, rv.Outcome.Result, rv.Outcome.Exploitability, rv.Detail)
		}
		if got := countAttackStatuses(rv, c.step)[c.acceptStatus]; got != 10 {
			t.Fatalf("%s vulnerable accepted %d of 10 attack requests, want 10", c.id, got)
		}

		fixed := newEnv(t, lab.ModeFixed, fx)
		rf := fixed.run(t, s, fixed.state)
		if rf.Outcome.Result != grade.PASS || rf.Outcome.Control != grade.Enforced {
			t.Fatalf("%s fixed = %s/%s (%s), want PASS/enforced", c.id, rf.Outcome.Result, rf.Outcome.Control, rf.Detail)
		}
		st := countAttackStatuses(rf, c.step)
		if st[c.acceptStatus] != c.wantAccepted || st[http.StatusTooManyRequests] != c.wantRefused {
			t.Fatalf("%s fixed statuses %v, want %d accepted and %d refused with 429", c.id, st, c.wantAccepted, c.wantRefused)
		}
	}
}
