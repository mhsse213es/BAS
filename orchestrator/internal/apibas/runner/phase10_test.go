package runner_test

import (
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 10 tranche: counted attack requests. ABUSE-001 sends five wrong codes
// and allows three accepted attempts.
func TestPhase10_CountedAttemptsVulnerableFailsFixedPasses(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-ABUSE-001"), e.state)
	if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable got %s / %s (%s), want FAIL / exploited",
			rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
	}

	e = newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep = e.run(t, scenarioByID(t, "API-BAS-ABUSE-001"), e.state)
	if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed got %s / %s (%s), want PASS / enforced",
			rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason)
	}
}

// The fixed build accepts exactly three attempts and then answers 429. The
// report holds the baseline plus five attack exchanges.
func TestPhase10_FixedAcceptsExactlyLimit(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-ABUSE-001"), e.state)
	if len(rep.Exchanges) != 6 {
		t.Fatalf("exchanges = %d, want 6 (baseline plus five attempts)", len(rep.Exchanges))
	}
	want := []int{http.StatusOK, http.StatusUnauthorized, http.StatusUnauthorized, http.StatusUnauthorized,
		http.StatusTooManyRequests, http.StatusTooManyRequests}
	for i, ex := range rep.Exchanges {
		if ex.Status != want[i] {
			t.Errorf("exchange %d status = %d, want %d", i, ex.Status, want[i])
		}
	}
}
