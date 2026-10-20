package runner_test

import (
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// ABUSE-003 runs on the paged fixture: the owner holds 151 orders, more than the
// largest page the fixed build allows, so both the granted size and the item count
// can exceed the cap.
func TestPhase12_PaginationVulnerableFailsFixedPasses(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersPaged())
	rep := e.run(t, scenarioByID(t, "API-BAS-ABUSE-003"), e.state)
	if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable got %s / %s (%s), want FAIL / exploited",
			rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
	}

	e = newEnv(t, lab.ModeFixed, fixture.OrdersPaged())
	rep = e.run(t, scenarioByID(t, "API-BAS-ABUSE-003"), e.state)
	if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed got %s / %s (%s), want PASS / enforced",
			rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason)
	}
	if attack := rep.Exchanges[len(rep.Exchanges)-1]; attack.Status != http.StatusBadRequest {
		t.Fatalf("fixed oversized page status = %d, want 400", attack.Status)
	}
}
