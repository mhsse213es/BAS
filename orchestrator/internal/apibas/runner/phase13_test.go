package runner_test

import (
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 13 tranche: upload bounds (ABUSE-005). The attack body is 2 MiB, built
// from a filler placeholder in the scenario.
func TestPhase13_UploadVulnerableFailsFixedPasses(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-ABUSE-005"), e.state)
	if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable got %s / %s (%s), want FAIL / exploited",
			rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
	}

	e = newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep = e.run(t, scenarioByID(t, "API-BAS-ABUSE-005"), e.state)
	if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed got %s / %s (%s), want PASS / enforced",
			rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason)
	}
	if attack := rep.Exchanges[len(rep.Exchanges)-1]; attack.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("fixed oversized attachment status = %d, want 413", attack.Status)
	}
}
