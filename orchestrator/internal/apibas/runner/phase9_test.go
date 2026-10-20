package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 9 tranche: response-header evidence. DISC-005 fails when the untrusted
// origin is reflected, and passes when no CORS grant is sent.
func TestPhase9_CORSVulnerableFailsFixedPasses(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-DISC-005"), e.state)
	if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable got %s / %s (%s), want FAIL / exploited",
			rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
	}

	e = newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep = e.run(t, scenarioByID(t, "API-BAS-DISC-005"), e.state)
	if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed got %s / %s (%s), want PASS / not exploited",
			rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
	}
}
