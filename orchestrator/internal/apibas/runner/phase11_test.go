package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 11 tranche: caching of authenticated responses (DATA-006). The header
// rule uses a case-insensitive contains match on Cache-Control.
func TestPhase11_CachingVulnerableFailsFixedPasses(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-DATA-006"), e.state)
	if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable got %s / %s (%s), want FAIL / exploited",
			rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
	}

	e = newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep = e.run(t, scenarioByID(t, "API-BAS-DATA-006"), e.state)
	if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed got %s / %s (%s), want PASS / enforced",
			rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason)
	}
}
