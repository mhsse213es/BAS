package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 2b tranche: legacy version bypass, debug exposure, summary projection.
// Each must FAIL against the planted flaw and PASS against the fixed build.
func TestPhase2b_VulnerableFailsFixedPasses(t *testing.T) {
	for _, id := range []string{"API-BAS-AUTHZ-010", "API-BAS-DISC-003", "API-BAS-DATA-001"} {
		t.Run(id+"/vulnerable", func(t *testing.T) {
			e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
			rep := e.run(t, scenarioByID(t, id), e.state)
			if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
				t.Fatalf("got %s / %s (%s), want FAIL / exploited",
					rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
			}
		})
		t.Run(id+"/fixed", func(t *testing.T) {
			e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
			rep := e.run(t, scenarioByID(t, id), e.state)
			if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
				t.Fatalf("got %s / %s (%s), want PASS / enforced",
					rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason)
			}
		})
	}
}

// The projection control must PASS on a 200 with no leak, but only because the
// fixed build actually served the projection. A 200 from a route that returns
// nothing would be the same status with no evidence, so check the fixed
// response is the summary and not an empty success.
func TestPhase2b_FixedSummaryIsServedAndClean(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-DATA-001"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Status != 200 || attack.Leaked != 0 {
		t.Fatalf("summary status=%d leaked=%d, want 200 and no leak", attack.Status, attack.Leaked)
	}
	if attack.Body == "" || attack.Body == "{}" {
		t.Fatalf("summary body is empty; a clean PASS needs a served projection")
	}
}

// The debug route must not exist in the fixed build, so the fixed build refuses
// it by not mounting it (404), not by a check that could be bypassed.
func TestPhase2b_DebugRouteAbsentFromFixedBuild(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-DISC-003"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Status != 404 {
		t.Fatalf("debug route status on fixed build = %d, want 404", attack.Status)
	}
}
