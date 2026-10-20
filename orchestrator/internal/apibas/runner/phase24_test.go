package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 24 tranche: authorization (API-BAS-AUTHZ 005, 008, 009, 011). Each scenario must FAIL
// with exploitation against the vulnerable build and PASS with control enforced against the
// fixed build.
var authzScenarios = []string{
	"API-BAS-AUTHZ-005",
	"API-BAS-AUTHZ-008",
	"API-BAS-AUTHZ-009",
	"API-BAS-AUTHZ-011",
}

func TestPhase24_AuthzVulnerableFailsFixedPasses(t *testing.T) {
	for _, id := range authzScenarios {
		t.Run(id, func(t *testing.T) {
			e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
			rep := e.run(t, scenarioByID(t, id), e.state)
			if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
				t.Fatalf("vulnerable got %s / %s (%s) %s, want FAIL / exploited",
					rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason, rep.Detail)
			}

			e = newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
			rep = e.run(t, scenarioByID(t, id), e.state)
			if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
				t.Fatalf("fixed got %s / %s (%s) %s, want PASS / enforced",
					rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason, rep.Detail)
			}
		})
	}
}

// Every authorization flaw must be registered against its scenario.
func TestPhase24_AuthzFlawsAreRegistered(t *testing.T) {
	want := map[string]bool{}
	for _, id := range authzScenarios {
		want[id] = false
	}
	for _, f := range lab.Flaws() {
		if _, ok := want[f.ScenarioID]; ok {
			want[f.ScenarioID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("no planted flaw registered for %s", id)
		}
	}
}
