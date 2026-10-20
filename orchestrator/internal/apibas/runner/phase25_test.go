package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 25 tranche: discovery (API-BAS-DISC 001, 004, 007, 008). Each scenario must FAIL with
// exploitation against the vulnerable build and PASS with control enforced against the fixed
// build.
var discoveryScenarios = []string{
	"API-BAS-DISC-001",
	"API-BAS-DISC-004",
	"API-BAS-DISC-007",
	"API-BAS-DISC-008",
}

func TestPhase25_DiscoveryVulnerableFailsFixedPasses(t *testing.T) {
	for _, id := range discoveryScenarios {
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

// Every discovery flaw must be registered against its scenario.
func TestPhase25_DiscoveryFlawsAreRegistered(t *testing.T) {
	want := map[string]bool{}
	for _, id := range discoveryScenarios {
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
