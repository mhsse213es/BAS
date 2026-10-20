package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 26 tranche: the last six Phase 2 scenarios (DATA-002, DATA-008, ABUSE-008, ABUSE-009,
// AUTHN-006, INTEG-004). Each must FAIL with exploitation against the vulnerable build and PASS
// with control enforced against the fixed build.
var remainingScenarios = []string{
	"API-BAS-DATA-002",
	"API-BAS-DATA-008",
	"API-BAS-ABUSE-008",
	"API-BAS-ABUSE-009",
	"API-BAS-AUTHN-006",
	"API-BAS-INTEG-004",
}

func TestPhase26_RemainingVulnerableFailsFixedPasses(t *testing.T) {
	for _, id := range remainingScenarios {
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

// Every flaw of the last six scenarios must be registered against its scenario.
func TestPhase26_RemainingFlawsAreRegistered(t *testing.T) {
	want := map[string]bool{}
	for _, id := range remainingScenarios {
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
