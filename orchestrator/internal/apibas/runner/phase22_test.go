package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 22 tranche: injection (API-BAS-INJ). Each scenario must FAIL with exploitation
// against the vulnerable build and PASS with control enforced against the fixed build.
// The fixed-build PASS is the negative control: a refused injection is not a finding.
var injectionScenarios = []string{
	"API-BAS-INJ-001",
	"API-BAS-INJ-002",
	"API-BAS-INJ-003",
	"API-BAS-INJ-004",
	"API-BAS-INJ-006",
	"API-BAS-INJ-008",
	"API-BAS-INJ-009",
	"API-BAS-INJ-010",
	"API-BAS-INJ-011",
	"API-BAS-INJ-012",
}

func TestPhase22_InjectionVulnerableFailsFixedPasses(t *testing.T) {
	for _, id := range injectionScenarios {
		t.Run(id, func(t *testing.T) {
			e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
			rep := e.run(t, scenarioByID(t, id), e.state)
			if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
				t.Fatalf("vulnerable got %s / %s (%s), want FAIL / exploited",
					rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
			}

			e = newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
			rep = e.run(t, scenarioByID(t, id), e.state)
			if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
				t.Fatalf("fixed got %s / %s (%s), want PASS / enforced",
					rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason)
			}
		})
	}
}

// Every injection flaw must be present in the vulnerable build's registry, so the
// planted flaw list and the scenarios cannot drift apart.
func TestPhase22_InjectionFlawsAreRegistered(t *testing.T) {
	want := map[string]bool{}
	for _, id := range injectionScenarios {
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
