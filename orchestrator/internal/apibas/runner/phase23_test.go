package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 23 tranche: gateway (API-BAS-GWAY). Each scenario must FAIL with exploitation against
// the vulnerable build and PASS with control enforced against the fixed build. GWAY-011 needs
// the lab to hold the authz-store-down fault, so it runs only in a faulted lab.
var gatewayScenarios = []string{
	"API-BAS-GWAY-001",
	"API-BAS-GWAY-002",
	"API-BAS-GWAY-004",
	"API-BAS-GWAY-005",
	"API-BAS-GWAY-006",
	"API-BAS-GWAY-007",
	"API-BAS-GWAY-008",
	"API-BAS-GWAY-009",
	"API-BAS-GWAY-010",
}

func TestPhase23_GatewayVulnerableFailsFixedPasses(t *testing.T) {
	for _, id := range gatewayScenarios {
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

// GWAY-011 runs only in a lab started with the authz-store-down fault. Without it the
// scenario must be skipped as a precondition failure, never counted as a pass.
func TestPhase23_FailOpenNeedsTheFault(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-GWAY-011"), e.state)
	if rep.Outcome.Result != grade.SKIPPED || rep.Outcome.Reason != grade.ReasonPreconditionMissing {
		t.Fatalf("without the fault got %s (%s), want SKIPPED / PRECONDITION_MISSING",
			rep.Outcome.Result, rep.Outcome.Reason)
	}
}

func TestPhase23_FailOpenVulnerableFailsFixedPasses(t *testing.T) {
	const fault = "authz-store-down"

	e := newEnvFaults(t, lab.ModeVulnerable, fixture.OrdersTwoTenant(), []string{fault})
	rep := e.run(t, scenarioByID(t, "API-BAS-GWAY-011"), e.state)
	if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable under fault got %s / %s (%s), want FAIL / exploited",
			rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
	}

	e = newEnvFaults(t, lab.ModeFixed, fixture.OrdersTwoTenant(), []string{fault})
	rep = e.run(t, scenarioByID(t, "API-BAS-GWAY-011"), e.state)
	if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed under fault got %s / %s (%s), want PASS / enforced",
			rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason)
	}
}

// Every gateway flaw must be registered against its scenario.
func TestPhase23_GatewayFlawsAreRegistered(t *testing.T) {
	want := map[string]bool{"API-BAS-GWAY-011": false}
	for _, id := range gatewayScenarios {
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
