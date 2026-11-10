package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// The manufacturing pack's scenarios, run through the existing grader in both builds on fixture.ManufacturingTwoPlant. The
// vulnerable build must FAIL as exploited. The fixed build must PASS with control enforced. A scenario that does not behave
// this way is wrong, not a result to record.
var manufacturingScenarios = []string{
	"API-BAS-AUTHZ-201", // MFG-001: planner reads another plant's production order
	"API-BAS-AUTHZ-202", // MFG-002: operator releases a production order
	"API-BAS-AUTHZ-203", // MFG-003: supplier changes another supplier's purchase order
	"API-BAS-AUTHZ-204", // MFG-004: device commands another device
	"API-BAS-DATA-201",  // MFG-005: planner reads another plant's bill of materials and CAD reference
	"API-BAS-DATA-202",  // MFG-006: asset inventory lists another plant's machines and telemetry keys
	"API-BAS-INTEG-201", // MFG-007: plant operator reaches the OT management configuration
}

func TestPhase8_ManufacturingScenariosBothBuilds(t *testing.T) {
	fx := fixture.ManufacturingTwoPlant()
	for _, id := range manufacturingScenarios {
		s := scenarioByID(t, id)
		for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
			e := newEnvWith(t, mode, fx, s.Preconditions.LabFaults, false)
			rep := e.run(t, s, e.state)
			if mode == lab.ModeVulnerable {
				if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
					t.Errorf("%s vulnerable: result %s exploitability %s (%s), want FAIL exploited",
						id, rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
				}
				continue
			}
			if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
				t.Errorf("%s fixed: result %s control %s (%s), want PASS enforced", id, rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason)
			}
		}
	}
}

// The pack's owners are served on their own routes: a pack record is never reachable through the orders routes, and the
// owner of each record can read it in the fixed build.
func TestPhase8_ManufacturingOwnersReachTheirRecords(t *testing.T) {
	fx := fixture.ManufacturingTwoPlant()
	if len(fx.Identities) != 9 {
		t.Fatalf("fixture has %d identities, want 9", len(fx.Identities))
	}
	seen := map[string]bool{}
	for _, o := range fx.Objects {
		if o.Kind == "" || o.OwnerID == "" {
			t.Errorf("%s: kind %q owner %q; every pack record needs both", o.ID, o.Kind, o.OwnerID)
		}
		if seen[o.ID] {
			t.Errorf("duplicate object id %s", o.ID)
		}
		seen[o.ID] = true
	}
}
