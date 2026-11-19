package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// The retail, logistics and telecom pack's scenarios, run through the existing grader in both builds on
// fixture.CommerceTelecomTwoTenant. The vulnerable build must FAIL as exploited. The fixed build must PASS with control enforced.
var commerceScenarios = []string{
	"API-BAS-AUTHZ-401", // RET-001: shopper tracks another shopper's shipment
	"API-BAS-AUTHZ-402", // RET-002: shopper redirects another shopper's shipment
	"API-BAS-AUTHZ-403", // TEL-001: SIM swap on another subscriber's line
	"API-BAS-DATA-401",  // TEL-002: usage listing includes other subscribers' call logs
	"API-BAS-DATA-402",  // TEL-003: subscriber reads another subscriber's record and national ID
	"API-BAS-BIZ-401",   // RET-003: shopper sets the price of their own order
	"API-BAS-INTEG-401", // PART-001: partner reads another partner's API key secret
	"API-BAS-INTEG-402", // PART-002: partner escalates their own API key to write scope
	"API-BAS-INTEG-403", // LOG-001: shopper reports their own shipment delivered through the carrier callback
}

func TestPhase10_CommerceScenariosBothBuilds(t *testing.T) {
	fx := fixture.CommerceTelecomTwoTenant()
	for _, id := range commerceScenarios {
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

// The staff and carrier identities the fixed build relies on are in the fixture with the roles the routes check, so a role
// check is exercised by a real identity rather than by the absence of one.
func TestPhase10_FixtureCarriesTheRolesTheRoutesCheck(t *testing.T) {
	fx := fixture.CommerceTelecomTwoTenant()
	for name, role := range map[string]string{"carrier-1": "carrier", "agent-1": "agent"} {
		id, ok := fx.Identity(name)
		if !ok || id.Role != role {
			t.Errorf("identity %s: found=%t role %q, want %q", name, ok, id.Role, role)
		}
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
