package runner_test

import (
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 5 tranche: identity confusion via header, bulk authorization.
// Each must FAIL against the planted flaw and PASS against the fixed build.
func TestPhase5_VulnerableFailsFixedPasses(t *testing.T) {
	for _, id := range []string{"API-BAS-AUTHN-008", "API-BAS-AUTHZ-007"} {
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

// The identity-header attack must carry the header, and the vulnerable build
// must act on it: the response then holds the other customer's protected values.
func TestPhase5_IdentityHeaderIsHonouredOnlyWhenVulnerable(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-AUTHN-008"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Status != http.StatusOK || attack.Leaked == 0 {
		t.Fatalf("vulnerable header attack status=%d leaked=%d, want 200 with disclosure", attack.Status, attack.Leaked)
	}
}

// The bulk attack must actually name the foreign order. The fixed build refuses
// the whole batch with 403, including the attacker's own order.
func TestPhase5_FixedBulkRefusesWholeBatch(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-AUTHZ-007"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Method != http.MethodPatch || attack.Status != http.StatusForbidden {
		t.Fatalf("fixed bulk method=%s status=%d, want PATCH 403", attack.Method, attack.Status)
	}
}
