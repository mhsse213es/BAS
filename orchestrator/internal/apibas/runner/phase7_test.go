package runner_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 7 tranche: parent-child item authorization, internal-service credential.
func TestPhase7_VulnerableFailsFixedPasses(t *testing.T) {
	for _, id := range []string{"API-BAS-AUTHZ-006", "API-BAS-INTEG-005"} {
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

// The parent-child attack must really name the foreign item under the caller's
// own parent, and the vulnerable build must return it.
func TestPhase7_ForeignItemReturnedOnlyWhenVulnerable(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-AUTHZ-006"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if !strings.Contains(attack.Body, "ITM-2001-1") || attack.Leaked == 0 {
		t.Fatalf("vulnerable foreign item status=%d leaked=%d body=%q", attack.Status, attack.Leaked, attack.Body)
	}
}

// The fixed build refuses the internal route without the internal-service
// credential, so nothing from it reaches the customer.
func TestPhase7_FixedInternalRouteRefusesCustomerToken(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-INTEG-005"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Status != http.StatusUnauthorized || strings.Contains(attack.Body, "BAS-SIM") {
		t.Fatalf("fixed internal status=%d body=%q, want 401 with no record", attack.Status, attack.Body)
	}
}
