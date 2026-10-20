package runner_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 8 tranche: export access, negative quantity, integration secret.
func TestPhase8_VulnerableFailsFixedPasses(t *testing.T) {
	for _, id := range []string{"API-BAS-AUTHZ-012", "API-BAS-BIZ-002", "API-BAS-INTEG-008"} {
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

// The negative-quantity attack must be refused with 400 by the fixed build, and
// the owner's own PATCH response must not echo protected values.
func TestPhase8_FixedRefusesNegativeQuantity(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-BIZ-002"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Status != http.StatusBadRequest {
		t.Fatalf("fixed negative quantity status=%d, want 400", attack.Status)
	}
}

// The integration secret must only leave the lab in the vulnerable build, and
// the fixed build must not include it in any response body.
func TestPhase8_IntegrationSecretOnlyWhenVulnerable(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-INTEG-008"), e.state)
	for _, ex := range rep.Exchanges {
		if strings.Contains(ex.Body, "BAS-SIM-WHSEC") && ex.Status != http.StatusOK {
			t.Fatalf("fixed build leaked a secret in a %d response", ex.Status)
		}
	}
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Status != http.StatusForbidden || strings.Contains(attack.Body, "BAS-SIM-WHSEC") {
		t.Fatalf("fixed non-owner integration status=%d body=%q, want 403 with no secret", attack.Status, attack.Body)
	}
}
