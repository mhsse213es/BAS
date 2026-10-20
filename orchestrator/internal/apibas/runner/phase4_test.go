package runner_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 4 tranche: retired API version, SSRF via webhook test, error leakage.
// Each must FAIL against the planted flaw and PASS against the fixed build.
func TestPhase4_VulnerableFailsFixedPasses(t *testing.T) {
	for _, id := range []string{"API-BAS-DISC-002", "API-BAS-INTEG-003", "API-BAS-DATA-003"} {
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

// The SSRF attack must really name the internal record. On the vulnerable build
// the lab fetches it, so the response carries the record's protected values;
// on the fixed build the request is refused before any fetch.
func TestPhase4_SSRFTargetsInternalRecord(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-INTEG-003"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Method != http.MethodPost || attack.Status != http.StatusOK {
		t.Fatalf("vulnerable attack method=%s status=%d, want POST 200", attack.Method, attack.Status)
	}
	if attack.Leaked == 0 {
		t.Fatalf("vulnerable build did not return the internal record")
	}
}

func TestPhase4_FixedSSRFRefusedBeforeFetch(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-INTEG-003"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Status != http.StatusForbidden || strings.Contains(attack.Body, "BAS-SIM") {
		t.Fatalf("fixed SSRF status=%d body=%q, want 403 with no record", attack.Status, attack.Body)
	}
}

// The retired route is refused by the fixed build by not being mounted.
func TestPhase4_RetiredRouteAbsentFromFixedBuild(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-DISC-002"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Status != http.StatusNotFound {
		t.Fatalf("retired route status on fixed build = %d, want 404", attack.Status)
	}
}

// The fixed error is generic: it carries no record data.
func TestPhase4_FixedErrorIsGeneric(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-DATA-003"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Status != http.StatusBadRequest || strings.Contains(attack.Body, "record") {
		t.Fatalf("fixed error status=%d body=%q, want generic 400", attack.Status, attack.Body)
	}
}
