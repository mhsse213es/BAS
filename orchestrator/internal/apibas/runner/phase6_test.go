package runner_test

import (
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 6 tranche: vertical escalation through a three-step chain.
func TestPhase6_EscalationFailsOnVulnerablePassesOnFixed(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-AUTHZ-004"), e.state)
	if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("got %s / %s (%s), want FAIL / exploited",
			rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
	}
	// The whole chain ran: baseline, setup (succeeded), final attack.
	if len(rep.Exchanges) != 3 {
		t.Fatalf("vulnerable chain ran %d exchanges, want 3", len(rep.Exchanges))
	}
	if setup := rep.Exchanges[1]; setup.Status != http.StatusOK {
		t.Errorf("setup status = %d, want 200 on the vulnerable build", setup.Status)
	}
	if final := rep.Exchanges[2]; final.Status != http.StatusOK {
		t.Errorf("final attack status = %d, want 200 after escalation", final.Status)
	}
}

func TestPhase6_EscalationFixedStopsAtSetup(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-AUTHZ-004"), e.state)
	if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
		t.Fatalf("got %s / %s (%s), want PASS / enforced",
			rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason)
	}
	// The chain stops at the refused setup step, so the final attack is never sent.
	if len(rep.Exchanges) != 2 {
		t.Fatalf("fixed chain ran %d exchanges, want 2 (baseline and refused setup)", len(rep.Exchanges))
	}
	if setup := rep.Exchanges[1]; setup.StepID != "setup-self-assign-admin-role" || setup.Status != http.StatusForbidden {
		t.Fatalf("refused step = %s status %d, want setup-self-assign-admin-role 403", setup.StepID, setup.Status)
	}
}
