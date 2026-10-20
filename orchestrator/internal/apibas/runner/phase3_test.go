package runner_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/runner"
)

// Phase 3 tranche: forged unsigned JWT, unbounded collection, method override.
// Each must FAIL against the planted flaw and PASS against the fixed build.
func TestPhase3_VulnerableFailsFixedPasses(t *testing.T) {
	for _, id := range []string{"API-BAS-AUTHN-003", "API-BAS-DATA-004", "API-BAS-GWAY-003"} {
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

// The forged token is refused by the fixed build with 401, and the attack
// request really carried an alg none token.
func TestPhase3_ForgedTokenIsSentAndRefused(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-AUTHN-003"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Auth != "alg_none" || attack.Status != http.StatusUnauthorized {
		t.Fatalf("attack auth=%s status=%d, want alg_none / 401", attack.Auth, attack.Status)
	}
}

// The fixed collection returns the caller's own projection, so the PASS rests
// on a served body, not an empty success.
func TestPhase3_FixedCollectionIsServedAndClean(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-DATA-004"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Status != http.StatusOK || attack.Leaked != 0 {
		t.Fatalf("list status=%d leaked=%d, want 200 and no leak", attack.Status, attack.Leaked)
	}
	if !strings.Contains(attack.Body, "ORD-1001") || strings.Contains(attack.Body, "ORD-2001") {
		t.Fatalf("fixed list should hold only the caller's order; body=%q", attack.Body)
	}
}

// The override must be ignored by the fixed build, which answers 405 to the
// POST, not 200.
func TestPhase3_FixedBuildIgnoresMethodOverride(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-GWAY-003"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Method != http.MethodPost || attack.Status != http.StatusMethodNotAllowed {
		t.Fatalf("attack method=%s status=%d, want POST / 405", attack.Method, attack.Status)
	}
}

// Guard: a lab that knows the revoked token but does not report it as revoked
// is misconfigured. The revoked-token scenario must be an ERROR, and no attack
// traffic may be sent, so a misconfigured lab can never produce a PASS.
func TestPhase3_RevokedGuardRefusesMisconfiguredLab(t *testing.T) {
	fx := fixture.OrdersTwoTenant()
	tokA, tokB, admin, revoked := randomToken(t), randomToken(t), randomToken(t), randomToken(t)
	l, err := lab.New(lab.Config{
		Mode:    lab.ModeFixed,
		Fixture: fx,
		Tokens:  map[string]string{tokA: "cust-a", tokB: "cust-b", revoked: "cust-a"},
		// Revoked is deliberately empty: the token is known but not revoked.
		AdminToken: admin,
	})
	if err != nil {
		t.Fatalf("lab.New: %v", err)
	}
	var apiHits atomic.Int64
	h := l.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiHits.Add(1)
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	admins := runner.NewLabAdmin(srv.URL, admin)
	r, err := runner.New(runner.Config{
		BaseURL: srv.URL,
		Fixture: fx,
		Secrets: runner.MapSecrets{
			"apibas/lab/customer-a":         tokA,
			"apibas/lab/customer-b":         tokB,
			"apibas/lab/customer-a-revoked": revoked,
		},
		State: admins,
		Reset: admins,
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}
	rep, err := r.Run(context.Background(), scenarioByID(t, "API-BAS-AUTHN-002"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcome.Result != grade.ERROR || rep.Outcome.Reason != grade.ReasonLabConfigMismatch {
		t.Fatalf("got %s/%s, want ERROR/%s", rep.Outcome.Result, rep.Outcome.Reason, grade.ReasonLabConfigMismatch)
	}
	if n := apiHits.Load(); n != 0 {
		t.Errorf("%d API requests were sent to a misconfigured lab", n)
	}
}
