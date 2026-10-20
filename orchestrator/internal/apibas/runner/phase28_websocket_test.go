package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/protocol"
)

// Phase 28 WebSocket acceptance (AUTHN-011). The baseline is a successful handshake (101), which the
// scenario declares explicitly. The vulnerable build streams the order with its protected values to a
// foreign-origin, unauthenticated client: FAIL exploited. The fixed build refuses with 403 before the
// upgrade and sends no frame: PASS enforced.
func TestPhase28_WebSocketAUTHN011VulnerableFailsFixedPasses(t *testing.T) {
	s := scenarioByID(t, "API-BAS-AUTHN-011")

	vuln := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rv := vuln.run(t, s, vuln.state)
	if rv.Outcome.Result != grade.FAIL || rv.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable AUTHN-011 = %s/%s, want FAIL/exploited (detail: %s)", rv.Outcome.Result, rv.Outcome.Exploitability, rv.Detail)
	}

	fixed := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rf := fixed.run(t, s, fixed.state)
	if rf.Outcome.Result != grade.PASS || rf.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed AUTHN-011 = %s/%s, want PASS/enforced (detail: %s)", rf.Outcome.Result, rf.Outcome.Control, rf.Detail)
	}
}

// Every WebSocket handshake in the catalog must pass the RFC 6455 handshake checks.
func TestPhase28_WebSocketCatalogHandshakesValidate(t *testing.T) {
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	a := protocol.WebSocket{}
	n := 0
	for _, s := range all {
		if s.Protocol != "websocket" {
			continue
		}
		for _, st := range s.Steps {
			n++
			if err := a.ValidateHandshake(st.Method, st.Headers); err != nil {
				t.Fatalf("%s step %s handshake: %v", s.ID, st.ID, err)
			}
		}
	}
	if n == 0 {
		t.Fatal("no websocket steps found in the catalog")
	}
}
