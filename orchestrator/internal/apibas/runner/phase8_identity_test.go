package runner_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Identity attribution end to end. Each request carries one correlation ID, its access event is read back the way the runner
// reads it, and REL-013 is judged by the same detector the runner uses.

const idRun = "id-run"

// idCall sends one request with the given headers under the correlation ID and returns the access events it produced.
func idCall(t *testing.T, e *env, method, path string, headers map[string]string) []detect.Event {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, e.srv.URL+path, strings.NewReader("{}"))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-BAS-Run", idRun)
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	resp.Body.Close()
	events, err := e.admin.AccessEvents(context.Background(), idRun)
	if err != nil {
		t.Fatalf("access events: %v", err)
	}
	return events
}

// rel013Fired reports whether REL-013 fires on the events.
func rel013Fired(events []detect.Event) bool {
	f := detect.NewElasticFixture()
	if err := f.Ingest(events); err != nil {
		panic(err)
	}
	for _, a := range f.Alerts(idRun) {
		if a.RuleID == "APIBAS-REL-013" {
			return true
		}
	}
	return false
}

// tokenFor is the signed lab token of a named identity, resolved the way the runner resolves credentials.
func tokenFor(t *testing.T, e *env, identity string) string {
	t.Helper()
	tok, err := e.secrets.Resolve("apibas/lab/" + identity)
	if err != nil {
		t.Fatalf("%s token: %v", identity, err)
	}
	return tok
}

// forgedToken is the alg-none token AUTHN-003 presents, naming customer-b.
func forgedToken(sub string) string {
	enc := base64.RawURLEncoding.EncodeToString
	hdr, _ := json.Marshal(map[string]string{"alg": "none"})
	pl, _ := json.Marshal(map[string]string{"sub": sub})
	return enc(hdr) + "." + enc(pl) + "."
}

// AUTHN-003, vulnerable: the forged subject is recorded as a claim. It is not proof, so REL-013 fires.
func TestPhase8_ForgedTokenRecordedAsClaim(t *testing.T) {
	e := newEnvWith(t, lab.ModeVulnerable, fixture.OrdersTwoTenant(), nil, false)
	events := idCall(t, e, http.MethodGet, "/api/orders/ORD-2001", map[string]string{"Authorization": "Bearer " + forgedToken("cust-b")})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Identity != "cust-b" || ev.IdentityBasis != "unsigned_token_claim" || ev.ClaimedIdentity != "cust-b" || ev.VerifiedIdentity != "" {
		t.Errorf("event identity = %q basis %q claim %q verified %q; want cust-b, unsigned_token_claim, cust-b, empty",
			ev.Identity, ev.IdentityBasis, ev.ClaimedIdentity, ev.VerifiedIdentity)
	}
	if !rel013Fired(events) {
		t.Error("REL-013 did not fire on a forged subject accepted by the vulnerable build")
	}
}

// AUTHN-003, fixed: the unsigned token is refused and no identity is established.
func TestPhase8_ForgedTokenRefusedFixedHasNoIdentity(t *testing.T) {
	e := newEnvWith(t, lab.ModeFixed, fixture.OrdersTwoTenant(), nil, false)
	events := idCall(t, e, http.MethodGet, "/api/orders/ORD-2001", map[string]string{"Authorization": "Bearer " + forgedToken("cust-b")})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].IdentityBasis != "" || events[0].ClaimedIdentity != "" {
		t.Errorf("refused token recorded basis %q claim %q", events[0].IdentityBasis, events[0].ClaimedIdentity)
	}
	if rel013Fired(events) {
		t.Error("REL-013 fired on a refused token")
	}
}

// The X-Customer-Id header the vulnerable build honours is recorded as a header claim beside the proven identity, and REL-013
// fires on the mismatch.
func TestPhase8_HeaderClaimRecordedBesideProof(t *testing.T) {
	e := newEnvWith(t, lab.ModeVulnerable, fixture.OrdersTwoTenant(), nil, false)
	events := idCall(t, e, http.MethodGet, "/api/orders/ORD-2001", map[string]string{
		"Authorization": "Bearer " + tokenFor(t, e, "customer-a"),
		"X-Customer-Id": "cust-b",
	})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.IdentityBasis != "header_claim" || ev.ClaimedIdentity != "cust-b" || ev.VerifiedIdentity != "cust-a" {
		t.Errorf("event basis %q claim %q verified %q; want header_claim, cust-b, cust-a", ev.IdentityBasis, ev.ClaimedIdentity, ev.VerifiedIdentity)
	}
	if !rel013Fired(events) {
		t.Error("REL-013 did not fire on a header claim that differs from the proven identity")
	}
}

// A signed token is recorded as proof, with no claim, and REL-013 does not fire.
func TestPhase8_SignedTokenIsProofWithoutClaim(t *testing.T) {
	e := newEnvWith(t, lab.ModeFixed, fixture.OrdersTwoTenant(), nil, false)
	events := idCall(t, e, http.MethodGet, "/api/orders/ORD-2001", map[string]string{
		"Authorization": "Bearer " + tokenFor(t, e, "customer-b"),
	})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.IdentityBasis != "signed_token" || ev.ClaimedIdentity != "" || ev.Identity != ev.VerifiedIdentity {
		t.Errorf("event basis %q claim %q identity %q verified %q", ev.IdentityBasis, ev.ClaimedIdentity, ev.Identity, ev.VerifiedIdentity)
	}
	if rel013Fired(events) {
		t.Error("REL-013 fired on a signed-token request")
	}
}
