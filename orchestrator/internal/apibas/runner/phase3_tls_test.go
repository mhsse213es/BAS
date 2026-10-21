package runner_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/runner"
)

// Decision (recorded in the QA log): both builds complete the TLS handshake. The fixed build then refuses at the
// application layer with the status the scenario declares. A handshake failure is a transport error and grades ERROR,
// never PASS or FAIL, because the control under test was never reached.

// tlsEnv is a lab on a TLS listener, with a rogue upstream whose certificate the runner does not trust.
type tlsEnv struct {
	url, rogue string
	fx         fixture.Fixture
	admin      runner.LabAdmin
	secrets    runner.MapSecrets
	pki        *lab.PKI
	roots      *x509.CertPool
	certs      map[string]tls.Certificate
	state      runner.StateReader
}

// newTLSEnv starts the lab with TLS. trust sets whether the runner trusts the lab CA. withCerts sets whether the
// runner is given the named client certificates.
func newTLSEnv(t *testing.T, mode lab.Mode, fx fixture.Fixture, trust, withCerts bool) *tlsEnv {
	t.Helper()
	pki, err := lab.NewPKI()
	if err != nil {
		t.Fatalf("NewPKI: %v", err)
	}
	tokA, tokB, adminTok := randomToken(t), randomToken(t), randomToken(t)
	l, err := lab.New(lab.Config{
		Mode:          mode,
		Fixture:       fx,
		Tokens:        map[string]string{tokA: "cust-a", tokB: "cust-b"},
		AdminToken:    adminTok,
		ClientCAs:     pki.CAPool,
		UpstreamRoots: pki.CAPool,
	})
	if err != nil {
		t.Fatalf("lab.New: %v", err)
	}
	srv := httptest.NewUnstartedServer(l.Handler())
	srv.TLS = l.TLSConfig(pki.Server)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	rogue := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"probe": "BAS-UPSTREAM-PROBE"})
	}))
	t.Cleanup(rogue.Close)

	roots := pki.CAPool
	if !trust {
		roots = x509.NewCertPool()
	}
	admin := runner.NewLabAdmin(srv.URL, adminTok)
	admin.HTTP = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pki.CAPool}}}

	e := &tlsEnv{
		url: srv.URL, rogue: rogue.URL, fx: fx, admin: admin, pki: pki, roots: roots, state: admin,
		secrets: runner.MapSecrets{"apibas/lab/customer-a": tokA, "apibas/lab/customer-b": tokB},
	}
	if withCerts {
		trusted, err := pki.IssueClientCert("cust-b")
		if err != nil {
			t.Fatalf("issue trusted cert: %v", err)
		}
		forged, err := lab.SelfSignedClientCert("cust-a")
		if err != nil {
			t.Fatalf("forge cert: %v", err)
		}
		e.certs = map[string]tls.Certificate{"trusted-cust-b": trusted, "forged-cust-a": forged}
	}
	return e
}

func (e *tlsEnv) run(t *testing.T, s contract.Scenario) runner.Report {
	t.Helper()
	httpClient := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.roots}}}
	r, err := runner.New(runner.Config{
		BaseURL:     e.url,
		Fixture:     e.fx,
		Secrets:     e.secrets,
		State:       e.state,
		Reset:       e.admin,
		Events:      e.admin,
		Faults:      e.admin,
		HTTP:        httpClient,
		RootCAs:     e.roots,
		ClientCerts: e.certs,
		RogueURL:    e.rogue,
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}
	rep, err := r.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

// phase3TLSScope are the two TLS-dependent scenarios.
var phase3TLSScope = []string{"API-BAS-AUTHN-007", "API-BAS-GWAY-012"}

func tlsScenario(t *testing.T, id string) contract.Scenario {
	t.Helper()
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	for _, s := range all {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("%s not in the catalog", id)
	return contract.Scenario{}
}

// TestPhase3_TLSAcceptance runs AUTHN-007 and GWAY-012 in both builds: vulnerable FAIL/exploited, fixed PASS/enforced.
func TestPhase3_TLSAcceptance(t *testing.T) {
	if testing.Short() {
		t.Skip("TLS batch skipped in -short mode")
	}
	for _, id := range phase3TLSScope {
		s := tlsScenario(t, id)
		fx := fixtureFor(t, s.Preconditions.Fixture)
		for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
			e := newTLSEnv(t, mode, fx, true, true)
			o := e.run(t, s).Outcome
			if mode == lab.ModeVulnerable {
				if o.Result != grade.FAIL || o.Exploitability != grade.Exploited {
					t.Errorf("%s vulnerable: %s/%s (%s), want FAIL/exploited", id, o.Result, o.Exploitability, o.Reason)
				}
			} else if o.Result != grade.PASS || o.Control != grade.Enforced {
				t.Errorf("%s fixed: %s/%s (%s), want PASS/enforced", id, o.Result, o.Control, o.Reason)
			}
		}
	}
}

// Both builds establish TLS, including with a forged client certificate. The handshake is never the refusal point.
func TestTLS_BothBuildsCompleteHandshake(t *testing.T) {
	fx := fixtureFor(t, "orders-two-tenant")
	forged, err := lab.SelfSignedClientCert("cust-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		e := newTLSEnv(t, mode, fx, true, true)
		conn, err := tls.Dial("tcp", e.url[len("https://"):], &tls.Config{
			RootCAs:      e.roots,
			Certificates: []tls.Certificate{forged},
		})
		if err != nil {
			t.Fatalf("%s: handshake failed: %v", modeName(mode), err)
		}
		if !conn.ConnectionState().HandshakeComplete {
			t.Errorf("%s: handshake did not complete", modeName(mode))
		}
		conn.Close()
	}
}

// The fixed build refuses a forged client certificate at the application layer: a 401, not a transport error.
func TestTLS_FixedRefusesForgedCertAtApplicationLayer(t *testing.T) {
	s := tlsScenario(t, "API-BAS-AUTHN-007")
	fx := fixtureFor(t, s.Preconditions.Fixture)
	rep := newTLSEnv(t, lab.ModeFixed, fx, true, true).run(t, s)
	last := rep.Exchanges[len(rep.Exchanges)-1]
	if last.Status != http.StatusUnauthorized {
		t.Fatalf("forged cert: status %d, want 401 from the application", last.Status)
	}
	if rep.Outcome.Reason == grade.ReasonTargetUnreachable {
		t.Fatal("forged cert was graded as a transport failure")
	}
}

// The fixed build refuses an untrusted upstream at the application layer: a 422, after a completed handshake.
func TestTLS_FixedRefusesUntrustedUpstreamAtApplicationLayer(t *testing.T) {
	s := tlsScenario(t, "API-BAS-GWAY-012")
	fx := fixtureFor(t, s.Preconditions.Fixture)
	rep := newTLSEnv(t, lab.ModeFixed, fx, true, true).run(t, s)
	last := rep.Exchanges[len(rep.Exchanges)-1]
	if last.Status != http.StatusUnprocessableEntity {
		t.Fatalf("untrusted upstream: status %d, want 422 from the application", last.Status)
	}
}

// A handshake the runner cannot complete (it does not trust the lab CA) is ERROR, never PASS.
func TestTLS_HandshakeFailureIsErrorNeverPass(t *testing.T) {
	s := tlsScenario(t, "API-BAS-AUTHN-007")
	fx := fixtureFor(t, s.Preconditions.Fixture)
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		o := newTLSEnv(t, mode, fx, false, true).run(t, s).Outcome
		if o.Result != grade.ERROR {
			t.Errorf("%s: untrusted lab CA graded %s (%s), want ERROR", modeName(mode), o.Result, o.Reason)
		}
	}
}

// A client certificate the runner was not given is a configuration failure: ERROR, never a control result.
func TestTLS_MissingClientCertIsErrorNeverResult(t *testing.T) {
	s := tlsScenario(t, "API-BAS-AUTHN-007")
	fx := fixtureFor(t, s.Preconditions.Fixture)
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		o := newTLSEnv(t, mode, fx, true, false).run(t, s).Outcome
		if o.Result == grade.PASS || o.Result == grade.FAIL {
			t.Errorf("%s: missing cert graded %s, want ERROR or SKIPPED", modeName(mode), o.Result)
		}
	}
}
