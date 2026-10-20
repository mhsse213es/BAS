package runner_test

// Phase 1 acceptance tests (docs/api-bas-blueprint.md section 10, A1-A7).
// These run the real lab over HTTP, so the vulnerable and fixed behaviour is
// what the server actually does, not what a fake returns.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/runner"
)

const scenarioID = "API-BAS-AUTHZ-001"

type env struct {
	url     string
	apiHits *atomic.Int64 // counts requests to /api/ only, so state reads are excluded
	srv     *httptest.Server
	admin   runner.LabAdmin
	secrets runner.MapSecrets
	fx      fixture.Fixture
	scen    contract.Scenario
	state   runner.StateReader // nil disables the ground-truth adapter
}

// newEnv starts a lab in the given mode and wires a runner to it. Tokens are
// random per test: short-lived by construction, never committed.
func newEnv(t *testing.T, mode lab.Mode, fx fixture.Fixture) *env {
	t.Helper()
	tokA, tokB, adminTok := randomToken(t), randomToken(t), randomToken(t)
	l, err := lab.New(lab.Config{
		Mode:       mode,
		Fixture:    fx,
		Tokens:     map[string]string{tokA: "cust-a", tokB: "cust-b"},
		AdminToken: adminTok,
	})
	if err != nil {
		t.Fatalf("lab.New: %v", err)
	}
	hits := &atomic.Int64{}
	h := l.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			hits.Add(1)
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	admin := runner.NewLabAdmin(srv.URL, adminTok)
	secrets := runner.MapSecrets{
		"apibas/lab/customer-a": tokA,
		"apibas/lab/customer-b": tokB,
	}
	return &env{
		url: srv.URL, apiHits: hits, srv: srv, admin: admin, secrets: secrets, fx: fx,
		scen:  loadScenario(t),
		state: admin,
	}
}

func loadScenario(t *testing.T) contract.Scenario {
	t.Helper()
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	for _, s := range all {
		if s.ID == scenarioID {
			return s
		}
	}
	t.Fatalf("scenario %s not in catalog", scenarioID)
	return contract.Scenario{}
}

func (e *env) run(t *testing.T, s contract.Scenario, state runner.StateReader) runner.Report {
	t.Helper()
	r, err := runner.New(runner.Config{
		BaseURL: e.url,
		Fixture: e.fx,
		Secrets: e.secrets,
		State:   state,
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

// A1: against the vulnerable build the planted BOLA must be detected: FAIL,
// exploited, with the owner's protected values shown to be disclosed.
func TestA1_VulnerableBuild_BOLA_Fails(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, e.scen, e.state)

	if rep.Outcome.Result != grade.FAIL {
		t.Fatalf("Result = %s (%s), want FAIL", rep.Outcome.Result, rep.Outcome.Reason)
	}
	if rep.Outcome.Exploitability != grade.Exploited || rep.Outcome.Control != grade.Failed {
		t.Errorf("axes = exploit %s / control %s, want exploited / failed",
			rep.Outcome.Exploitability, rep.Outcome.Control)
	}
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Status != http.StatusOK || attack.Leaked == 0 {
		t.Errorf("attack exchange status=%d leaked=%d, want 200 with disclosure", attack.Status, attack.Leaked)
	}
	for _, ex := range rep.Exchanges {
		for _, raw := range []string{"BAS-SIM-2001", "BAS-SIM-ACC-B"} {
			if strings.Contains(ex.Body, raw) {
				t.Errorf("evidence for step %s still contains raw protected value %s", ex.StepID, raw)
			}
		}
	}
}

// A2: the same scenario against the fixed build must PASS with the control
// enforced and ground truth present.
func TestA2_FixedBuild_PassesWithEvidence(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, e.scen, e.state)

	if rep.Outcome.Result != grade.PASS {
		t.Fatalf("Result = %s (%s), want PASS", rep.Outcome.Result, rep.Outcome.Reason)
	}
	if rep.Outcome.Control != grade.Enforced || rep.Outcome.Exploitability != grade.NotExploited {
		t.Errorf("axes = control %s / exploit %s, want enforced / not_exploited",
			rep.Outcome.Control, rep.Outcome.Exploitability)
	}
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Status != http.StatusForbidden {
		t.Errorf("attack status = %d, want 403", attack.Status)
	}
}

// A3: a stopped lab is an ERROR, never a PASS or a SKIP.
func TestA3_TargetDown_IsError(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	e.srv.Close()
	rep := e.run(t, e.scen, e.state)

	if rep.Outcome.Result != grade.ERROR {
		t.Fatalf("Result = %s, want ERROR", rep.Outcome.Result)
	}
	if rep.Outcome.Reason != grade.ReasonTargetUnreachable {
		t.Errorf("Reason = %s, want %s", rep.Outcome.Reason, grade.ReasonTargetUnreachable)
	}
}

// A4: without the state adapter the scenario is SKIPPED before any request.
func TestA4_NoStateAdapter_SkipsWithoutTraffic(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, e.scen, nil)

	if rep.Outcome.Result != grade.SKIPPED || rep.Outcome.Reason != grade.ReasonAdapterUnavailable {
		t.Fatalf("got %s/%s, want SKIPPED/%s", rep.Outcome.Result, rep.Outcome.Reason, grade.ReasonAdapterUnavailable)
	}
	if n := e.apiHits.Load(); n != 0 {
		t.Errorf("%d API requests were sent for a scenario that could not be graded", n)
	}
}

// A5: an attacker identical to the owner is not a cross-identity claim. It is
// SKIPPED with no attack traffic, so a legitimate self-read cannot become a
// finding.
func TestA5_SameIdentity_NoFinding(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	self := e.scen
	self.Steps = append([]contract.Step(nil), self.Steps...)
	self.Steps[1].Identity = "customer-b" // the owner

	rep := e.run(t, self, e.state)
	if rep.Outcome.Result != grade.SKIPPED || rep.Outcome.Reason != grade.ReasonNotCrossIdentity {
		t.Fatalf("got %s/%s, want SKIPPED/%s", rep.Outcome.Result, rep.Outcome.Reason, grade.ReasonNotCrossIdentity)
	}
	if n := e.apiHits.Load(); n != 0 {
		t.Errorf("%d API requests were sent for a same-identity preflight skip", n)
	}
}

// A6: cleanup removes only records carrying the run tag. Seed data and the
// audit log are never removed.
func TestA6_CleanupTouchesOnlyTaggedRecords(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	ctx := context.Background()

	const runTag = "apibas-run-a6"
	if err := e.admin.CreateTagged(ctx, "ORD-TAG-1", "cust-a", "pending", runTag); err != nil {
		t.Fatalf("CreateTagged: %v", err)
	}

	// A different run's cleanup must not touch this run's record.
	if n, err := e.admin.Cleanup(ctx, "apibas-other"); err != nil || n != 0 {
		t.Fatalf("cleanup of unrelated tag removed %d (err %v), want 0", n, err)
	}
	if n, err := e.admin.Cleanup(ctx, runTag); err != nil || n != 1 {
		t.Fatalf("cleanup of run tag removed %d (err %v), want 1", n, err)
	}

	state, err := e.admin.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, ok := state["ORD-TAG-1"]; ok {
		t.Errorf("tagged record survived cleanup")
	}
	for _, seed := range []string{"ORD-1001", "ORD-2001"} {
		if _, ok := state[seed]; !ok {
			t.Errorf("seed record %s was removed by cleanup", seed)
		}
	}

	audit, err := e.admin.Audit(ctx)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	actions := map[string]bool{}
	for _, a := range audit {
		actions[a["action"].(string)] = true
	}
	for _, want := range []string{"seed", "create", "cleanup"} {
		if !actions[want] {
			t.Errorf("audit log is missing a %q entry; audit must survive cleanup", want)
		}
	}
}

// A7: a 2xx with no disclosure and no state change does not prove the control
// failed. It must be graded inconclusive, never FAIL.
func TestA7_2xxWithoutDisclosure_IsInconclusive(t *testing.T) {
	fx := fixture.OrdersNoProtected()
	e := newEnv(t, lab.ModeVulnerable, fx)
	scen := e.scen
	scen.Preconditions.Fixture = fx.Name

	rep := e.run(t, scen, e.state)
	if rep.Outcome.Result == grade.FAIL || rep.Outcome.Result == grade.PASS {
		t.Fatalf("Result = %s, want SKIPPED (inconclusive); a 2xx alone must not decide", rep.Outcome.Result)
	}
	if rep.Outcome.Reason != grade.ReasonEvidenceInconclusive {
		t.Errorf("Reason = %s, want %s", rep.Outcome.Reason, grade.ReasonEvidenceInconclusive)
	}
}

// Credentials missing from the secret store are a precondition failure, and
// no request is sent.
func TestMissingCredential_IsPreconditionSkip(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	e.secrets = runner.MapSecrets{} // nothing resolvable

	rep := e.run(t, e.scen, e.state)
	if rep.Outcome.Result != grade.SKIPPED || rep.Outcome.Reason != grade.ReasonPreconditionMissing {
		t.Fatalf("got %s/%s, want SKIPPED/%s", rep.Outcome.Result, rep.Outcome.Reason, grade.ReasonPreconditionMissing)
	}
	if n := e.apiHits.Load(); n != 0 {
		t.Errorf("%d API requests were sent without credentials", n)
	}
}

// Evidence must never contain a bearer token, in any outcome.
func TestEvidenceNeverContainsCredentials(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, e.scen, e.state)
	for _, tok := range e.secrets {
		for _, ex := range rep.Exchanges {
			if strings.Contains(ex.Body, tok) || strings.Contains(ex.Path, tok) {
				t.Fatalf("evidence contains a credential")
			}
		}
	}
}

// Every planted flaw must name a scenario that exists in the catalog. An
// orphan flaw would mean the lab proves something no scenario tests.
func TestFlawRegistryLinksToCatalog(t *testing.T) {
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	ids := map[string]bool{}
	for _, s := range all {
		ids[s.ID] = true
	}
	for _, f := range lab.Flaws() {
		if !ids[f.ScenarioID] {
			t.Errorf("flaw %s names scenario %s, which is not in the catalog", f.ID, f.ScenarioID)
		}
	}
}

func randomToken(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b[:])
}
