package exec

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/grade"
)

func toySecrets() secretMap {
	return secretMap{"tok-alice": "tok-alice", "tok-bob": "tok-bob", "tok-carol": "tok-carol", "tok-dave": "tok-dave", "tok-erin": "tok-erin"}
}

func toyCreated() []model.CreatedObject {
	return []model.CreatedObject{
		{Operation: "seed", ID: "item-a1", Owner: "cust-a", Compensate: "deleteV2"},
		{Operation: "seed", ID: "item-b1", Owner: "cust-b", Compensate: "deleteV2"},
	}
}

func toyWorkflow() *property.Workflow {
	return &property.Workflow{Name: "approval", SuccessValues: []string{"completed"}, Steps: []property.WorkflowStep{
		{Op: "authorize", Kind: property.StepAuthorize, Role: "checker"},
		{Op: "terms", Kind: property.StepModify},
		{Op: "execute", Kind: property.StepExecute},
		{Op: "reverse", Kind: property.StepReverse},
		{Op: "statusV2", Kind: property.StepRead},
	}}
}

func newExec(t *testing.T, ty *toy, srv *httptest.Server) *Executor {
	t.Helper()
	e, err := New(Config{
		BaseURL: srv.URL, Fixture: toyFixture(), Secrets: toySecrets(), Model: toyModel(),
		Guard:   testGuard(t, srv.URL, toyModel()),
		Created: toyCreated(), StateExtra: ty,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func generated(t *testing.T) []generate.Test {
	t.Helper()
	tests, err := generate.Generate(toyModel(), toyFixture(), toyAccounts(), generate.Options{
		Seed: 1, Catalogue: []contract.Scenario{},
		Workflow:      toyWorkflow(),
		ReservedRoles: map[string]string{"reports": "admin"},
		Limits:        map[string]int{"redeem": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tests
}

// pick returns the first generated test of a property on an operation.
func pick(t *testing.T, prop, opID string) generate.Test {
	t.Helper()
	var seen []string
	for _, ts := range generated(t) {
		if ts.Property == prop && ts.Params["operation"] == opID {
			return ts
		}
		seen = append(seen, ts.Property+"/"+ts.Params["operation"])
	}
	t.Fatalf("no generated test %s on %s; have %v", prop, opID, seen)
	return generate.Test{}
}

func runTest(t *testing.T, ty *toy, srv *httptest.Server, ts generate.Test) Result {
	t.Helper()
	ty.reset()
	res, err := newExec(t, ty, srv).Run(context.Background(), ts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func wantFinding(t *testing.T, res Result, kind property.OracleKind, f Finding) {
	t.Helper()
	if res.Verdict.Oracle != kind {
		t.Fatalf("oracle %s, want %s", res.Verdict.Oracle, kind)
	}
	if res.Verdict.Finding != f {
		t.Fatalf("finding %s (%s), want %s; runner %s/%s %s", res.Verdict.Finding, res.Verdict.Reason, f,
			res.Report.Outcome.Result, res.Report.Outcome.Reason, res.Report.Detail)
	}
}

func TestRunExecutesGeneratedScenarioThroughRunner(t *testing.T) {
	ts := pick(t, "P-OWN-1", "getV2")
	ty, srv := newToy("read-v2")
	defer srv.Close()
	res := runTest(t, ty, srv, ts)
	if res.Report.Outcome.Result != grade.FAIL || len(res.Report.Exchanges) < 2 {
		t.Fatalf("runner did not run the scenario: %+v", res.Report.Outcome)
	}
	wantFinding(t, res, property.OracleRunnerGrade, FindingYes)

	ok, srvOK := newToy()
	defer srvOK.Close()
	res = runTest(t, ok, srvOK, ts)
	if res.Report.Outcome.Result != grade.PASS {
		t.Fatalf("corrected server: %+v", res.Report.Outcome)
	}
	wantFinding(t, res, property.OracleRunnerGrade, FindingNo)
}

func TestUATStateReaderDetectsModification(t *testing.T) {
	ty, srv := newToy()
	defer srv.Close()
	e := newExec(t, ty, srv)
	before, err := e.State().Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rec := before["item-a1"]
	if rec.Status != "pending" || rec.OwnerID != "cust-a" || rec.Quantity != "10" || rec.Tag == "" {
		t.Fatalf("generic mapping failed: %+v", rec)
	}
	again, _ := e.State().Snapshot(context.Background())
	if again["item-a1"] != rec {
		t.Fatal("snapshot is not stable")
	}
	// A change to a field that has no StateRecord column (title) must still show.
	ty.mu.Lock()
	ty.items["item-a1"].Title = "changed"
	ty.mu.Unlock()
	after, _ := e.State().Snapshot(context.Background())
	if after["item-a1"] == rec || after["item-a1"].Tag == rec.Tag {
		t.Fatal("modification of an unmapped field was not detected")
	}
	// Removal shows as an absent record.
	ty.mu.Lock()
	delete(ty.items, "item-b1")
	ty.mu.Unlock()
	gone, _ := e.State().Snapshot(context.Background())
	if _, ok := gone["item-b1"]; ok {
		t.Fatal("deleted object still present")
	}
}

func TestCompensatingResetDeletesOnlyTaggedObjects(t *testing.T) {
	ty, srv := newToy()
	defer srv.Close()
	e := newExec(t, ty, srv)
	// Reset alone must not touch the shared fixture objects.
	if err := e.Resetter().Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(ty.items) != 5 {
		t.Fatalf("Reset removed fixture objects: %d left", len(ty.items))
	}
	// A tracked run-created object is removed by Reset.
	ty.mu.Lock()
	ty.items["inv-9"] = &titem{ID: "inv-9", Owner: "cust-a"}
	ty.mu.Unlock()
	e.Track(model.CreatedObject{Operation: "invoice", ID: "inv-9", Owner: "cust-a", Compensate: "deleteV2"})
	if err := e.Resetter().Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := ty.items["inv-9"]; ok {
		t.Fatal("tracked object not compensated")
	}
	// Cleanup removes Created only; carol and dave's objects were never ours.
	if err := e.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"item-a1", "item-b1"} {
		if _, ok := ty.items[id]; ok {
			t.Fatalf("%s not compensated", id)
		}
	}
	for _, id := range []string{"item-c1", "item-d1"} {
		if _, ok := ty.items[id]; !ok {
			t.Fatalf("%s was deleted but was never created by ALEEF", id)
		}
	}
	// Idempotent: the server now answers 404 for the compensated objects.
	if err := e.Cleanup(context.Background()); err != nil {
		t.Fatalf("second cleanup must not error: %v", err)
	}
	if len(e.Orphans()) != 0 {
		t.Fatalf("orphans: %v", e.Orphans())
	}
}

func TestResetFailureSurfacesOrphansAndReasonCleanupFailed(t *testing.T) {
	ty, srv := newToy()
	defer srv.Close()
	e, err := New(Config{
		BaseURL: srv.URL, Fixture: toyFixture(), Secrets: toySecrets(), Model: toyModel(),
		Guard: testGuard(t, srv.URL, toyModel()),
		Created: []model.CreatedObject{
			{Operation: "seed", ID: "item-a1", Owner: "cust-a", Compensate: "deleteV2"},
			{Operation: "seed", ID: "item-b1", Owner: "cust-b"},                         // no Compensate
			{Operation: "seed", ID: "item-c1", Owner: "cust-a", Compensate: "deleteV2"}, // wrong owner: refused
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = e.Cleanup(context.Background())
	if err == nil || !errors.Is(err, ErrCleanupFailed) || !strings.Contains(err.Error(), "CLEANUP_FAILED") {
		t.Fatalf("want CLEANUP_FAILED, got %v", err)
	}
	orphans := e.Orphans()
	if len(orphans) != 2 {
		t.Fatalf("orphans: %v", orphans)
	}
	if _, ok := ty.items["item-c1"]; !ok {
		t.Fatal("refused compensation must leave the object")
	}
	// Surfaced through the runner: an object tracked during the run cannot be
	// compensated, so the post-run reset fails.
	mut := pick(t, "P-AUTH-2", "terms")
	ty.reset()
	var e2 *Executor
	var once atomic.Bool
	hc := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method == "PATCH" && once.CompareAndSwap(false, true) {
			e2.Track(model.CreatedObject{Operation: "x", ID: "ghost", Owner: "cust-b"}) // no Compensate
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	e2, err = New(Config{BaseURL: srv.URL, Fixture: toyFixture(), Secrets: toySecrets(), Model: toyModel(),
		Guard: testGuard(t, srv.URL, toyModel()), Created: toyCreated(), HTTP: hc})
	if err != nil {
		t.Fatal(err)
	}
	res, err := e2.Run(context.Background(), mut)
	if err != nil {
		t.Fatal(err)
	}
	if res.Report.Outcome.Reason != "CLEANUP_FAILED" || res.Verdict.Finding != FindingInconclusive || res.Report.Reset != "failed" {
		t.Fatalf("got %+v / %+v / reset=%q", res.Report.Outcome, res.Verdict, res.Report.Reset)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNewRefusesBaseURLOutsideEngagement(t *testing.T) {
	g := testGuard(t, "http://127.0.0.1:8080", toyModel())
	for _, u := range []string{"http://example.com", "https://10.1.2.3:8443", "http://192.168.0.5", "ftp://127.0.0.1", "127.0.0.1", "",
		"http://127.0.0.1:8081", "https://127.0.0.1:8080", "http://u@127.0.0.1:8080", "http://localhost:8080"} {
		if _, err := New(Config{BaseURL: u, Fixture: toyFixture(), Secrets: toySecrets(), Model: toyModel(), Guard: g}); err == nil {
			t.Errorf("%q must be refused", u)
		}
	}
	if _, err := New(Config{BaseURL: "http://127.0.0.1:8080", Fixture: toyFixture(), Secrets: toySecrets(), Model: toyModel(), Guard: g}); err != nil {
		t.Errorf("engagement host refused: %v", err)
	}
}

func TestExecRequiresGuard(t *testing.T) {
	_, err := New(Config{BaseURL: "http://127.0.0.1:8080", Fixture: toyFixture(), Secrets: toySecrets(), Model: toyModel()})
	if err == nil || !strings.Contains(err.Error(), "Guard") {
		t.Fatalf("got %v", err)
	}
}

type doerFn func(*http.Request) (*http.Response, error)

func (f doerFn) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestExecWrapsCustomDoer(t *testing.T) {
	var reached atomic.Int32
	d := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		reached.Add(1)
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}}, nil
	})}
	g := testGuard(t, "http://127.0.0.1:8080", toyModel())
	created := []model.CreatedObject{{Operation: "seed", ID: "item-a1", Owner: "cust-a", Compensate: "deleteV2"}}
	e, err := New(Config{BaseURL: "http://127.0.0.1:8080", Fixture: toyFixture(), Secrets: toySecrets(), Model: toyModel(),
		Guard: g, Doer: d, Created: created})
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup sends through the custom client, and the guard saw it.
	if err := e.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reached.Load() != 1 || g.Stats().CleanupRequests != 1 {
		t.Fatalf("reached=%d stats=%+v", reached.Load(), g.Stats())
	}
	// Once stopped, state reads never reach the custom client.
	g.Stop()
	reached.Store(0)
	e2, err := New(Config{BaseURL: "http://127.0.0.1:8080", Fixture: toyFixture(), Secrets: toySecrets(), Model: toyModel(),
		Guard: g, Doer: d, Created: created})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2.State().Snapshot(context.Background()); err == nil {
		t.Fatal("snapshot succeeded through a stopped guard")
	}
	if reached.Load() != 0 {
		t.Fatalf("custom client reached %d times after stop", reached.Load())
	}
}

func TestNewRefusesNonClientDoer(t *testing.T) {
	g := testGuard(t, "http://127.0.0.1:8080", toyModel())
	d := doerFn(func(r *http.Request) (*http.Response, error) { t.Fatal("must never be called"); return nil, nil })
	if _, err := New(Config{BaseURL: "http://127.0.0.1:8080", Fixture: toyFixture(), Secrets: toySecrets(), Model: toyModel(),
		Guard: g, Doer: d}); err == nil {
		t.Fatal("custom struct Doer accepted")
	}
}

func TestClientDoerNeverFollowsRedirects(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewServer(http_counter(&otherHits, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer redir.Close()
	e, err := New(Config{BaseURL: redir.URL, Fixture: toyFixture(), Secrets: toySecrets(), Model: toyModel(),
		Guard: testGuard(t, redir.URL, toyModel()), Doer: &http.Client{}, Created: toyCreated()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.State().Snapshot(context.Background()); err == nil {
		t.Fatal("redirect treated as readable object")
	}
	if otherHits.Load() != 0 {
		t.Fatalf("redirect target received %d requests", otherHits.Load())
	}
}

func TestRunRefusesClientCertStepsBeforeAnyRequest(t *testing.T) {
	ty, srv := newToy()
	defer srv.Close()
	var hits atomic.Int32
	counting := httptest.NewServer(http_counter(&hits, srv.Config.Handler))
	defer counting.Close()
	e := newExec(t, ty, counting)
	base := pick(t, "P-OWN-1", "getV2")
	hits.Store(0)
	mk := func(f func(*generate.Test)) generate.Test {
		c := base
		c.Scenario.Steps = append([]contract.Step(nil), base.Scenario.Steps...)
		f(&c)
		return c
	}
	cases := map[string]generate.Test{
		"step": mk(func(c *generate.Test) { c.Scenario.Steps[0].ClientCert = "forged" }),
		"control": mk(func(c *generate.Test) {
			oc := base
			oc.Scenario.Steps = append([]contract.Step(nil), base.Scenario.Steps...)
			oc.Scenario.Steps[0].ClientCert = "forged"
			c.OwnerControl = &oc
		}),
	}
	for name, ts := range cases {
		if _, err := e.Run(context.Background(), ts); err == nil || !strings.Contains(err.Error(), "client-certificate") {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests sent", hits.Load())
	}
}

func TestExecGuardRefusalsAreEnforcedOnRunnerPath(t *testing.T) {
	ty, srv := newToy()
	defer srv.Close()
	var hits atomic.Int32
	counting := httptest.NewServer(http_counter(&hits, srv.Config.Handler))
	defer counting.Close()
	e := newExec(t, ty, counting)
	e.cfg.Guard.Stop()
	hits.Store(0)
	res, err := e.Run(context.Background(), pick(t, "P-OWN-1", "getV2"))
	if hits.Load() != 0 {
		t.Fatalf("%d requests reached the target after Stop (err=%v res=%+v)", hits.Load(), err, res.Verdict)
	}
	if err == nil && res.Verdict.Finding == FindingYes {
		t.Fatal("a stopped run produced a finding")
	}
}

func TestSoftFailure200ErrorBodyNotCountedAsAccess(t *testing.T) {
	ts := pick(t, "P-ROLE-1", "reports")
	if ts.Template.Oracle != property.OracleRepeatAccepted {
		t.Fatalf("oracle %s", ts.Template.Oracle)
	}
	// Correct role check that answers 200 {"error":...}: a refusal.
	ty, srv := newToy("soft")
	defer srv.Close()
	wantFinding(t, runTest(t, ty, srv, ts), property.OracleRepeatAccepted, FindingNo)
	// Real flaw (no role check) is still a finding.
	ty2, srv2 := newToy("role")
	defer srv2.Close()
	wantFinding(t, runTest(t, ty2, srv2, ts), property.OracleRepeatAccepted, FindingYes)
}

func TestRunRefusesInvalidScenarioWithoutSending(t *testing.T) {
	var hits atomic.Int32
	ty, srv := newToy()
	defer srv.Close()
	counting := httptest.NewServer(http_counter(&hits, srv.Config.Handler))
	defer counting.Close()
	e := newExec(t, ty, counting)
	hits.Store(0)
	_, err := e.Run(context.Background(), generate.Test{ID: "bad"})
	if err == nil || hits.Load() != 0 {
		t.Fatalf("err=%v hits=%d", err, hits.Load())
	}
}

func TestLeakEchoInRequestIsInconclusive(t *testing.T) {
	ts := pick(t, "P-OWN-1", "getV2")
	ty, srv := newToy("read-v2")
	defer srv.Close()
	wantFinding(t, runTest(t, ty, srv, ts), property.OracleRunnerGrade, FindingYes)

	// Same leak, but the attacker also sent the victim's canary in the URL.
	echo := ts
	echo.Scenario.Steps = append([]contract.Step(nil), ts.Scenario.Steps...)
	canary := toyFixture().Objects[0].Protected["canary"]
	for _, o := range toyFixture().Objects {
		if o.ID == ts.Scenario.Preconditions.Object {
			canary = o.Protected["canary"]
		}
	}
	last := len(echo.Scenario.Steps) - 1
	echo.Scenario.Steps[last].Path += "?q=" + canary + "&o=" + strings.Join(ts.Template.ForbiddenValues, "&o=")
	res := runTest(t, ty, srv, echo)
	wantFinding(t, res, property.OracleRunnerGrade, FindingInconclusive)
	if res.Verdict.Reason != "value present in request" {
		t.Fatalf("reason %q", res.Verdict.Reason)
	}
}

// ---- one test per oracle kind, on flawed and corrected toy servers ----

func TestOracleStateChange(t *testing.T) {
	ts := pick(t, "P-AUTH-2", "terms")
	bad, s1 := newToy("tamper")
	defer s1.Close()
	wantFinding(t, runTest(t, bad, s1, ts), property.OracleStateChange, FindingYes)
	ok, s2 := newToy()
	defer s2.Close()
	wantFinding(t, runTest(t, ok, s2, ts), property.OracleStateChange, FindingNo)
}

func TestOracleRepeatAccepted(t *testing.T) {
	ts := pick(t, "P-ROLE-1", "reports")
	bad, s1 := newToy("role")
	defer s1.Close()
	wantFinding(t, runTest(t, bad, s1, ts), property.OracleRepeatAccepted, FindingYes)
	ok, s2 := newToy()
	defer s2.Close()
	wantFinding(t, runTest(t, ok, s2, ts), property.OracleRepeatAccepted, FindingNo)
}

func TestOracleStateChangeOnReplay(t *testing.T) {
	ts := pick(t, "P-IDEM-1", "invoice")
	bad, s1 := newToy("idem-ignore")
	defer s1.Close()
	wantFinding(t, runTest(t, bad, s1, ts), property.OracleStateChangeOnReplay, FindingYes)
	ok, s2 := newToy()
	defer s2.Close()
	wantFinding(t, runTest(t, ok, s2, ts), property.OracleStateChangeOnReplay, FindingNo)
}

func TestOracleAcceptedOverLimit(t *testing.T) {
	ts := pick(t, "P-RACE-1", "redeem")
	bad, s1 := newToy("race")
	defer s1.Close()
	wantFinding(t, runTest(t, bad, s1, ts), property.OracleAcceptedOverLimit, FindingYes)
	ok, s2 := newToy()
	defer s2.Close()
	wantFinding(t, runTest(t, ok, s2, ts), property.OracleAcceptedOverLimit, FindingNo)
}

func TestOracleForbiddenValues(t *testing.T) {
	var ts generate.Test
	for _, g := range generated(t) {
		if g.Property == "P-STATE-2" {
			ts = g
			break
		}
	}
	if ts.ID == "" {
		t.Fatal("no P-STATE-2 test")
	}
	bad, s1 := newToy("status-lie")
	defer s1.Close()
	wantFinding(t, runTest(t, bad, s1, ts), property.OracleForbiddenValues, FindingYes)
	ok, s2 := newToy()
	defer s2.Close()
	wantFinding(t, runTest(t, ok, s2, ts), property.OracleForbiddenValues, FindingNo)
}

func TestOracleRunnerGrade(t *testing.T) {
	ts := pick(t, "P-OWN-1", "getV1")
	bad, s1 := newToy("read-v1")
	defer s1.Close()
	wantFinding(t, runTest(t, bad, s1, ts), property.OracleRunnerGrade, FindingYes)
	ok, s2 := newToy()
	defer s2.Close()
	wantFinding(t, runTest(t, ok, s2, ts), property.OracleRunnerGrade, FindingNo)
}

// http_counter counts requests reaching next.
func http_counter(n *atomic.Int32, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		next.ServeHTTP(w, r)
	})
}

func TestCountOracleTruncatedSoftFailureIsInconclusive(t *testing.T) {
	ts := pick(t, "P-ROLE-1", "reports")
	ty, srv := newToy()
	defer srv.Close()
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/admin/reports" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"forbidden","pad":"` + strings.Repeat("x", 4000) + `"}`))
			return
		}
		srv.Config.Handler.ServeHTTP(w, r)
	}))
	defer big.Close()
	res := runTest(t, ty, big, ts)
	wantFinding(t, res, property.OracleRepeatAccepted, FindingInconclusive)
	if res.Verdict.Reason != "body truncated" {
		t.Fatalf("reason %q", res.Verdict.Reason)
	}
}

func TestCompensationClassAndMethodAreChecked(t *testing.T) {
	ty, srv := newToy()
	defer srv.Close()
	var hits atomic.Int32
	counting := httptest.NewServer(http_counter(&hits, srv.Config.Handler))
	defer counting.Close()
	m := toyModel()
	idp := []model.Param{idParam()}
	m.Operations = append(m.Operations,
		op("cMoney", "POST", "/api/v2/items/{id}/redeem", idp, nil, model.ClassMoney),
		op("cNotify", "POST", "/api/v2/items/{id}/reverse", idp, nil, model.ClassNotifying),
		op("cUnknown", "POST", "/api/v2/items/{id}/reverse", idp, nil, model.ClassUnknown),
	)
	ids := []string{"item-a1", "item-b1", "item-c1", "item-d1"}
	owners := []string{"cust-a", "cust-b", "cust-c", "cust-d"}
	var created []model.CreatedObject
	for i, c := range []string{"cMoney", "cNotify", "cUnknown", "getV2"} {
		created = append(created, model.CreatedObject{Operation: "seed", ID: ids[i], Owner: owners[i], Compensate: c})
	}
	e, err := New(Config{BaseURL: counting.URL, Fixture: toyFixture(), Secrets: toySecrets(), Model: m, Created: created,
		Guard: testGuard(t, counting.URL, m)})
	if err != nil {
		t.Fatal(err)
	}
	hits.Store(0)
	err = e.Cleanup(context.Background())
	if !errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d compensation requests were sent", hits.Load())
	}
	if len(e.Orphans()) != 4 {
		t.Fatalf("orphans: %v", e.Orphans())
	}
	if len(ty.items) != 5 {
		t.Fatal("toy state changed")
	}
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewServer(http_counter(&otherHits, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer redir.Close()
	// A caller-supplied client that would follow redirects is overridden.
	e, err := New(Config{BaseURL: redir.URL, Fixture: toyFixture(), Secrets: toySecrets(), Model: toyModel(),
		Guard: testGuard(t, redir.URL, toyModel()), Created: toyCreated(), HTTP: &http.Client{}})
	if err != nil {
		t.Fatal(err)
	}
	// Runner path.
	if _, err := e.Run(context.Background(), pick(t, "P-OWN-1", "getV2")); err != nil {
		t.Fatal(err)
	}
	// UATState path.
	if _, err := e.State().Snapshot(context.Background()); err == nil {
		t.Fatal("redirect must not be treated as a readable object")
	}
	// Cleanup path.
	if err := e.Cleanup(context.Background()); !errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("got %v", err)
	}
	if otherHits.Load() != 0 {
		t.Fatalf("redirect target received %d requests", otherHits.Load())
	}
}
