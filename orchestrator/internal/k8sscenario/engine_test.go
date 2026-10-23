package k8sscenario

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeClient is an in-memory cluster. It records every write so tests can assert that refused runs wrote nothing.
type fakeClient struct {
	objects      map[string]Object
	nsLabels     map[string]map[string]string
	identity     string
	writes       []string
	failCreate   bool
	failDelete   bool
	keepOnDelete bool // delete reports success but the object stays (rollback verification must catch this)
	// token probe fakes: the token the fake mints, whether minting fails, and who the token authenticates as.
	issued        []byte
	issueErr      error
	tokenIdentity string
}

func newFakeClient() *fakeClient {
	return &fakeClient{
		objects: map[string]Object{},
		nsLabels: map[string]map[string]string{
			"bas-sandbox": {SandboxLabel: "true"},
			"production":  {},
		},
		identity: ScenarioIdentity,
	}
}

func key(r ObjectRef) string { return r.Kind + "/" + r.Namespace + "/" + r.Name }

func (f *fakeClient) NamespaceLabels(_ context.Context, ns string) (map[string]string, bool, error) {
	l, ok := f.nsLabels[ns]
	return l, ok, nil
}
func (f *fakeClient) CurrentIdentity(context.Context) (string, error) { return f.identity, nil }
func (f *fakeClient) Get(_ context.Context, r ObjectRef) (Object, bool, error) {
	o, ok := f.objects[key(r)]
	return o, ok, nil
}
func (f *fakeClient) Create(_ context.Context, o Object) error {
	f.writes = append(f.writes, "create "+key(o.Ref))
	if f.failCreate {
		return errors.New("create refused")
	}
	f.objects[key(o.Ref)] = o
	return nil
}
func (f *fakeClient) SetData(_ context.Context, r ObjectRef, data map[string]string) error {
	f.writes = append(f.writes, "setdata "+key(r))
	o, ok := f.objects[key(r)]
	if !ok {
		return errors.New("not found")
	}
	nd := map[string]string{}
	for k, v := range o.Data {
		nd[k] = v
	}
	for k, v := range data {
		if v == "" {
			delete(nd, k)
		} else {
			nd[k] = v
		}
	}
	o.Data = nd
	f.objects[key(r)] = o
	return nil
}
func (f *fakeClient) Delete(_ context.Context, r ObjectRef) error {
	f.writes = append(f.writes, "delete "+key(r))
	if f.failDelete {
		return errors.New("delete refused")
	}
	if !f.keepOnDelete {
		delete(f.objects, key(r))
	}
	return nil
}

type recordAudit struct {
	events []string
	fail   bool
}

func (a *recordAudit) Write(_ context.Context, e Event) error {
	if a.fail {
		return errors.New("audit store down")
	}
	a.events = append(a.events, e.Type)
	return nil
}

type recordAlert struct{ msgs []string }

func (a *recordAlert) Alert(_ context.Context, msg string) { a.msgs = append(a.msgs, msg) }

const (
	testCluster = "kind-bas-lab"
	testServer  = "https://127.0.0.1:6443"
	testNS      = "bas-sandbox"
)

func testConfig(c *fakeClient, au Audit, al *recordAlert, store *memApprovals) Config {
	return Config{
		AllowedClusters:   map[string]string{testCluster: testServer},
		AllowedNamespaces: []string{testNS},
		Client:            c,
		Audit:             au,
		Alert:             al,
		Approvals:         store,
		ApproverPermitted: func(id string) bool { return id == "operator-2" },
		Now:               func() time.Time { return time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC) },
	}
}

func podRequest(live bool, approvalID string) RunRequest {
	return RunRequest{
		RunID:      "run-1",
		Requester:  "operator-1",
		Cluster:    ClusterRef{Name: testCluster, Server: testServer},
		Namespace:  testNS,
		ActionID:   "pod-create-unprivileged",
		Params:     map[string]string{"name": "bas-sbx-probe"},
		Live:       live,
		ApprovalID: approvalID,
	}
}

// approvedPod stores a valid approval for podRequest and returns its ID.
func approvedPod(t *testing.T, store *memApprovals, req RunRequest) string {
	t.Helper()
	a := Approval{
		ID:          "appr-1",
		ApproverID:  "operator-2",
		RequesterID: req.Requester,
		RunID:       req.RunID,
		Cluster:     req.Cluster.Name,
		Namespace:   req.Namespace,
		ActionID:    req.ActionID,
		ParamsHash:  HashParams(req.Params),
		ExpiresAt:   time.Date(2026, 10, 23, 10, 30, 0, 0, time.UTC),
	}
	if err := store.Put(a); err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func TestDryRunIsTheDefaultAndWritesNothing(t *testing.T) {
	c := newFakeClient()
	au := &recordAudit{}
	res := NewEngine(testConfig(c, au, &recordAlert{}, newMemApprovals())).Run(context.Background(), podRequest(false, ""))
	if res.State != StateDryRunPlanned {
		t.Fatalf("state = %s, want %s", res.State, StateDryRunPlanned)
	}
	if len(res.Plan) == 0 {
		t.Fatal("a dry run must return the plan")
	}
	if len(c.writes) != 0 {
		t.Fatalf("dry run wrote to the cluster: %v", c.writes)
	}
}

func TestRefusals_BeforeAnyWrite(t *testing.T) {
	cases := map[string]func(*RunRequest){
		"unlisted cluster":        func(r *RunRequest) { r.Cluster.Name = "prod" },
		"cluster server mismatch": func(r *RunRequest) { r.Cluster.Server = "https://evil:6443" },
		"namespace not listed":    func(r *RunRequest) { r.Namespace = "production" },
		"unknown action":          func(r *RunRequest) { r.ActionID = "role-bind-cluster-admin" },
		"bad object name":         func(r *RunRequest) { r.Params = map[string]string{"name": "../../kube-system/x"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := newFakeClient()
			req := podRequest(true, "appr-1")
			mutate(&req)
			res := NewEngine(testConfig(c, &recordAudit{}, &recordAlert{}, newMemApprovals())).Run(context.Background(), req)
			if res.State != StateRefused {
				t.Fatalf("state = %s, want %s", res.State, StateRefused)
			}
			if len(c.writes) != 0 {
				t.Fatalf("refused run wrote to the cluster: %v", c.writes)
			}
		})
	}
}

func TestLiveRun_NamespaceMustBeLabelledSandbox(t *testing.T) {
	c := newFakeClient()
	c.nsLabels["bas-sandbox"] = map[string]string{} // allow-listed but not labelled
	store := newMemApprovals()
	req := podRequest(true, "")
	req.ApprovalID = approvedPod(t, store, req)
	res := NewEngine(testConfig(c, &recordAudit{}, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateRefused || len(c.writes) != 0 {
		t.Fatalf("unlabelled namespace: state=%s writes=%v", res.State, c.writes)
	}
}

func TestLiveRun_CredentialMustBeTheScenarioIdentity(t *testing.T) {
	c := newFakeClient()
	c.identity = "system:serviceaccount:default:web"
	store := newMemApprovals()
	req := podRequest(true, "")
	req.ApprovalID = approvedPod(t, store, req)
	res := NewEngine(testConfig(c, &recordAudit{}, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateRefused || len(c.writes) != 0 {
		t.Fatalf("wrong credential: state=%s writes=%v", res.State, c.writes)
	}
}

func TestApproval_EachRejectionRefusesTheRun(t *testing.T) {
	type tc struct {
		name   string
		mutate func(*Approval)
		noID   bool
	}
	cases := []tc{
		{name: "no approval id", noID: true},
		{name: "self approval", mutate: func(a *Approval) { a.ApproverID = a.RequesterID }},
		{name: "approver lacks permission", mutate: func(a *Approval) { a.ApproverID = "operator-3" }},
		{name: "different run", mutate: func(a *Approval) { a.RunID = "run-9" }},
		{name: "different cluster", mutate: func(a *Approval) { a.Cluster = "other" }},
		{name: "different namespace", mutate: func(a *Approval) { a.Namespace = "other-ns" }},
		{name: "different action", mutate: func(a *Approval) { a.ActionID = "configmap-patch-labelled" }},
		{name: "different params", mutate: func(a *Approval) { a.ParamsHash = HashParams(map[string]string{"name": "other"}) }},
		{name: "expired", mutate: func(a *Approval) { a.ExpiresAt = time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fc := newFakeClient()
			store := newMemApprovals()
			req := podRequest(true, "")
			if !c.noID {
				a := Approval{ID: "appr-1", ApproverID: "operator-2", RequesterID: req.Requester, RunID: req.RunID,
					Cluster: req.Cluster.Name, Namespace: req.Namespace, ActionID: req.ActionID, ParamsHash: HashParams(req.Params),
					ExpiresAt: time.Date(2026, 10, 23, 10, 30, 0, 0, time.UTC)}
				c.mutate(&a)
				_ = store.Put(a)
				req.ApprovalID = "appr-1"
			}
			res := NewEngine(testConfig(fc, &recordAudit{}, &recordAlert{}, store)).Run(context.Background(), req)
			if res.State != StateRefused || len(fc.writes) != 0 {
				t.Fatalf("state=%s writes=%v, want refused with no writes", res.State, fc.writes)
			}
		})
	}
}

func TestApproval_CannotBeReused(t *testing.T) {
	fc := newFakeClient()
	store := newMemApprovals()
	req := podRequest(true, "")
	req.ApprovalID = approvedPod(t, store, req)
	eng := NewEngine(testConfig(fc, &recordAudit{}, &recordAlert{}, store))
	if res := eng.Run(context.Background(), req); res.State != StateCleaned {
		t.Fatalf("first run state = %s, want %s", res.State, StateCleaned)
	}
	// Same run, same approval: only the consumed state can refuse it.
	again := podRequest(true, req.ApprovalID)
	res := eng.Run(context.Background(), again)
	if res.State != StateRefused || !strings.Contains(res.Error, "already used") {
		t.Fatalf("second use of the approval = %s (%q), want refused as already used", res.State, res.Error)
	}
}

func TestAudit_RequestedMustBeWrittenBeforeAnyWrite(t *testing.T) {
	fc := newFakeClient()
	store := newMemApprovals()
	req := podRequest(true, "")
	req.ApprovalID = approvedPod(t, store, req)
	au := &recordAudit{fail: true}
	res := NewEngine(testConfig(fc, au, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateRefused || len(fc.writes) != 0 {
		t.Fatalf("audit down: state=%s writes=%v, want refused with no writes", res.State, fc.writes)
	}
}

func TestLiveRun_AppliesVerifiesAndCleansUp(t *testing.T) {
	fc := newFakeClient()
	store := newMemApprovals()
	req := podRequest(true, "")
	req.ApprovalID = approvedPod(t, store, req)
	au := &recordAudit{}
	res := NewEngine(testConfig(fc, au, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateCleaned {
		t.Fatalf("state = %s (%s), want %s", res.State, res.Error, StateCleaned)
	}
	if _, ok := fc.objects["Pod/bas-sandbox/bas-sbx-probe"]; ok {
		t.Fatal("the labelled pod must be removed after the run")
	}
	if !strings.Contains(strings.Join(au.events, ","), "k8s.scenario.outcome") {
		t.Fatalf("audit events %v lack an outcome", au.events)
	}
}

func TestVerificationFailure_RollsBackAndCleans(t *testing.T) {
	fc := newFakeClient()
	store := newMemApprovals()
	req := podRequest(true, "")
	req.ApprovalID = approvedPod(t, store, req)
	reg := Registry()
	reg["pod-create-unprivileged"].forceVerifyFail = true
	t.Cleanup(func() { reg["pod-create-unprivileged"].forceVerifyFail = false })
	res := NewEngine(testConfig(fc, &recordAudit{}, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateCleaned || res.Verified {
		t.Fatalf("state=%s verified=%v, want cleaned and not verified", res.State, res.Verified)
	}
}

func TestRollbackFailure_EndsInCleanupFailedAndAlerts(t *testing.T) {
	fc := newFakeClient()
	fc.failDelete = true
	store := newMemApprovals()
	req := podRequest(true, "")
	req.ApprovalID = approvedPod(t, store, req)
	al := &recordAlert{}
	au := &recordAudit{}
	res := NewEngine(testConfig(fc, au, al, store)).Run(context.Background(), req)
	if res.State != StateCleanupFailed {
		t.Fatalf("state = %s, want %s", res.State, StateCleanupFailed)
	}
	if res.State == StateCleaned {
		t.Fatal("a failed rollback must never be reported as cleaned up")
	}
	if len(al.msgs) == 0 {
		t.Fatal("the operator must be alerted")
	}
	if !strings.Contains(strings.Join(au.events, ","), "k8s.scenario.outcome") {
		t.Fatal("audit evidence must be retained")
	}
}

func TestRollbackVerification_CatchesObjectThatSurvivesDelete(t *testing.T) {
	fc := newFakeClient()
	fc.keepOnDelete = true // delete returns success but the object remains
	store := newMemApprovals()
	req := podRequest(true, "")
	req.ApprovalID = approvedPod(t, store, req)
	res := NewEngine(testConfig(fc, &recordAudit{}, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateCleanupFailed {
		t.Fatalf("state = %s, want %s: a delete that did not remove the object is not cleanup", res.State, StateCleanupFailed)
	}
}

func TestOutcomeAuditFailure_WithholdsResult(t *testing.T) {
	fc := newFakeClient()
	store := newMemApprovals()
	req := podRequest(true, "")
	req.ApprovalID = approvedPod(t, store, req)
	au := &recordAudit{}
	eng := NewEngine(testConfig(fc, au, &recordAlert{}, store))
	// Fail only the outcome write: let requested succeed, then fail.
	au2 := &outcomeFailAudit{inner: au}
	eng.cfg.Audit = au2
	res := eng.Run(context.Background(), req)
	if !res.Withheld {
		t.Fatal("when the outcome cannot be recorded, the result must be withheld")
	}
}

type outcomeFailAudit struct{ inner *recordAudit }

func (o *outcomeFailAudit) Write(ctx context.Context, e Event) error {
	if e.Type == EventOutcome {
		return errors.New("outcome store down")
	}
	return o.inner.Write(ctx, e)
}

func TestConfigMapPatch_RestoresPriorValue(t *testing.T) {
	fc := newFakeClient()
	fc.objects["ConfigMap/bas-sandbox/bas-fixture"] = Object{
		Ref:    ObjectRef{Kind: "ConfigMap", Namespace: testNS, Name: "bas-fixture"},
		Labels: map[string]string{FixtureLabel: "true"},
		Data:   map[string]string{"state": "original"},
	}
	store := newMemApprovals()
	req := RunRequest{RunID: "run-2", Requester: "operator-1", Cluster: ClusterRef{Name: testCluster, Server: testServer},
		Namespace: testNS, ActionID: "configmap-patch-labelled", Params: map[string]string{"name": "bas-fixture", "value": "changed"}, Live: true}
	a := Approval{ID: "appr-2", ApproverID: "operator-2", RequesterID: req.Requester, RunID: req.RunID, Cluster: testCluster,
		Namespace: testNS, ActionID: req.ActionID, ParamsHash: HashParams(req.Params), ExpiresAt: time.Date(2026, 10, 23, 10, 30, 0, 0, time.UTC)}
	_ = store.Put(a)
	req.ApprovalID = a.ID
	res := NewEngine(testConfig(fc, &recordAudit{}, &recordAlert{}, store)).Run(context.Background(), req)
	if res.State != StateCleaned {
		t.Fatalf("state = %s (%s), want %s", res.State, res.Error, StateCleaned)
	}
	if got := fc.objects["ConfigMap/bas-sandbox/bas-fixture"].Data["state"]; got != "original" {
		t.Fatalf("state after run = %q, want the prior value restored", got)
	}
}

// IssueToken mints a fake token. The bytes are kept so tests can check they are cleared after rollback.
func (f *fakeClient) IssueToken(_ context.Context, _ string, _ string, _ int64) (IssuedToken, error) {
	if f.issueErr != nil {
		return IssuedToken{}, f.issueErr
	}
	f.issued = []byte("SECRET-PROBE-TOKEN-VALUE")
	return IssuedToken{Token: f.issued, Expires: time.Now().Add(10 * time.Minute)}, nil
}

// IdentityWithToken reports the identity the fake token authenticates as.
func (f *fakeClient) IdentityWithToken(_ context.Context, _ []byte) (string, error) {
	return f.tokenIdentity, nil
}
