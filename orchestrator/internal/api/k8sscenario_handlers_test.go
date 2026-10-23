package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/k8sscenario"
)

// fakeScenarioCluster is an in-memory cluster for the handler tests. It records every write.
type fakeScenarioCluster struct {
	mu     sync.Mutex
	pods   map[string]k8sscenario.Object
	writes []string
}

func (f *fakeScenarioCluster) NamespaceLabels(context.Context, string) (map[string]string, bool, error) {
	return map[string]string{k8sscenario.SandboxLabel: "true"}, true, nil
}
func (f *fakeScenarioCluster) CurrentIdentity(context.Context) (string, error) {
	return k8sscenario.ScenarioIdentity, nil
}
func (f *fakeScenarioCluster) Get(_ context.Context, ref k8sscenario.ObjectRef) (k8sscenario.Object, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.pods[ref.Name]
	return o, ok, nil
}
func (f *fakeScenarioCluster) Create(_ context.Context, o k8sscenario.Object) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, "create "+o.Ref.Name)
	f.pods[o.Ref.Name] = o
	return nil
}
func (f *fakeScenarioCluster) SetData(context.Context, k8sscenario.ObjectRef, map[string]string) error {
	return errors.New("not used by pod actions")
}
func (f *fakeScenarioCluster) Delete(_ context.Context, ref k8sscenario.ObjectRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, "delete "+ref.Name)
	delete(f.pods, ref.Name)
	return nil
}
func (f *fakeScenarioCluster) IssueToken(context.Context, string, string, int64) (k8sscenario.IssuedToken, error) {
	return k8sscenario.IssuedToken{}, errors.New("not used by pod actions")
}
func (f *fakeScenarioCluster) IdentityWithToken(context.Context, []byte) (string, error) {
	return "", errors.New("not used by pod actions")
}
func (f *fakeScenarioCluster) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

type memRuns struct {
	mu sync.Mutex
	m  map[string]K8sRun
}

func (s *memRuns) InsertRun(_ context.Context, r K8sRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[r.ID] = r
	return nil
}
func (s *memRuns) UpdateRun(_ context.Context, r K8sRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[r.ID] = r
	return nil
}
func (s *memRuns) GetRun(_ context.Context, id string) (K8sRun, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[id]
	return r, ok, nil
}
func (s *memRuns) ListRuns(context.Context, int) ([]K8sRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []K8sRun
	for _, r := range s.m {
		out = append(out, r)
	}
	return out, nil
}

type memApprovalStore struct {
	mu sync.Mutex
	m  map[string]k8sscenario.Approval
}

func (s *memApprovalStore) Put(a k8sscenario.Approval) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[a.ID] = a
	return nil
}
func (s *memApprovalStore) Get(id string) (k8sscenario.Approval, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[id]
	return a, ok, nil
}
func (s *memApprovalStore) MarkUsed(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[id]
	if !ok || a.Used {
		return errors.New("approval unavailable")
	}
	a.Used = true
	s.m[id] = a
	return nil
}

type noopAudit struct{}

func (noopAudit) Write(context.Context, k8sscenario.Event) error { return nil }

type noopAlert struct{}

func (noopAlert) Alert(context.Context, string) {}

type scenarioHarness struct {
	h         *Handler
	cluster   *fakeScenarioCluster
	runs      *memRuns
	approvals *memApprovalStore
	router    *chi.Mux
}

func newScenarioHarness(t *testing.T) *scenarioHarness {
	t.Helper()
	cluster := &fakeScenarioCluster{pods: map[string]k8sscenario.Object{}}
	runs := &memRuns{m: map[string]K8sRun{}}
	approvals := &memApprovalStore{m: map[string]k8sscenario.Approval{}}
	engine := k8sscenario.NewEngine(k8sscenario.Config{
		AllowedClusters:   map[string]string{"kind-bas-lab": "https://lab.example:6443"},
		AllowedNamespaces: []string{"bas-sandbox"},
		Client:            cluster,
		Audit:             noopAudit{},
		Alert:             noopAlert{},
		Approvals:         approvals,
		ApproverPermitted: func(id string) bool { return id == "admin-2" },
		Now:               time.Now,
	})
	h := &Handler{k8sScenario: &K8sScenarioService{
		Engine:     engine,
		Runs:       runs,
		Approvals:  approvals,
		Clusters:   map[string]string{"kind-bas-lab": "https://lab.example:6443"},
		Namespaces: []string{"bas-sandbox"},
	}}
	r := chi.NewRouter()
	r.Post("/api/k8s-scenarios/runs", h.CreateK8sRun)
	r.Post("/api/k8s-scenarios/runs/{id}/approve", h.ApproveK8sRun)
	r.Post("/api/k8s-scenarios/runs/{id}/execute", h.ExecuteK8sRun)
	r.Get("/api/k8s-scenarios/runs", h.ListK8sRuns)
	return &scenarioHarness{h: h, cluster: cluster, runs: runs, approvals: approvals, router: r}
}

// do sends a request as the given user with the given role.
func (sh *scenarioHarness) do(t *testing.T, method, path, user string, role auth.Role, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = strings.NewReader(string(b))
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: user, Role: role}))
	rec := httptest.NewRecorder()
	sh.router.ServeHTTP(rec, req)
	return rec
}

var labPodBody = map[string]any{"cluster": "kind-bas-lab", "namespace": "bas-sandbox", "action": "pod-create-unprivileged",
	"params": map[string]string{"name": "bas-sbx-api-probe"}}

func planRun(t *testing.T, sh *scenarioHarness, user string) K8sRun {
	t.Helper()
	rec := sh.do(t, http.MethodPost, "/api/k8s-scenarios/runs", user, auth.RoleAnalyst, labPodBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("plan: status %d body %s", rec.Code, rec.Body.String())
	}
	var run K8sRun
	if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	return run
}

func TestK8sRun_PlanningWritesNothing(t *testing.T) {
	sh := newScenarioHarness(t)
	run := planRun(t, sh, "requester-1")
	if run.State != "PLANNED" || run.Detail == "" {
		t.Fatalf("run = %+v, want PLANNED with a plan", run)
	}
	if sh.cluster.writeCount() != 0 {
		t.Fatalf("planning wrote to the cluster: %v", sh.cluster.writes)
	}
}

func TestK8sRun_UnconfiguredTargetIsRefused(t *testing.T) {
	sh := newScenarioHarness(t)
	body := map[string]any{"cluster": "production", "namespace": "bas-sandbox", "action": "pod-create-unprivileged",
		"params": map[string]string{"name": "bas-sbx-x"}}
	rec := sh.do(t, http.MethodPost, "/api/k8s-scenarios/runs", "requester-1", auth.RoleAnalyst, body)
	if rec.Code != http.StatusBadRequest || len(sh.runs.m) != 0 {
		t.Fatalf("status %d, runs stored %d; want 400 and nothing stored", rec.Code, len(sh.runs.m))
	}
}

func TestK8sRun_SelfApprovalIsForbidden(t *testing.T) {
	sh := newScenarioHarness(t)
	run := planRun(t, sh, "requester-1")
	rec := sh.do(t, http.MethodPost, "/api/k8s-scenarios/runs/"+run.ID+"/approve", "requester-1", auth.RoleAdmin, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval status = %d, want 403", rec.Code)
	}
}

func TestK8sRun_ApprovalByAnotherAdminIsRecordedAndBound(t *testing.T) {
	sh := newScenarioHarness(t)
	run := planRun(t, sh, "requester-1")
	rec := sh.do(t, http.MethodPost, "/api/k8s-scenarios/runs/"+run.ID+"/approve", "admin-2", auth.RoleAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status = %d body %s", rec.Code, rec.Body.String())
	}
	var approved K8sRun
	_ = json.Unmarshal(rec.Body.Bytes(), &approved)
	if approved.State != "APPROVED" || approved.ApprovalID == "" {
		t.Fatalf("run = %+v, want APPROVED with an approval", approved)
	}
	a, ok, _ := sh.approvals.Get(approved.ApprovalID)
	if !ok || a.ApproverID != "admin-2" || a.RequesterID != "requester-1" || a.ParamsHash != run.ParamsHash || a.RunID != run.ID {
		t.Fatalf("approval = %+v, want bound to this run, approver and requester", a)
	}
}

func TestK8sRun_OnlyTheRequesterMayExecute(t *testing.T) {
	sh := newScenarioHarness(t)
	run := planRun(t, sh, "requester-1")
	sh.do(t, http.MethodPost, "/api/k8s-scenarios/runs/"+run.ID+"/approve", "admin-2", auth.RoleAdmin, nil)
	rec := sh.do(t, http.MethodPost, "/api/k8s-scenarios/runs/"+run.ID+"/execute", "admin-2", auth.RoleAdmin, nil)
	if rec.Code != http.StatusForbidden || sh.cluster.writeCount() != 0 {
		t.Fatalf("non-requester execute: status %d writes %v, want 403 and no writes", rec.Code, sh.cluster.writes)
	}
}

func TestK8sRun_ExecuteWithoutApprovalConflicts(t *testing.T) {
	sh := newScenarioHarness(t)
	run := planRun(t, sh, "requester-1")
	rec := sh.do(t, http.MethodPost, "/api/k8s-scenarios/runs/"+run.ID+"/execute", "requester-1", auth.RoleAnalyst, nil)
	if rec.Code != http.StatusConflict || sh.cluster.writeCount() != 0 {
		t.Fatalf("execute without approval: status %d writes %v, want 409 and no writes", rec.Code, sh.cluster.writes)
	}
}

func TestK8sRun_ApprovedExecuteRunsVerifiesAndCleansUp(t *testing.T) {
	sh := newScenarioHarness(t)
	run := planRun(t, sh, "requester-1")
	sh.do(t, http.MethodPost, "/api/k8s-scenarios/runs/"+run.ID+"/approve", "admin-2", auth.RoleAdmin, nil)
	rec := sh.do(t, http.MethodPost, "/api/k8s-scenarios/runs/"+run.ID+"/execute", "requester-1", auth.RoleAnalyst, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("execute status = %d body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Run      K8sRun `json:"run"`
		Verified bool   `json:"verified"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Run.State != string(k8sscenario.StateCleaned) || !out.Verified {
		t.Fatalf("result = %+v, want CLEANED and verified", out)
	}
	if _, left := sh.cluster.pods["bas-sbx-api-probe"]; left {
		t.Fatal("the pod was not removed")
	}
	if got := sh.runs.m[run.ID].State; got != string(k8sscenario.StateCleaned) {
		t.Fatalf("stored state = %s, want CLEANED", got)
	}
}

func TestK8sRun_ApprovalCannotBeUsedTwice(t *testing.T) {
	sh := newScenarioHarness(t)
	run := planRun(t, sh, "requester-1")
	sh.do(t, http.MethodPost, "/api/k8s-scenarios/runs/"+run.ID+"/approve", "admin-2", auth.RoleAdmin, nil)
	sh.do(t, http.MethodPost, "/api/k8s-scenarios/runs/"+run.ID+"/execute", "requester-1", auth.RoleAnalyst, nil)
	writesAfterFirst := sh.cluster.writeCount()
	rec := sh.do(t, http.MethodPost, "/api/k8s-scenarios/runs/"+run.ID+"/execute", "requester-1", auth.RoleAnalyst, nil)
	if rec.Code != http.StatusConflict || sh.cluster.writeCount() != writesAfterFirst {
		t.Fatalf("second execute: status %d, extra writes %d; want 409 and none", rec.Code, sh.cluster.writeCount()-writesAfterFirst)
	}
}

func (f *fakeScenarioCluster) ReadSecretAs(context.Context, []byte, string, string) (string, bool, error) {
	return "", false, errors.New("not used by pod actions")
}
func (f *fakeScenarioCluster) GetBinding(context.Context, string, string) (k8sscenario.BindingState, bool, error) {
	return k8sscenario.BindingState{}, false, errors.New("not used by pod actions")
}
func (f *fakeScenarioCluster) SetBindingSubjects(context.Context, string, string, []string) error {
	return errors.New("not used by pod actions")
}
func (f *fakeScenarioCluster) SetSecretValue(context.Context, string, string, string) error {
	return errors.New("not used by pod actions")
}

func (f *fakeScenarioCluster) SyntheticSecretLabels(context.Context, string, string) (map[string]string, bool, error) {
	return nil, false, errors.New("not used by pod actions")
}
