package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/audspect/bas/internal/aleef/exec"
	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/safety"
	"github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/runner"
)

// ---- a small toy application, written for the verifier tests ----
//
// Routes: GET/DELETE /api/v2/items/{id}, POST /api/v2/items/{id}/archive.
// Switches: readFlaw (func of the cross-identity read count: true = the read
// of another customer's item is wrongly allowed), roleFlaw (non-admins can
// archive), noisy (every read perturbs the object, as a correct application
// with volatile fields would), delFails (compensation fails).

type titem struct {
	ID, Owner, Title, Status string
	Hits                     int
}

type toy struct {
	mu             sync.Mutex
	items          map[string]*titem
	crossRds       int
	readFlaw       func(n int) bool
	roleFlaw       bool
	noisy          bool
	delFails       bool
	adminNoArchive bool                 // the legitimate admin archive is wrongly refused
	crossStatus    int                  // when non-zero, cross-identity reads fail with this status
	tokens         map[string][2]string // token -> customer, role
}

func newToy() *toy {
	t := &toy{tokens: map[string][2]string{
		"tok-alice": {"cust-a", "member"}, "tok-bob": {"cust-b", "member"}, "tok-dave": {"cust-d", "admin"},
	}}
	t.reset()
	return t
}

func (t *toy) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.items = map[string]*titem{}
	for _, s := range []struct{ id, owner, who string }{{"item-a1", "cust-a", "alice"}, {"item-b1", "cust-b", "bob"}, {"item-d1", "cust-d", "dave"}} {
		t.items[s.id] = &titem{ID: s.id, Owner: s.owner, Title: "ALEEF-CANARY-t-" + s.who, Status: "pending"}
	}
}

func (t *toy) Snapshot(context.Context) (map[string]runner.StateRecord, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]runner.StateRecord{}
	for id, it := range t.items {
		out[id] = runner.StateRecord{ID: id, OwnerID: it.Owner, Status: it.Status, Tag: it.Title, Quantity: fmt.Sprint(it.Hits)}
	}
	return out, nil
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (t *toy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	who, ok := t.tokens[tok]
	if !ok {
		reply(w, 401, map[string]any{"error": "unauthenticated"})
		return
	}
	cust, role := who[0], who[1]
	p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(p) < 4 || p[0] != "api" || p[2] != "items" {
		reply(w, 404, map[string]any{"error": "no route"})
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	it, found := t.items[p[3]]
	if !found {
		reply(w, 404, map[string]any{"error": "not found"})
		return
	}
	switch {
	case len(p) == 4 && r.Method == "GET":
		if it.Owner != cust {
			t.crossRds++
			if t.crossStatus != 0 {
				reply(w, t.crossStatus, map[string]any{"error": "fault"})
				return
			}
			if t.readFlaw == nil || !t.readFlaw(t.crossRds) {
				reply(w, 403, map[string]any{"error": "forbidden"})
				return
			}
		}
		out := map[string]any{"id": it.ID, "owner": it.Owner, "title": it.Title, "status": it.Status}
		if t.noisy {
			it.Hits++
			out["hits"] = it.Hits
		}
		reply(w, 200, out)
	case len(p) == 4 && r.Method == "DELETE":
		if t.delFails {
			reply(w, 500, map[string]any{"error": "boom"})
			return
		}
		delete(t.items, it.ID)
		reply(w, 200, map[string]any{"ok": true})
	case len(p) == 5 && p[4] == "archive" && r.Method == "POST":
		if it.Owner != cust || (role != "admin" && !t.roleFlaw) || (role == "admin" && t.adminNoArchive) {
			reply(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		it.Status = "archived"
		reply(w, 200, map[string]any{"ok": true})
	default:
		reply(w, 404, map[string]any{"error": "no route"})
	}
}

// ---- model, fixture, accounts ----

type secretMap map[string]string

func (s secretMap) Resolve(ref string) (string, error) {
	if v, ok := s[ref]; ok {
		return v, nil
	}
	return "", fmt.Errorf("no secret")
}

func toyAccounts() []model.Account {
	return []model.Account{
		{Name: "alice", CustomerID: "cust-a", TokenRef: "tok-alice", Role: "member"},
		{Name: "bob", CustomerID: "cust-b", TokenRef: "tok-bob", Role: "member"},
		{Name: "dave", CustomerID: "cust-d", TokenRef: "tok-dave", Role: "admin"},
	}
}

func toyFixture() fixture.Fixture {
	f := fixture.Fixture{Name: "toy"}
	objs := map[string]string{"alice": "item-a1", "bob": "item-b1", "dave": "item-d1"}
	for _, a := range toyAccounts() {
		f.Identities = append(f.Identities, fixture.Identity{Name: a.Name, CustomerID: a.CustomerID, TokenRef: a.TokenRef, Role: a.Role})
		f.Objects = append(f.Objects, fixture.Object{
			ID: objs[a.Name], OwnerID: a.CustomerID, Status: "pending",
			Public: map[string]string{}, Protected: map[string]string{"canary": "ALEEF-CANARY-t-" + a.Name},
		})
	}
	return f
}

func toyModel() model.Model {
	idp := []model.Param{{Name: "id", In: "path", IsObjectID: true, Required: true, Schema: &model.Schema{Type: "string"}}}
	str := &model.Schema{Type: "string"}
	return model.Model{
		Roles: []string{"member", "admin"},
		Operations: []model.Operation{
			{ID: "getV2", Method: "GET", Path: "/api/v2/items/{id}", PathParams: idp, Class: model.ClassRead},
			{ID: "deleteV2", Method: "DELETE", Path: "/api/v2/items/{id}", PathParams: idp, Class: model.ClassReversible},
			{ID: "archive", Method: "POST", Path: "/api/v2/items/{id}/archive", PathParams: idp, Class: model.ClassReversible,
				Body: &model.Schema{Type: "object", Properties: map[string]*model.Schema{"reason": str}}},
		},
	}
}

func toyCreated() []model.CreatedObject {
	return []model.CreatedObject{
		{Operation: "seed", ID: "item-a1", Owner: "cust-a", Compensate: "deleteV2"},
		{Operation: "seed", ID: "item-b1", Owner: "cust-b", Compensate: "deleteV2"},
	}
}

// generatedFor returns the generated test for a property on an operation,
// with its real controls.
func generatedFor(t *testing.T, prop, opID string) generate.Test {
	t.Helper()
	tests, err := generate.Generate(toyModel(), toyFixture(), toyAccounts(), generate.Options{
		Seed: 1, Catalogue: []contract.Scenario{},
		ReservedRoles: map[string]string{"archive": "admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	for _, x := range tests {
		if x.Property == prop && x.Params["operation"] == opID {
			if x.OwnerControl == nil || x.NegativeControl == nil || x.ControlsBlocked {
				t.Fatalf("%s/%s has no controls", prop, opID)
			}
			return x
		}
		seen = append(seen, x.Property+"/"+x.Params["operation"])
	}
	t.Fatalf("no generated test %s on %s; have %v", prop, opID, seen)
	return generate.Test{}
}

// ---- fake Env ----

type fakeEnv struct {
	t       *testing.T
	ty      *toy
	srv     *httptest.Server
	fresh   atomic.Int32
	cleaned atomic.Int32
	// orphan, when non-nil, is reported by every cleanup together with an error.
	orphan *model.CreatedObject
}

func newEnv(t *testing.T, ty *toy) *fakeEnv {
	srv := httptest.NewServer(ty)
	t.Cleanup(srv.Close)
	return &fakeEnv{t: t, ty: ty, srv: srv}
}

func (e *fakeEnv) Fresh(ctx context.Context) (*exec.Executor, func(context.Context) ([]model.CreatedObject, error), error) {
	e.fresh.Add(1)
	e.ty.reset()
	now := time.Now()
	g, err := safety.NewGuard(safety.Engagement{ID: "toy", Customer: "toy", Environment: "lab", Hosts: []string{e.srv.URL}, Approver: "test",
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), MaxRequests: 1 << 20, MaxConcurrent: 64, RPS: 1e6,
	}, nil, toyModel(), safety.GuardOptions{})
	if err != nil {
		return nil, nil, err
	}
	ex, err := exec.New(exec.Config{
		Guard:   g,
		BaseURL: e.srv.URL, Fixture: toyFixture(), Model: toyModel(), Created: toyCreated(), StateExtra: e.ty,
		Secrets: secretMap{"tok-alice": "tok-alice", "tok-bob": "tok-bob", "tok-dave": "tok-dave"},
	})
	if err != nil {
		return nil, nil, err
	}
	cleanup := func(ctx context.Context) ([]model.CreatedObject, error) {
		e.cleaned.Add(1)
		if e.orphan != nil {
			return []model.CreatedObject{*e.orphan}, fmt.Errorf("%w: 1 object(s) not compensated", exec.ErrCleanupFailed)
		}
		err := ex.Cleanup(ctx)
		return ex.Orphans(), err
	}
	return ex, cleanup, nil
}

// ---- fake Recorder ----

type fakeRec struct {
	mu       sync.Mutex
	findings []string
	states   map[string]string
	history  []string // "<id>:<state>"
	hash     map[string]string
	results  []string // "<testID>#<execNo>"
}

func newRec() *fakeRec { return &fakeRec{states: map[string]string{}, hash: map[string]string{}} }

type storeFinding = store.Finding

func (r *fakeRec) CreateFinding(ctx context.Context, runID string, t generate.Test, res exec.Result) (storeFinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := fmt.Sprintf("f-%d", len(r.findings)+1)
	r.findings = append(r.findings, id)
	r.states[id] = "candidate"
	r.history = append(r.history, id+":candidate")
	return storeFinding{ID: id, TestID: t.ID}, nil
}

func (r *fakeRec) SetFindingState(ctx context.Context, id, state, reason, actor string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if state == "verified" {
		return fmt.Errorf("verified via SetFindingState")
	}
	r.states[id] = state
	r.history = append(r.history, id+":"+state)
	return nil
}

func (r *fakeRec) MarkVerified(ctx context.Context, id, h, actor string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h == "" {
		return fmt.Errorf("empty hash")
	}
	r.states[id] = "verified"
	r.hash[id] = h
	r.history = append(r.history, id+":verified")
	return nil
}

func (r *fakeRec) SaveResult(ctx context.Context, runID string, t generate.Test, execNo int, res exec.Result) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results = append(r.results, fmt.Sprintf("%s#%d", t.ID, execNo))
	return nil
}

var modelOrphan = model.CreatedObject{Operation: "seed", ID: "item-a1", Owner: "cust-a", Compensate: "deleteV2"}
