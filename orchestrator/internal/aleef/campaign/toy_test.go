package campaign

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/aleef/exec"
	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/safety"
	"github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/apibas/contract"
)

// ---- a small toy application with generic nouns ----
//
// POST /api/v2/items creates an item owned by the caller and returns a NEW
// server-assigned id every time (ids never repeat, so every fixture differs
// from the generation fixture). GET/DELETE /api/v2/items/{id},
// POST /api/v2/items/{id}/archive, GET /api/v2/items (unclassified in tests).

type titem struct{ ID, Owner, Title string }

type toy struct {
	mu       sync.Mutex
	items    map[string]*titem
	seq      int
	readFlaw bool // cross-customer reads are wrongly allowed
	// tooMany: once this many non-DELETE requests were served, every
	// non-DELETE request is answered 429 (zero disables).
	tooMany  int
	served   int
	hits     map[string]int // "METHOD /path-shape" -> count
	deletes  int
	noDelete bool                 // compensation is refused
	idFn     func(seq int) string // overrides the id assigned to the seq-th created item
	probe    bool                 // an X-Probe header was received
	sawRef   bool                 // a ref query parameter was received
	paths    []string
	tokens   map[string][2]string
}

func newToy() *toy {
	return &toy{
		items: map[string]*titem{}, hits: map[string]int{},
		tokens: map[string][2]string{"tok-alice": {"cust-a", "member"}, "tok-bob": {"cust-b", "member"}, "tok-dave": {"cust-d", "admin"}},
	}
}

func (t *toy) leftover() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.items)
}

func (t *toy) hitCount(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.hits[key]
}

func (t *toy) total() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, v := range t.hits {
		n += v
	}
	return n
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (t *toy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	shape := r.Method + " /" + strings.Join(p, "/")
	if len(p) >= 4 {
		p2 := append([]string(nil), p...)
		p2[3] = "{id}"
		shape = r.Method + " /" + strings.Join(p2, "/")
	}
	t.hits[shape]++
	t.paths = append(t.paths, r.Method+" "+r.URL.Path)
	if r.Header.Get("X-Probe") != "" {
		t.probe = true
	}
	if r.URL.Query().Get("ref") != "" {
		t.sawRef = true
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	who, ok := t.tokens[tok]
	if !ok {
		reply(w, 401, map[string]any{"error": "unauthenticated"})
		return
	}
	if r.Method != "DELETE" {
		t.served++
		if t.tooMany > 0 && t.served > t.tooMany {
			reply(w, 429, map[string]any{"error": "slow down"})
			return
		}
	}
	cust, role := who[0], who[1]
	if len(p) < 3 || p[0] != "api" || p[2] != "items" {
		reply(w, 404, map[string]any{"error": "no route"})
		return
	}
	if len(p) == 3 {
		switch r.Method {
		case "POST":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			t.seq++
			it := &titem{ID: fmt.Sprintf("item-%d", t.seq), Owner: cust}
			if t.idFn != nil {
				it.ID = t.idFn(t.seq)
			}
			it.Title, _ = body["title"].(string)
			t.items[it.ID] = it
			reply(w, 201, map[string]any{"id": it.ID, "owner": it.Owner, "title": it.Title})
		case "GET":
			reply(w, 200, map[string]any{"items": []any{}})
		default:
			reply(w, 404, map[string]any{"error": "no route"})
		}
		return
	}
	it, found := t.items[p[3]]
	if !found {
		reply(w, 404, map[string]any{"error": "not found"})
		return
	}
	switch {
	case len(p) == 4 && r.Method == "GET":
		if it.Owner != cust && !t.readFlaw {
			reply(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		reply(w, 200, map[string]any{"id": it.ID, "owner": it.Owner, "title": it.Title})
	case len(p) == 4 && r.Method == "DELETE":
		if it.Owner != cust || t.noDelete {
			reply(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		t.deletes++
		delete(t.items, it.ID)
		reply(w, 200, map[string]any{"ok": true})
	case len(p) == 5 && p[4] == "archive" && r.Method == "POST":
		if it.Owner != cust || role != "admin" {
			reply(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		reply(w, 200, map[string]any{"ok": true})
	default:
		reply(w, 404, map[string]any{"error": "no route"})
	}
}

// ---- OpenAPI, accounts, secrets ----

const toySpec = `{
 "openapi": "3.0.3",
 "info": {"title": "Items", "version": "1"},
 "paths": {
  "/api/v2/items": {
   "get": {"operationId": "listItems", "responses": {"200": {"description": "ok"}}},
   "post": {"operationId": "createItem",
    "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["title"], "properties": {"title": {"type": "string"}}}}}},
    "responses": {"201": {"description": "created"}}}
  },
  "/api/v2/items/{id}": {
   "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
   "get": {"operationId": "getItem", "responses": {"200": {"description": "ok"}}},
   "delete": {"operationId": "deleteItem", "responses": {"200": {"description": "ok"}}}
  },
  "/api/v2/items/{id}/archive": {
   "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
   "post": {"operationId": "archiveItem", "responses": {"200": {"description": "ok"}}}
  }
 }
}`

type secretMap map[string]string

func (s secretMap) Resolve(ref string) (string, error) {
	if v, ok := s[ref]; ok {
		return v, nil
	}
	return "", fmt.Errorf("no secret")
}

func toySecrets() secretMap {
	return secretMap{"tok-alice": "tok-alice", "tok-bob": "tok-bob", "tok-dave": "tok-dave"}
}

func toyAccounts() []model.Account {
	return []model.Account{
		{Name: "alice", CustomerID: "cust-a", TokenRef: "tok-alice", Role: "member"},
		{Name: "bob", CustomerID: "cust-b", TokenRef: "tok-bob", Role: "member"},
		{Name: "dave", CustomerID: "cust-d", TokenRef: "tok-dave", Role: "admin"},
	}
}

// ---- fake Recorder (in memory; enforces the store's foreign key) ----

type fakeRec struct {
	mu       sync.Mutex
	runs     int
	tests    map[string]bool
	findings []string
	states   map[string]string
	hash     map[string]string
	results  []string
	fkMisses int
}

func newRec() *fakeRec {
	return &fakeRec{tests: map[string]bool{}, states: map[string]string{}, hash: map[string]string{}}
}

func (r *fakeRec) CreateRun(ctx context.Context, eng string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs++
	return fmt.Sprintf("run-%d", r.runs), nil
}

func (r *fakeRec) SaveTest(ctx context.Context, runID string, t generate.Test) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tests[t.ID] = true
	return nil
}

func (r *fakeRec) CreateFinding(ctx context.Context, runID string, t generate.Test, res exec.Result) (store.Finding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.tests[t.ID] {
		r.fkMisses++
	}
	id := fmt.Sprintf("f-%d", len(r.findings)+1)
	r.findings = append(r.findings, id)
	r.states[id] = "candidate"
	return store.Finding{ID: id, TestID: t.ID}, nil
}

func (r *fakeRec) SetFindingState(ctx context.Context, id, state, reason, actor string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states[id] = state
	return nil
}

func (r *fakeRec) MarkVerified(ctx context.Context, id, h, actor string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states[id] = "verified"
	r.hash[id] = h
	return nil
}

func (r *fakeRec) SaveResult(ctx context.Context, runID string, t generate.Test, execNo int, res exec.Result) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.tests[t.ID] {
		r.fkMisses++
		return fmt.Errorf("foreign key: test %s not saved", t.ID)
	}
	r.results = append(r.results, fmt.Sprintf("%s#%d", t.ID, execNo))
	return nil
}

// ---- config helper ----

func toyConfig(t *testing.T, ty *toy, rec Recorder) (Config, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(ty)
	t.Cleanup(srv.Close)
	now := time.Now()
	return Config{
		OpenAPI: []byte(toySpec),
		BaseURL: srv.URL,
		Engagement: safety.Engagement{ID: "toy-eng", Customer: "toy", Environment: "lab", Hosts: []string{srv.URL}, Approver: "test",
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), MaxRequests: 100000, MaxConcurrent: 64, RPS: 1e6},
		Accounts: toyAccounts(),
		Setup:    []model.SetupOp{{OperationID: "createItem", Body: map[string]any{}, Compensate: "deleteItem"}},
		Classes: map[string]model.OpClass{
			"createItem": model.ClassSetupSafe, "getItem": model.ClassRead, "deleteItem": model.ClassReversible,
		},
		Roles:         []string{"member", "admin"},
		ReservedRoles: map[string]string{"archiveItem": "admin"},
		Secrets:       toySecrets(),
		Recorder:      rec,
		Options:       Options{Seed: 1, Catalogue: []contract.Scenario{}},
	}, srv
}
