package api

import (
	"bytes"
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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/aleef/exec"
	"github.com/audspect/bas/internal/aleef/generate"
	aleefstore "github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// ---- a small toy application with generic nouns ----
//
// POST /api/v2/items creates an item owned by the caller. GET/DELETE /api/v2/items/{id}. With
// readFlaw set, cross-customer reads are wrongly allowed. Every request is counted.

type aleefToyItem struct{ ID, Owner, Title string }

type aleefToy struct {
	mu       sync.Mutex
	items    map[string]*aleefToyItem
	seq      int
	readFlaw bool
	delay    time.Duration
	requests atomic.Int64
	tokens   map[string][2]string
}

func newAleefToy() *aleefToy {
	return &aleefToy{
		items:  map[string]*aleefToyItem{},
		tokens: map[string][2]string{"tok-alice": {"cust-a", "member"}, "tok-bob": {"cust-b", "member"}},
	}
}

func (t *aleefToy) leftover() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.items)
}

func aleefReply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (t *aleefToy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.requests.Add(1)
	if t.delay > 0 {
		time.Sleep(t.delay)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	who, ok := t.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if !ok {
		aleefReply(w, 401, map[string]any{"error": "unauthenticated"})
		return
	}
	p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(p) < 3 || p[0] != "api" || p[2] != "items" {
		aleefReply(w, 404, map[string]any{"error": "no route"})
		return
	}
	if len(p) == 3 {
		switch r.Method {
		case "POST":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			t.seq++
			it := &aleefToyItem{ID: fmt.Sprintf("item-%d", t.seq), Owner: who[0]}
			it.Title, _ = body["title"].(string)
			t.items[it.ID] = it
			aleefReply(w, 201, map[string]any{"id": it.ID, "owner": it.Owner, "title": it.Title})
		case "GET":
			aleefReply(w, 200, map[string]any{"items": []any{}})
		default:
			aleefReply(w, 404, map[string]any{"error": "no route"})
		}
		return
	}
	it, found := t.items[p[3]]
	if !found {
		aleefReply(w, 404, map[string]any{"error": "not found"})
		return
	}
	switch {
	case len(p) == 4 && r.Method == "GET":
		if it.Owner != who[0] && !t.readFlaw {
			aleefReply(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		aleefReply(w, 200, map[string]any{"id": it.ID, "owner": it.Owner, "title": it.Title})
	case len(p) == 4 && r.Method == "DELETE":
		if it.Owner != who[0] {
			aleefReply(w, 403, map[string]any{"error": "forbidden"})
			return
		}
		delete(t.items, it.ID)
		aleefReply(w, 200, map[string]any{"ok": true})
	default:
		aleefReply(w, 404, map[string]any{"error": "no route"})
	}
}

const aleefToySpec = `{
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
  }
 }
}`

type aleefSecretMap map[string]string

func (s aleefSecretMap) Resolve(ref string) (string, error) {
	if v, ok := s[ref]; ok {
		return v, nil
	}
	return "", fmt.Errorf("no secret")
}

// ---- harness ----

type aleefEnv struct {
	t      *testing.T
	pool   *pgxpool.Pool
	router http.Handler
	store  *aleefstore.Store
	state  *aleefState
}

func setAleefLicense(t *testing.T, tier license.Tier, addons ...string) {
	t.Helper()
	prev := license.Current()
	license.SetInitial(license.Info{State: license.StateValid, Tier: tier, Addons: addons})
	t.Cleanup(func() { license.SetInitial(prev) })
}

func withAleefEnv(t *testing.T, fn func(e *aleefEnv)) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := aleefstore.EnsureSchema(context.Background(), pool); err != nil {
			t.Fatal(err)
		}
		setAleefLicense(t, license.TierEnterprise, "aleef")
		st := aleefstore.New(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithAleef(st, aleefSecretMap{"tok-alice": "tok-alice", "tok-bob": "tok-bob"})
		fn(&aleefEnv{t: t, pool: pool, store: st, state: h.aleef, router: Mount(h, ws.NewHub(), testJWTSecret, "", http.NotFoundHandler(), 0, 0)})
	})
}

func (e *aleefEnv) do(method, path string, role auth.Role, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	if role != "" {
		tenant := "default"
		tok, err := auth.GenerateTenantToken("aleef-"+string(role), role, &tenant, false, testJWTSecret, time.Hour)
		if err != nil {
			e.t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not JSON (%d): %s", rec.Code, rec.Body.String())
	}
	return m
}

func aleefEngagementBody(host string, env string, notBefore, notAfter time.Time) map[string]any {
	return map[string]any{
		"customer": "toy", "environment": env, "hosts": []string{host},
		"notBefore": notBefore, "notAfter": notAfter, "maxRequests": 100000, "maxConcurrent": 64, "rps": 1e6,
	}
}

func (e *aleefEnv) createEngagement(host string) string {
	e.t.Helper()
	now := time.Now()
	rec := e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleAdmin, aleefEngagementBody(host, "lab", now.Add(-time.Hour), now.Add(time.Hour)))
	if rec.Code != http.StatusCreated {
		e.t.Fatalf("create engagement: %d %s", rec.Code, rec.Body.String())
	}
	return decodeMap(e.t, rec)["id"].(string)
}

func aleefRunBody(engagementID, baseURL string) map[string]any {
	return map[string]any{
		"engagement_id": engagementID, "openapi": aleefToySpec, "base_url": baseURL,
		"accounts": []map[string]string{
			{"name": "alice", "customer_id": "cust-a", "token_ref": "tok-alice", "role": "member"},
			{"name": "bob", "customer_id": "cust-b", "token_ref": "tok-bob", "role": "member"},
		},
		"setup":   []map[string]any{{"operation_id": "createItem", "body": map[string]any{}, "compensate": "deleteItem"}},
		"classes": map[string]string{"createItem": "setup_safe", "getItem": "read", "deleteItem": "reversible"},
		"options": map[string]any{"seed": 1},
	}
}

func (e *aleefEnv) waitRun(runID string, d time.Duration) map[string]any {
	e.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		rec := e.do(http.MethodGet, "/api/aleef/runs/"+runID, auth.RoleAnalyst, nil)
		m := decodeMap(e.t, rec)
		if s, _ := m["status"].(string); s != "running" && s != "stopping" {
			return m
		}
		time.Sleep(50 * time.Millisecond)
	}
	e.t.Fatalf("run %s did not finish within %s", runID, d)
	return nil
}

func (e *aleefEnv) startRun(engagementID, baseURL string) string {
	e.t.Helper()
	rec := e.do(http.MethodPost, "/api/aleef/runs", auth.RoleAnalyst, aleefRunBody(engagementID, baseURL))
	if rec.Code != http.StatusAccepted {
		e.t.Fatalf("start run: %d %s", rec.Code, rec.Body.String())
	}
	return decodeMap(e.t, rec)["run_id"].(string)
}

var aleefAllRoutes = []struct{ method, path string }{
	{http.MethodPost, "/api/aleef/engagements"},
	{http.MethodPost, "/api/aleef/runs"},
	{http.MethodGet, "/api/aleef/runs/x"},
	{http.MethodPost, "/api/aleef/runs/x/stop"},
	{http.MethodGet, "/api/aleef/findings"},
	{http.MethodGet, "/api/aleef/findings/x/regression"},
	{http.MethodPost, "/api/aleef/findings/x/prior-knowledge"},
}

// ---- tests ----

// Every Aleef route is refused (403 product_not_licensed) without the add-on, on every tier
// including Enterprise, even for an admin. With the add-on the gate lets the request through.
func TestAleefRoutesRefusedWithoutAddOn(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		for _, tier := range []license.Tier{license.TierCore, license.TierAdvanced, license.TierEnterprise} {
			license.SetInitial(license.Info{State: license.StateValid, Tier: tier})
			for _, rt := range aleefAllRoutes {
				rec := e.do(rt.method, rt.path, auth.RoleAdmin, map[string]any{})
				if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "product_not_licensed") {
					t.Fatalf("%s %s on %s without add-on: %d %s", rt.method, rt.path, tier, rec.Code, rec.Body.String())
				}
			}
			license.SetInitial(license.Info{State: license.StateValid, Tier: tier, Addons: []string{"aleef"}})
			for _, rt := range aleefAllRoutes {
				rec := e.do(rt.method, rt.path, auth.RoleAdmin, map[string]any{})
				if strings.Contains(rec.Body.String(), "product_not_licensed") {
					t.Fatalf("%s %s on %s with add-on was refused by the product gate", rt.method, rt.path, tier)
				}
			}
		}
		// A locked licence refuses even with the add-on.
		license.SetInitial(license.Info{State: license.StateLocked, Tier: license.TierEnterprise, Addons: []string{"aleef"}})
		if rec := e.do(http.MethodGet, "/api/aleef/findings", auth.RoleAdmin, nil); rec.Code != http.StatusForbidden && rec.Code != http.StatusPaymentRequired {
			t.Fatalf("locked licence: %d", rec.Code)
		}
	})
}

// A viewer holds neither aleef permission: it can neither start, stop or annotate nor read.
// Anonymous requests get 401. An analyst clears the permission gate.
func TestAleefRoutesRequirePermission(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		for _, rt := range aleefAllRoutes {
			if rec := e.do(rt.method, rt.path, auth.RoleViewer, map[string]any{}); rec.Code != http.StatusForbidden {
				t.Fatalf("viewer %s %s: %d, want 403", rt.method, rt.path, rec.Code)
			}
			if rec := e.do(rt.method, rt.path, "", nil); rec.Code != http.StatusUnauthorized {
				t.Fatalf("anonymous %s %s: %d, want 401", rt.method, rt.path, rec.Code)
			}
			if rt.path == "/api/aleef/engagements" {
				// only aleef:authorize (admin) creates engagements
				if rec := e.do(rt.method, rt.path, auth.RoleAnalyst, map[string]any{}); rec.Code != http.StatusForbidden {
					t.Fatalf("analyst %s %s: %d, want 403", rt.method, rt.path, rec.Code)
				}
				if rec := e.do(rt.method, rt.path, auth.RoleAdmin, map[string]any{}); rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
					t.Fatalf("admin %s %s: %d, want the permission gate cleared", rt.method, rt.path, rec.Code)
				}
				continue
			}
			if rec := e.do(rt.method, rt.path, auth.RoleAnalyst, map[string]any{}); rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
				t.Fatalf("analyst %s %s: %d, want the permission gate cleared", rt.method, rt.path, rec.Code)
			}
		}
	})
}

// A production (or unknown) environment is refused with a clear message and nothing is stored.
func TestProductionEngagementRefused(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		now := time.Now()
		for _, env := range []string{"production", "prod", ""} {
			rec := e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleAdmin,
				aleefEngagementBody("https://uat.example.test", env, now.Add(-time.Hour), now.Add(time.Hour)))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "production is refused") {
				t.Fatalf("environment %q: %d %s", env, rec.Code, rec.Body.String())
			}
		}
		var n int
		if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM aleef_engagements`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("refused engagements were stored: %d (%v)", n, err)
		}
		// A body with a credential field is refused too: only token references exist.
		body := aleefEngagementBody("https://uat.example.test", "uat", now.Add(-time.Hour), now.Add(time.Hour))
		body["token"] = "secret"
		if rec := e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleAdmin, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("engagement with a token field: %d", rec.Code)
		}
	})
}

// No request reaches the target when the engagement is unknown, tampered, outside its window, or
// does not authorise the base URL; and a pasted credential as token_ref is refused.
func TestRunRefusedWithoutValidEngagement(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		srv := httptest.NewServer(toy)
		defer srv.Close()
		now := time.Now()
		ctx := context.Background()

		expired, err := e.store.CreateEngagement(ctx, aleefstore.Engagement{Customer: "toy", Environment: "lab", Body: mustStoredEngagement(t, aleefEngagementBody(srv.URL, "lab", now.Add(-3*time.Hour), now.Add(-time.Hour)))})
		if err != nil {
			t.Fatal(err)
		}
		future, _ := e.store.CreateEngagement(ctx, aleefstore.Engagement{Customer: "toy", Environment: "lab", Body: mustStoredEngagement(t, aleefEngagementBody(srv.URL, "lab", now.Add(time.Hour), now.Add(2*time.Hour)))})
		// A production engagement can only exist by tampering with the record; it is still refused.
		prodBody := aleefEngagementBody(srv.URL, "production", now.Add(-time.Hour), now.Add(time.Hour))
		prod, _ := e.store.CreateEngagement(ctx, aleefstore.Engagement{Customer: "toy", Environment: "production", Body: mustStoredEngagementRaw(t, prodBody)})
		garbage, _ := e.store.CreateEngagement(ctx, aleefstore.Engagement{Customer: "toy", Environment: "lab", Body: []byte(`{"x":1}`)})
		valid := e.createEngagement(srv.URL)

		cases := []struct {
			name   string
			mutate func(m map[string]any)
			want   int
		}{
			{"unknown engagement", func(m map[string]any) { m["engagement_id"] = "does-not-exist" }, http.StatusBadRequest},
			{"expired window", func(m map[string]any) { m["engagement_id"] = expired }, http.StatusConflict},
			{"future window", func(m map[string]any) { m["engagement_id"] = future }, http.StatusConflict},
			{"production record", func(m map[string]any) { m["engagement_id"] = prod }, http.StatusBadRequest},
			{"unreadable record", func(m map[string]any) { m["engagement_id"] = garbage }, http.StatusBadRequest},
			{"foreign base url", func(m map[string]any) { m["engagement_id"] = valid; m["base_url"] = "http://127.0.0.1:1" }, http.StatusBadRequest},
			{"url with credentials", func(m map[string]any) { m["engagement_id"] = valid; m["base_url"] = "http://u:p@" + strings.TrimPrefix(srv.URL, "http://") }, http.StatusBadRequest},
			{"pasted credential as token_ref", func(m map[string]any) {
				m["engagement_id"] = valid
				m["accounts"] = []map[string]string{{"name": "a", "customer_id": "c", "token_ref": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig-sig-sig-sig-sig-sig-sig-sig-sig", "role": "member"}}
			}, http.StatusBadRequest},
			{"unresolvable token_ref", func(m map[string]any) {
				m["engagement_id"] = valid
				m["accounts"] = []map[string]string{{"name": "a", "customer_id": "c", "token_ref": "no-such-ref", "role": "member"}}
			}, http.StatusBadRequest},
			{"bad class", func(m map[string]any) { m["engagement_id"] = valid; m["classes"] = map[string]string{"getItem": "nuclear"} }, http.StatusBadRequest},
		}
		for _, c := range cases {
			body := aleefRunBody(valid, srv.URL)
			c.mutate(body)
			rec := e.do(http.MethodPost, "/api/aleef/runs", auth.RoleAnalyst, body)
			if rec.Code != c.want {
				t.Fatalf("%s: %d %s, want %d", c.name, rec.Code, rec.Body.String(), c.want)
			}
		}
		// oversized body
		big := bytes.Repeat([]byte("a"), maxAleefRunBody+1024)
		if rec := e.do(http.MethodPost, "/api/aleef/runs", auth.RoleAnalyst, append([]byte(`{"openapi":"`), append(big, []byte(`"}`)...)...)); rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized body: %d", rec.Code)
		}
		time.Sleep(200 * time.Millisecond)
		if n := toy.requests.Load(); n != 0 {
			t.Fatalf("%d requests reached the target for refused runs, want 0", n)
		}
	})
}

func mustStoredEngagement(t *testing.T, body map[string]any) []byte {
	t.Helper()
	return mustStoredEngagementRaw(t, body)
}

func mustStoredEngagementRaw(t *testing.T, body map[string]any) []byte {
	t.Helper()
	b := map[string]any{"approver": "user:seed"}
	for k, v := range body {
		b[k] = v
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(storedEngagement{Engagement: raw})
	return out
}

// verified findings come only from ListVerifiedWithRegression: one without a saved regression is
// never in "verified". Candidates are a separate array.
func TestFindingsListSeparatesCandidatesFromVerified(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		ctx := context.Background()
		runID, err := e.store.CreateRun(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		mk := func(id, prop string) aleefstore.Finding {
			tst := generate.Test{ID: id, Property: prop, Params: map[string]string{}, Covered: true}
			if err := e.store.SaveTest(ctx, runID, tst); err != nil {
				t.Fatal(err)
			}
			f, err := e.store.CreateFinding(ctx, runID, tst, exec.Result{})
			if err != nil {
				t.Fatal(err)
			}
			return f
		}
		cand := mk("t-cand", "P-OWN-1")
		withReg := mk("t-reg", "P-OWN-2")
		noReg := mk("t-noreg", "P-ROLE-1")
		if err := e.store.MarkVerified(ctx, withReg.ID, "hash-reg", "test"); err != nil {
			t.Fatal(err)
		}
		if err := e.store.SaveRegression(ctx, withReg.ID, "REG-0001", []byte(`{"steps":[]}`), nil, "no catalogue scenario applies"); err != nil {
			t.Fatal(err)
		}
		if err := e.store.MarkVerified(ctx, noReg.ID, "hash-noreg", "test"); err != nil {
			t.Fatal(err)
		}

		rec := e.do(http.MethodGet, "/api/aleef/findings?run_id="+runID, auth.RoleAnalyst, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		var out map[string][]map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		ids := func(k string) []string {
			var r []string
			for _, f := range out[k] {
				r = append(r, f["id"].(string))
			}
			return r
		}
		if got := ids("candidates"); len(got) != 1 || got[0] != cand.ID {
			t.Fatalf("candidates = %v, want [%s]", got, cand.ID)
		}
		if got := ids("verified"); len(got) != 1 || got[0] != withReg.ID {
			t.Fatalf("verified = %v, want only the finding with a regression [%s]", got, withReg.ID)
		}
		if got := ids("pending_regression"); len(got) != 1 || got[0] != noReg.ID {
			t.Fatalf("pending_regression = %v, want [%s]", got, noReg.ID)
		}
		v := out["verified"][0]
		if v["regression_id"] != "REG-0001" || v["evidence_hash"] != "hash-reg" || v["prior_knowledge"] != "not_checked" || v["property_id"] != "P-OWN-2" {
			t.Fatalf("verified finding view: %v", v)
		}
		for _, k := range []string{"candidates", "verified", "unconfirmed", "rejected", "pending_regression"} {
			if _, ok := out[k]; !ok {
				t.Fatalf("missing array %q", k)
			}
		}
		low := strings.ToLower(rec.Body.String())
		if strings.Contains(low, "zero-day") || strings.Contains(low, "zero day") || strings.Contains(low, "zeroday") {
			t.Fatal("response claims zero-day")
		}

		// Regression endpoint: stored bundle for the regressed finding, 404 for the other.
		rr := e.do(http.MethodGet, "/api/aleef/findings/"+withReg.ID+"/regression", auth.RoleAnalyst, nil)
		m := decodeMap(t, rr)
		if rr.Code != http.StatusOK || m["regression_id"] != "REG-0001" || m["yaml_note"] != "no catalogue scenario applies" || m["bundle"] == nil {
			t.Fatalf("regression: %d %s", rr.Code, rr.Body.String())
		}
		if rr := e.do(http.MethodGet, "/api/aleef/findings/"+noReg.ID+"/regression", auth.RoleAnalyst, nil); rr.Code != http.StatusNotFound {
			t.Fatalf("regression of an unregressed finding: %d", rr.Code)
		}

		// Prior knowledge: run permission, valid value, actor recorded, state unchanged.
		pk := func(role auth.Role, id string, body any) *httptest.ResponseRecorder {
			return e.do(http.MethodPost, "/api/aleef/findings/"+id+"/prior-knowledge", role, body)
		}
		if rr := pk(auth.RoleViewer, cand.ID, map[string]any{"value": "known_public"}); rr.Code != http.StatusForbidden {
			t.Fatalf("viewer prior-knowledge: %d", rr.Code)
		}
		if rr := pk(auth.RoleAnalyst, cand.ID, map[string]any{"value": "zero_day"}); rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid value: %d", rr.Code)
		}
		if rr := pk(auth.RoleAnalyst, "no-such-finding", map[string]any{"value": "known_public"}); rr.Code != http.StatusNotFound {
			t.Fatalf("unknown finding: %d", rr.Code)
		}
		rr = pk(auth.RoleAnalyst, withReg.ID, map[string]any{"value": "checked_none_found"})
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "new to Audspect") {
			t.Fatalf("prior-knowledge: %d %s", rr.Code, rr.Body.String())
		}
		var actor, state string
		if err := e.pool.QueryRow(ctx, `SELECT h.actor, f.state FROM aleef_finding_history h JOIN aleef_findings f ON f.id=h.finding_id
			WHERE h.finding_id=$1 AND h.reason LIKE 'prior knowledge:%' ORDER BY h.id DESC LIMIT 1`, withReg.ID).Scan(&actor, &state); err != nil {
			t.Fatal(err)
		}
		if actor != "user:aleef-analyst" || state != "verified" {
			t.Fatalf("history actor=%q state=%q", actor, state)
		}
	})
}

// Whole path: create an engagement, start a run against a flawed toy target, wait, and see a
// verified finding with a regression in GET findings. Responses never carry the tokens.
func TestAleefEndToEndVerifiesFlawAndLeaksNoSecrets(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		toy.readFlaw = true
		srv := httptest.NewServer(toy)
		defer srv.Close()

		var bodies []string
		engID := e.createEngagement(srv.URL)
		runID := e.startRun(engID, srv.URL)
		final := e.waitRun(runID, 3*time.Minute)
		raw, _ := json.Marshal(final)
		bodies = append(bodies, string(raw))
		if final["status"] != "completed" {
			t.Fatalf("run status %v: %s", final["status"], raw)
		}
		rep, _ := final["report"].(map[string]any)
		if rep == nil || rep["RunID"] != runID || rep["Verified"].(float64) < 1 {
			t.Fatalf("report: %s", raw)
		}
		if toy.leftover() != 0 {
			t.Fatalf("%d objects left on the target", toy.leftover())
		}

		rec := e.do(http.MethodGet, "/api/aleef/findings?run_id="+runID, auth.RoleAnalyst, nil)
		bodies = append(bodies, rec.Body.String())
		var out map[string][]map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if len(out["verified"]) < 1 {
			t.Fatalf("no verified finding: %s", rec.Body.String())
		}
		f := out["verified"][0]
		regID, _ := f["regression_id"].(string)
		if regID == "" || f["evidence_hash"] == "" || f["state"] != "verified" {
			t.Fatalf("verified finding: %v", f)
		}
		rr := e.do(http.MethodGet, "/api/aleef/findings/"+f["id"].(string)+"/regression", auth.RoleAnalyst, nil)
		bodies = append(bodies, rr.Body.String())
		if rr.Code != http.StatusOK || decodeMap(t, rr)["regression_id"] != regID {
			t.Fatalf("regression: %d %s", rr.Code, rr.Body.String())
		}
		for _, b := range bodies {
			for _, secret := range []string{"tok-alice", "tok-bob", "Bearer "} {
				if strings.Contains(b, secret) {
					t.Fatalf("response contains %q", secret)
				}
			}
		}
	})
}

// A secret never appears in responses even when something fails: the failure messages for an
// unresolvable reference do not echo the reference.
func TestResponsesContainNoSecrets(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		srv := httptest.NewServer(toy)
		defer srv.Close()
		engID := e.createEngagement(srv.URL)
		body := aleefRunBody(engID, srv.URL)
		pasted := "sk-live-ABCDEF0123456789"
		body["accounts"] = []map[string]string{{"name": "a", "customer_id": "c", "token_ref": pasted, "role": "member"}}
		rec := e.do(http.MethodPost, "/api/aleef/runs", auth.RoleAnalyst, body)
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), pasted) {
			t.Fatalf("unresolvable reference: %d %s", rec.Code, rec.Body.String())
		}
		if toy.requests.Load() != 0 {
			t.Fatal("request reached the target")
		}
		// The engagement response carries no credential fields either.
		now := time.Now()
		rec = e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleAdmin, aleefEngagementBody(srv.URL, "lab", now.Add(-time.Hour), now.Add(time.Hour)))
		if strings.Contains(strings.ToLower(rec.Body.String()), "token") {
			t.Fatalf("engagement response mentions a token: %s", rec.Body.String())
		}
	})
}

// Stop answers 200 repeatedly, 404 for an unknown run, and the campaign still cleans up.
func TestStopIsIdempotent(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		toy.readFlaw = true
		toy.delay = 15 * time.Millisecond
		srv := httptest.NewServer(toy)
		defer srv.Close()
		engID := e.createEngagement(srv.URL)
		runID := e.startRun(engID, srv.URL)

		if rec := e.do(http.MethodPost, "/api/aleef/runs/no-such-run/stop", auth.RoleAnalyst, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("unknown run: %d", rec.Code)
		}
		time.Sleep(300 * time.Millisecond)
		for i := 0; i < 3; i++ {
			rec := e.do(http.MethodPost, "/api/aleef/runs/"+runID+"/stop", auth.RoleAnalyst, nil)
			m := decodeMap(t, rec)
			if rec.Code != http.StatusOK || (m["status"] != "stopping" && m["status"] != "stopped") {
				t.Fatalf("stop #%d: %d %s", i, rec.Code, rec.Body.String())
			}
		}
		final := e.waitRun(runID, time.Minute)
		if final["status"] != "stopped" {
			t.Fatalf("final status %v", final["status"])
		}
		if rec := e.do(http.MethodPost, "/api/aleef/runs/"+runID+"/stop", auth.RoleAnalyst, nil); rec.Code != http.StatusOK || decodeMap(t, rec)["status"] != "stopped" {
			t.Fatalf("stop after finish: %d %s", rec.Code, rec.Body.String())
		}
		if toy.leftover() != 0 {
			t.Fatalf("stopped campaign left %d objects on the target", toy.leftover())
		}
	})
}

// A second run for an engagement with an active campaign is refused with 409; once the first has
// finished, a new one is accepted. Different engagements are independent.
func TestOneActiveCampaignPerEngagement(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		toy.readFlaw = true
		toy.delay = 15 * time.Millisecond
		srv := httptest.NewServer(toy)
		defer srv.Close()
		engID := e.createEngagement(srv.URL)
		first := e.startRun(engID, srv.URL)

		rec := e.do(http.MethodPost, "/api/aleef/runs", auth.RoleAnalyst, aleefRunBody(engID, srv.URL))
		if rec.Code != http.StatusConflict {
			t.Fatalf("second run on an active engagement: %d %s", rec.Code, rec.Body.String())
		}
		other := e.createEngagement(srv.URL)
		second := e.startRun(other, srv.URL)

		for _, id := range []string{first, second} {
			e.do(http.MethodPost, "/api/aleef/runs/"+id+"/stop", auth.RoleAnalyst, nil)
		}
		e.waitRun(first, time.Minute)
		e.waitRun(second, time.Minute)
		third := e.startRun(engID, srv.URL)
		e.do(http.MethodPost, "/api/aleef/runs/"+third+"/stop", auth.RoleAnalyst, nil)
		e.waitRun(third, time.Minute)
	})
}

func TestAleefEnvSecrets(t *testing.T) {
	t.Setenv("ALEEF_SECRET_BANK_UAT_ALICE", "value-1")
	if v, err := (AleefEnvSecrets{}).Resolve("bank/uat/alice"); err != nil || v != "value-1" {
		t.Fatalf("resolve: %q %v", v, err)
	}
	for _, ref := range []string{"", "has space", "bank/uat/other", strings.Repeat("a", 65)} {
		if _, err := (AleefEnvSecrets{}).Resolve(ref); err == nil || strings.Contains(err.Error(), ref+"x") {
			t.Fatalf("ref %q: %v", ref, err)
		}
	}
}
