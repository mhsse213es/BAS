package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	apibasjobs "github.com/audspect/bas/internal/apibas/jobs"
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/secretstore"
)

func jobsRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.With(auth.RequirePermission(auth.CanManageAPIBASTargets)).Post("/api/apibas/targets", h.CreateAPIBASTarget)
	r.With(auth.RequirePermission(auth.CanRunAPIBAS)).Post("/api/apibas/jobs", h.SubmitAPIBASJob)
	r.With(auth.RequirePermission(auth.CanViewAPIBASRuns)).Get("/api/apibas/jobs/{id}", h.GetAPIBASJob)
	r.With(auth.RequirePermission(auth.CanRunAPIBAS)).Post("/api/apibas/jobs/{id}/cancel", h.CancelAPIBASJob)
	r.With(auth.RequirePermission(auth.CanRunAPIBAS)).Post("/api/apibas/approvals", h.RequestAPIBASApproval)
	r.With(auth.RequirePermission(auth.CanApproveAPIBASProduction)).Post("/api/apibas/approvals/{id}/approve", h.ApproveAPIBASApproval)
	r.With(auth.RequirePermission(auth.CanApproveAPIBASProduction)).Post("/api/apibas/approvals/{id}/revoke", h.RevokeAPIBASApproval)
	r.With(auth.RequirePermission(auth.CanViewAPIBASRuns)).Get("/api/apibas/approvals", h.ListAPIBASApprovals)
	r.With(auth.RequirePermission(auth.CanViewAPIBASRuns)).Get("/api/apibas/approvals/{id}", h.GetAPIBASApproval)
	r.With(auth.RequirePermission(auth.CanManageAPIBASTargets)).Post("/api/apibas/targets/{id}/inventory", h.ImportAPIBASInventory)
	r.With(auth.RequirePermission(auth.CanViewAPIBASRuns)).Get("/api/apibas/targets/{id}/inventory", h.GetAPIBASInventory)
	r.With(auth.RequirePermission(auth.CanViewAPIBASRuns)).Get("/api/apibas/targets/{id}/inventory/versions", h.ListAPIBASInventoryVersions)
	r.With(auth.RequirePermission(auth.CanViewAPIBASRuns)).Post("/api/apibas/targets/{id}/inventory/drift", h.DriftAPIBASInventory)
	r.With(auth.RequirePermission(auth.CanViewAPIBASRuns)).Post("/api/apibas/targets/{id}/binding/plan", h.PlanAPIBASBinding)
	return r
}

// jobsHandler returns a handler with a real job service whose runner path is any existing file. The background start is
// replaced by a no-op, so submitted jobs stay queued and the tests control the lifecycle.
func jobsHandler(t *testing.T, withService bool) *Handler {
	t.Helper()
	ctx := context.Background()
	if err := db.EnsureSecretStoreSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureAPIBASJobSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatal(err)
	}
	h := &Handler{db: sharedDB.Pool, apibasAsyncHook: func(func()) {}}
	if withService {
		store, err := secretstore.NewPGStore(sharedDB.Pool, credTestKey)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := apibasjobs.New(sharedDB.Pool, store, apibasjobs.Config{RunnerPath: os.Args[0], WorkDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		h.apibasJobs = svc
	}
	return h
}

func postAs(t *testing.T, h http.Handler, path string, body any, role auth.Role, user string) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	if role != "" {
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: user, Role: role}))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func targetBody(id, env string) map[string]any {
	ref, _ := secretstore.MakeRef("apibas_targets", id, "token")
	b := map[string]any{
		"id": id, "name": id, "base_url": "http://127.0.0.1:8099", "environment": env,
		"allowed_hosts": []string{"127.0.0.1:8099"}, "allowed_scenarios": []string{"API-BAS-AUTHZ-001"},
		"credential_refs": map[string]string{"apibas/lab/customer-a": ref}, "enabled": true,
	}
	if env != "lab" {
		b["allowed_paths"] = []string{"/api/orders"}
	}
	return b
}

func auditCount(t *testing.T, action, resource string) int {
	t.Helper()
	var n int
	if err := sharedDB.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE action = $1 AND resource = $2`, action, resource).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAPIBASJobRoleBoundaries(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	cases := []struct {
		name string
		path string
		body any
		role auth.Role
		want int
	}{
		{"no identity creates target", "/api/apibas/targets", targetBody("rb-t0", "lab"), "", http.StatusForbidden},
		{"viewer creates target", "/api/apibas/targets", targetBody("rb-t1", "lab"), auth.RoleViewer, http.StatusForbidden},
		{"analyst creates target", "/api/apibas/targets", targetBody("rb-t2", "lab"), auth.RoleAnalyst, http.StatusForbidden},
		{"admin creates target", "/api/apibas/targets", targetBody("rb-t3", "lab"), auth.RoleAdmin, http.StatusCreated},
		{"viewer submits job", "/api/apibas/jobs", map[string]any{}, auth.RoleViewer, http.StatusForbidden},
		{"no identity submits job", "/api/apibas/jobs", map[string]any{}, "", http.StatusForbidden},
	}
	for _, c := range cases {
		if rec := postAs(t, h, c.path, c.body, c.role, "u1"); rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d (%s)", c.name, rec.Code, c.want, rec.Body.String())
		}
	}
}

func TestAPIBASTargetRegistrationRefusals(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	mut := func(f func(m map[string]any)) map[string]any {
		m := targetBody("reg-ok", "lab")
		f(m)
		return m
	}
	cases := map[string]map[string]any{
		"plaintext credential": mut(func(m map[string]any) {
			m["credential_refs"] = map[string]string{"apibas/lab/customer-a": "sk-live-secret"}
		}),
		"host not in allowed": mut(func(m map[string]any) { m["allowed_hosts"] = []string{"10.0.0.9:8099"} }),
		"unknown scenario":    mut(func(m map[string]any) { m["allowed_scenarios"] = []string{"API-BAS-NOPE-999"} }),
		"no scenarios":        mut(func(m map[string]any) { m["allowed_scenarios"] = []string{} }),
		"bad environment":     mut(func(m map[string]any) { m["environment"] = "dev" }),
		"bad id":              mut(func(m map[string]any) { m["id"] = "../x" }),
		"non-http base url":   mut(func(m map[string]any) { m["base_url"] = "file:///etc/passwd" }),
		"unknown body field":  mut(func(m map[string]any) { m["allow_everything"] = true }),
	}
	for name, body := range cases {
		rec := postAs(t, h, "/api/apibas/targets", body, auth.RoleAdmin, "admin1")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", name, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "sk-live-secret") {
			t.Errorf("%s: the refused credential value appeared in the response", name)
		}
	}
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("reg-dup", "lab"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("first registration: %d", rec.Code)
	}
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("reg-dup", "lab"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusConflict {
		t.Errorf("duplicate registration: status = %d, want 409", rec.Code)
	}
	if auditCount(t, "apibas.target.create", "apibas-target:reg-dup") != 1 {
		t.Error("target registration did not leave exactly one audit record")
	}
}

func TestAPIBASJobSubmitFlow(t *testing.T) {
	hh := jobsHandler(t, true)
	h := jobsRouter(hh)
	for _, id := range []string{"flow-lab", "flow-prod"} {
		env := "lab"
		if id == "flow-prod" {
			env = "production"
		}
		if rec := postAs(t, h, "/api/apibas/targets", targetBody(id, env), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
			t.Fatalf("register %s: %d %s", id, rec.Code, rec.Body.String())
		}
	}
	submit := func(key, target string, scen ...string) *httptest.ResponseRecorder {
		if len(scen) == 0 {
			scen = []string{"API-BAS-AUTHZ-001"}
		}
		return postAs(t, h, "/api/apibas/jobs", map[string]any{
			"key": key, "target_id": target, "fixture": "orders-two-tenant", "scenario_ids": scen,
		}, auth.RoleAnalyst, "alice")
	}

	rec := submit("flow-key-0001", "flow-lab")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID      string `json:"id"`
		Created bool   `json:"created"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == "" || !created.Created {
		t.Fatalf("submit body = %s", rec.Body.String())
	}
	if auditCount(t, "apibas.job.submit", "apibas-job:"+created.ID) != 1 {
		t.Error("submit left no audit record with the requester")
	}
	var actor string
	_ = sharedDB.Pool.QueryRow(context.Background(),
		`SELECT actor_id FROM audit_logs WHERE action = 'apibas.job.submit' AND resource = $1`, "apibas-job:"+created.ID).Scan(&actor)
	if actor != "alice" {
		t.Errorf("audit actor = %q, want alice", actor)
	}

	if rec := submit("flow-key-0001", "flow-lab"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"created":false`) {
		t.Errorf("repeat key: %d %s; want 200 with created=false", rec.Code, rec.Body.String())
	}
	if rec := submit("flow-key-0002", "flow-lab"); rec.Code != http.StatusConflict {
		t.Errorf("second active job on one target: %d, want 409", rec.Code)
	}
	if rec := submit("flow-key-0003", "flow-prod"); rec.Code != http.StatusForbidden {
		t.Errorf("production target: %d, want 403", rec.Code)
	}
	if auditCount(t, "apibas.job.refused", "apibas-target:flow-prod") != 1 {
		t.Error("the production refusal left no audit record")
	}
	if rec := submit("flow-key-0004", "flow-lab", "API-BAS-DATA-102"); rec.Code != http.StatusForbidden && rec.Code != http.StatusConflict {
		t.Errorf("scenario outside scope: %d, want 403", rec.Code)
	}
	if rec := submit("flow-key-0005", "no-such-target"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown target: %d, want 404", rec.Code)
	}

	get := httptest.NewRecorder()
	greq := httptest.NewRequest(http.MethodGet, "/api/apibas/jobs/"+created.ID, nil)
	greq = greq.WithContext(auth.ContextWithClaims(greq.Context(), &auth.Claims{UserID: "u", Role: auth.RoleAnalyst}))
	h.ServeHTTP(get, greq)
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"status":"queued"`) {
		t.Errorf("get job: %d %s", get.Code, get.Body.String())
	}
	if strings.Contains(get.Body.String(), "customer-a") {
		t.Error("the job view exposed credential names or references")
	}
}

// Credentials given as values are stored encrypted, replaced by references, and never echoed, audited or kept in the target row.
func TestAPIBASTargetCredentialsAreWriteOnly(t *testing.T) {
	hh := jobsHandler(t, true)
	store, err := secretstore.NewPGStore(sharedDB.Pool, credTestKey)
	if err != nil {
		t.Fatal(err)
	}
	hh.WithSecretStore(store)
	h := jobsRouter(hh)
	body := targetBody("wo-target", "lab")
	delete(body, "credential_refs")
	body["credentials"] = map[string]string{"apibas/lab/customer-a": "VALUE-A-7731", "apibas/lab/customer-b": "VALUE-B-7731"}
	rec := postAs(t, h, "/api/apibas/targets", body, auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "VALUE-") {
		t.Error("a credential value appeared in the response")
	}
	tgt, err := db.GetAPIBASTarget(context.Background(), sharedDB.Pool, "wo-target")
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.CredentialRefs) != 2 {
		t.Fatalf("refs = %v, want two references", tgt.CredentialRefs)
	}
	for name, ref := range tgt.CredentialRefs {
		got, err := store.Get(context.Background(), ref)
		if err != nil || !strings.HasPrefix(got, "VALUE-") {
			t.Errorf("%s: store.Get(%s) = %q, %v; want the stored value", name, ref, got, err)
		}
	}
	var leaked int
	_ = sharedDB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE detail::text LIKE '%VALUE-%'`).Scan(&leaked)
	var inRow int
	_ = sharedDB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM apibas_targets WHERE credential_refs::text LIKE '%VALUE-%'`).Scan(&inRow)
	if leaked != 0 || inRow != 0 {
		t.Errorf("credential values leaked: audit rows=%d target rows=%d", leaked, inRow)
	}
	both := targetBody("wo-both", "lab")
	both["credentials"] = map[string]string{"apibas/lab/customer-a": "VALUE-C"}
	if rec := postAs(t, h, "/api/apibas/targets", both, auth.RoleAdmin, "admin1"); rec.Code != http.StatusBadRequest {
		t.Errorf("name given as both reference and value: %d, want 400", rec.Code)
	}
	noStore := jobsRouter(jobsHandler(t, false))
	withVals := targetBody("wo-nostore", "lab")
	withVals["credentials"] = map[string]string{"x": "VALUE-D"}
	if rec := postAs(t, noStore, "/api/apibas/targets", withVals, auth.RoleAdmin, "admin1"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("credentials with no secret store: %d, want 503", rec.Code)
	}
}

// Path scope is validated at registration: staging and production need prefixes, and malformed prefixes are refused.
func TestAPIBASTargetAllowedPaths(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	post := func(id, env string, paths any) int {
		b := targetBody(id, env)
		delete(b, "allowed_paths")
		if paths != nil {
			b["allowed_paths"] = paths
		}
		return postAs(t, h, "/api/apibas/targets", b, auth.RoleAdmin, "admin1").Code
	}
	if c := post("p-stg-none", "staging", nil); c != http.StatusBadRequest {
		t.Errorf("staging without allowed_paths: %d, want 400", c)
	}
	if c := post("p-lab-none", "lab", nil); c != http.StatusCreated {
		t.Errorf("lab without allowed_paths: %d, want 201", c)
	}
	for i, bad := range []string{"/", "api/orders", "/api/../x", "/api?x=1", "/api/%2e%2e/x", ""} {
		if c := post("p-bad-"+string(rune('a'+i)), "staging", []string{bad}); c != http.StatusBadRequest {
			t.Errorf("allowed_paths %q: %d, want 400", bad, c)
		}
	}
	if c := post("p-stg-ok", "staging", []string{"/api/orders", "/health"}); c != http.StatusCreated {
		t.Fatalf("staging with valid allowed_paths: %d, want 201", c)
	}
	tgt, err := db.GetAPIBASTarget(context.Background(), sharedDB.Pool, "p-stg-ok")
	if err != nil || len(tgt.AllowedPaths) != 2 {
		t.Errorf("stored paths = %v, %v; want two prefixes", tgt.AllowedPaths, err)
	}
}

func TestAPIBASJobEndpointsUnavailableWithoutService(t *testing.T) {
	h := jobsRouter(jobsHandler(t, false))
	rec := postAs(t, h, "/api/apibas/jobs", map[string]any{"key": "k"}, auth.RoleAnalyst, "alice")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("submit without a service: %d, want 503", rec.Code)
	}
	if rec := postAs(t, h, "/api/apibas/jobs/x/cancel", map[string]any{}, auth.RoleAnalyst, "alice"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("cancel without a service: %d, want 503", rec.Code)
	}
}
