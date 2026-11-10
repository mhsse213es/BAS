package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
)

func TestAPIBASTargetJobsList(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	for _, id := range []string{"tj-1", "tj-2"} {
		if rec := postAs(t, h, "/api/apibas/targets", targetBody(id, "lab"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
			t.Fatalf("register %s: %d", id, rec.Code)
		}
	}
	ctx := context.Background()
	submit := func(target, key string) string {
		rec := postAs(t, h, "/api/apibas/jobs", map[string]any{"key": key, "target_id": target, "fixture": "orders-two-tenant", "scenario_ids": []string{"API-BAS-AUTHZ-001"}}, auth.RoleAdmin, "admin1")
		if rec.Code != http.StatusAccepted {
			t.Fatalf("submit %s: %d %s", key, rec.Code, rec.Body.String())
		}
		return decode(t, rec)["id"].(string)
	}
	finish := func(id, result string) {
		if ok, err := db.StartAPIBASJob(ctx, sharedDB.Pool, id); err != nil || !ok {
			t.Fatalf("start: %v %v", ok, err)
		}
		if err := db.FinishAPIBASJob(ctx, sharedDB.Pool, id, "completed", "", []db.APIBASJobReport{
			{ScenarioID: "API-BAS-AUTHZ-001", RunTag: "tag-" + id[:8], Result: result, Reason: "", Report: []byte(`{}`)},
		}); err != nil {
			t.Fatalf("finish: %v", err)
		}
	}

	// A target with no jobs lists none, as an empty array.
	rec := getAsUser(t, h, "/api/apibas/targets/tj-2/jobs", auth.RoleAnalyst, "a1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"jobs":[]`) {
		t.Fatalf("empty list: %d %s", rec.Code, rec.Body.String())
	}

	first := submit("tj-1", "tj-key-1")
	finish(first, "FAIL")
	second := submit("tj-1", "tj-key-2") // queued, not finished
	other := submit("tj-2", "tj-key-3")
	_ = other

	rec = getAsUser(t, h, "/api/apibas/targets/tj-1/jobs", auth.RoleAnalyst, "a1")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	jobs := decode(t, rec)["jobs"].([]any)
	if len(jobs) != 2 {
		t.Fatalf("%d jobs for tj-1, want 2 (the other target's job must not appear): %s", len(jobs), rec.Body.String())
	}
	newest := jobs[0].(map[string]any)
	oldest := jobs[1].(map[string]any)
	if newest["id"] != second || newest["status"] != "queued" || oldest["id"] != first || oldest["status"] != "completed" {
		t.Errorf("order or status wrong: %v", jobs)
	}
	res := oldest["results"].(map[string]any)
	if res["fail"].(float64) != 1 || res["pass"].(float64) != 0 || oldest["scenarios"].(float64) != 1 || oldest["bound"] != false {
		t.Errorf("results: %v", oldest)
	}
	// The list carries neither credential references nor report bodies.
	if strings.Contains(rec.Body.String(), "credential") || strings.Contains(rec.Body.String(), "cred:") || strings.Contains(rec.Body.String(), "run_tag") {
		t.Errorf("the list exposes more than a summary: %s", rec.Body.String())
	}

	// limit is validated and applied.
	if rec := getAsUser(t, h, "/api/apibas/targets/tj-1/jobs?limit=1", auth.RoleAnalyst, "a1"); len(decode(t, rec)["jobs"].([]any)) != 1 {
		t.Errorf("limit=1: %s", rec.Body.String())
	}
	for _, bad := range []string{"0", "-1", "101", "x"} {
		if rec := getAsUser(t, h, "/api/apibas/targets/tj-1/jobs?limit="+bad, auth.RoleAnalyst, "a1"); rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%s: %d, want 400", bad, rec.Code)
		}
	}
	// Unknown target and unauthenticated caller.
	if rec := getAsUser(t, h, "/api/apibas/targets/nope-1/jobs", auth.RoleAnalyst, "a1"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown target: %d", rec.Code)
	}
	if rec := getAsUser(t, h, "/api/apibas/targets/tj-1/jobs", "", ""); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Errorf("unauthenticated: %d", rec.Code)
	}
}

// The API BAS routes the console and the runbook depend on must be on the real router. The RBAC matrix cannot catch a route that
// is missing from both the router and the matrix, so this names them.
func TestAPIBASRoutesAreRegistered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(_ *pgxpool.Pool) {
		mux, ok := mountTestRouter(t).(chi.Routes)
		if !ok {
			t.Fatal("router is not a chi.Routes")
		}
		have := map[string]bool{}
		_ = chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			have[method+" "+route] = true
			return nil
		})
		for _, want := range []string{
			"GET /api/apibas/targets", "POST /api/apibas/targets", "GET /api/apibas/targets/{id}/jobs",
			"POST /api/apibas/targets/{id}/inventory", "GET /api/apibas/targets/{id}/inventory", "GET /api/apibas/targets/{id}/inventory/versions",
			"POST /api/apibas/targets/{id}/inventory/drift", "POST /api/apibas/targets/{id}/binding/plan",
			"PUT /api/apibas/targets/{id}/binding", "GET /api/apibas/targets/{id}/binding", "DELETE /api/apibas/targets/{id}/binding",
			"POST /api/apibas/targets/{id}/binding/jobs", "POST /api/apibas/jobs", "GET /api/apibas/jobs/{id}",
		} {
			if !have[want] {
				t.Errorf("route %s is not registered", want)
			}
		}
	})
}
