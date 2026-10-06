package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func withRole(r *http.Request, userID string, role auth.Role) *http.Request {
	return r.WithContext(auth.ContextWithClaims(r.Context(), &auth.Claims{UserID: userID, Role: role}))
}

func vidRequest(method, vid string, body any) *http.Request {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/x", rd)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("vid", vid)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func lifecycleOf(t *testing.T, pool *pgxpool.Pool, vid string) (lc string, events int) {
	t.Helper()
	if err := pool.QueryRow(context.Background(), `SELECT lifecycle FROM content_versions WHERE id=$1`, vid).Scan(&lc); err != nil {
		t.Fatal(err)
	}
	_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM content_version_events WHERE content_version_id=$1`, vid).Scan(&events)
	return
}

func TestTransitionEndpoint_ApproveIntelDraftForLocalUse(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, reg, dir := registryEngine(t, pool)
		writeIntel(t, dir, "intel-ap", "id: intel-ap\nname: I\nlocal_check: true\n")
		_ = e.Load()
		h := New(pool, ws.NewHub(), e, "")
		vs, _ := reg.ListVersions(context.Background(), "intel-ap")
		req := withRole(vidRequest(http.MethodPost, vs[0].ID, map[string]string{"to": "PUBLISHED_LOCAL", "reason": "reviewed"}), "admin1", auth.RoleAdmin)
		rec := httptest.NewRecorder()
		h.TransitionContentVersion(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}
		if _, err := e.ResolveExecutable(context.Background(), "intel-ap"); err != nil {
			t.Fatalf("approved draft must now execute: %v", err)
		}
		var actor string
		_ = pool.QueryRow(context.Background(), `SELECT actor FROM content_version_events WHERE content_version_id=$1 ORDER BY id DESC LIMIT 1`, vs[0].ID).Scan(&actor)
		if actor != "user:admin1" {
			t.Fatalf("actor must come from claims, got %q", actor)
		}
		// Illegal transition -> 409.
		req2 := withRole(vidRequest(http.MethodPost, vs[0].ID, map[string]string{"to": "PUBLISHED"}), "admin1", auth.RoleAdmin)
		rec2 := httptest.NewRecorder()
		h.TransitionContentVersion(rec2, req2)
		if rec2.Code != http.StatusConflict {
			t.Fatalf("illegal transition code=%d", rec2.Code)
		}
	})
}

func TestTransitionEndpoint_IllegalChangesNothing(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, reg, dir := registryEngine(t, pool)
		writeIntel(t, dir, "intel-ill", "id: intel-ill\nname: I\nlocal_check: true\n")
		_ = e.Load()
		h := New(pool, ws.NewHub(), e, "")
		vs, _ := reg.ListVersions(context.Background(), "intel-ill")
		vid := vs[0].ID
		lc0, ev0 := lifecycleOf(t, pool, vid)
		// DRAFT -> PUBLISHED directly is illegal for a LOCAL version.
		rec := httptest.NewRecorder()
		h.TransitionContentVersion(rec, withRole(vidRequest(http.MethodPost, vid, map[string]string{"to": "PUBLISHED"}), "a", auth.RoleAdmin))
		if rec.Code < 400 || rec.Code >= 500 {
			t.Fatalf("illegal transition must be 4xx, got %d", rec.Code)
		}
		// A body-supplied actor is ignored; with no claims there is no human actor.
		rec = httptest.NewRecorder()
		body := map[string]string{"to": "PUBLISHED_LOCAL", "actor": "user:forged", "reason": "x"}
		h.TransitionContentVersion(rec, vidRequest(http.MethodPost, vid, body))
		if rec.Code < 400 || rec.Code >= 500 {
			t.Fatalf("no-claims transition must be 4xx, got %d", rec.Code)
		}
		if lc, ev := lifecycleOf(t, pool, vid); lc != lc0 || ev != ev0 {
			t.Fatalf("rejected transitions changed state: %s/%d -> %s/%d", lc0, ev0, lc, ev)
		}
		// Unknown version -> 404; malformed body -> 400.
		rec = httptest.NewRecorder()
		h.TransitionContentVersion(rec, withRole(vidRequest(http.MethodPost, "00000000-0000-0000-0000-000000000000", map[string]string{"to": "PUBLISHED_LOCAL"}), "a", auth.RoleAdmin))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("unknown version code=%d", rec.Code)
		}
		rec = httptest.NewRecorder()
		h.TransitionContentVersion(rec, withRole(vidRequest(http.MethodPost, vid, nil), "a", auth.RoleAdmin))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("bad body code=%d", rec.Code)
		}
	})
}

// Roles without CanTransitionContent are stopped by the route middleware.
func TestTransitionRoute_RequiresPermission(t *testing.T) {
	hit := false
	r := chi.NewRouter()
	r.With(auth.RequirePermission(auth.CanTransitionContent)).Post("/t", func(http.ResponseWriter, *http.Request) { hit = true })
	for _, role := range []auth.Role{auth.RoleAnalyst, auth.RoleViewer} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, withRole(httptest.NewRequest(http.MethodPost, "/t", nil), "u", role))
		if rec.Code != http.StatusForbidden || hit {
			t.Fatalf("role %s: code=%d handlerRan=%v", role, rec.Code, hit)
		}
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, withRole(httptest.NewRequest(http.MethodPost, "/t", nil), "u", auth.RoleAdmin))
	if rec.Code != http.StatusOK || !hit {
		t.Fatalf("admin must pass: code=%d", rec.Code)
	}
}

func TestArtifactEndpoint_SafeHeaders(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, reg, dir := registryEngine(t, pool)
		writeIntel(t, dir, "intel-art", "id: intel-art\nname: \"<script>alert(1)</script>\"\nlocal_check: true\n")
		_ = e.Load()
		h := New(pool, ws.NewHub(), e, "")
		vs, _ := reg.ListVersions(context.Background(), "intel-art")
		rec := httptest.NewRecorder()
		h.GetContentArtifact(rec, vidRequest(http.MethodGet, vs[0].ID, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code=%d", rec.Code)
		}
		hd := rec.Header()
		if ct := hd.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
			t.Fatalf("content-type %q", ct)
		}
		if hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Content-Disposition") == "" ||
			hd.Get("X-Artifact-SHA256") != vs[0].SHA256 {
			t.Fatalf("headers: %v", hd)
		}
		if !bytes.Equal(rec.Body.Bytes(), vs[0].Artifact) {
			t.Fatal("body must be the exact stored bytes")
		}
		rec = httptest.NewRecorder()
		h.GetContentArtifact(rec, vidRequest(http.MethodGet, "00000000-0000-0000-0000-000000000000", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("unknown code=%d", rec.Code)
		}
	})
}

func TestMigrationReport_IncludesBlockedSchedulesAndDetailEndpoint(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, reg, dir := registryEngine(t, pool)
		writeIntel(t, dir, "intel-mr", "id: intel-mr\nname: I\nlocal_check: true\n")
		_ = e.Load()
		h := New(pool, ws.NewHub(), e, "")
		rec := httptest.NewRecorder()
		h.GetContentMigrationReport(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code=%d %s", rec.Code, rec.Body.String())
		}
		var out map[string]json.RawMessage
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		for _, k := range []string{"migrated", "inventory", "blockedSchedules", "legacyIntel"} {
			if _, ok := out[k]; !ok {
				t.Fatalf("missing %q: %s", k, rec.Body.String())
			}
		}
		vs, _ := reg.ListVersions(context.Background(), "intel-mr")
		rec = httptest.NewRecorder()
		h.GetContentVersion(rec, vidRequest(http.MethodGet, vs[0].ID, nil))
		var d map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &d)
		if rec.Code != http.StatusOK || d["detectionEffectivenessStatus"] != "NO_DATA" {
			t.Fatalf("detail code=%d %s", rec.Code, rec.Body.String())
		}
	})
}

func TestListScenarios_CarriesRegistrySummary(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		_ = e.SaveAs(context.Background(), &scenario.Scenario{ID: "ls", Name: "L", LocalCheck: true}, "user:op")
		h := New(pool, ws.NewHub(), e, "")
		rec := httptest.NewRecorder()
		h.ListScenarios(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios", nil))
		var out []map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 1 {
			t.Fatalf("list: %s", rec.Body.String())
		}
		reg, _ := out[0]["registry"].(map[string]any)
		if reg == nil || reg["executableLifecycle"] != "PUBLISHED_LOCAL" || reg["executableVersion"].(float64) != 1 {
			t.Fatalf("registry summary: %v", out[0]["registry"])
		}
	})
}

// A registry failure must not break the list: enrichment is simply omitted.
func TestListScenarios_RegistryErrorOmitsEnrichment(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		_ = e.SaveAs(context.Background(), &scenario.Scenario{ID: "le", Name: "L", LocalCheck: true}, "user:op")
		h := New(pool, ws.NewHub(), e, "")
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Summaries' query fails on the cancelled context
		rec := httptest.NewRecorder()
		h.ListScenarios(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios", nil).WithContext(ctx))
		var out []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out) != 1 {
			t.Fatalf("list must still succeed: code=%d %s", rec.Code, rec.Body.String())
		}
		if _, has := out[0]["registry"]; has {
			t.Fatalf("enrichment must be omitted on registry error: %v", out[0])
		}
	})
}

// A human cannot fabricate VALIDATED: VALIDATING->VALIDATED is system-only.
func TestTransitionEndpoint_HumanCannotFabricateValidated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, reg, dir := registryEngine(t, pool)
		writeIntel(t, dir, "intel-val", "id: intel-val\nname: I\nlocal_check: true\n")
		_ = e.Load()
		h := New(pool, ws.NewHub(), e, "")
		vs, _ := reg.ListVersions(context.Background(), "intel-val")
		vid := vs[0].ID
		if err := reg.Transition(context.Background(), vid, contentregistry.LifecycleValidating, contentregistry.ActorIntake, ""); err != nil {
			t.Fatal(err)
		}
		lc0, ev0 := lifecycleOf(t, pool, vid)
		for _, to := range []string{"VALIDATED", "DRAFT"} {
			rec := httptest.NewRecorder()
			h.TransitionContentVersion(rec, withRole(vidRequest(http.MethodPost, vid, map[string]string{"to": to}), "admin1", auth.RoleAdmin))
			if rec.Code != http.StatusConflict {
				t.Fatalf("VALIDATING->%s by human: code=%d", to, rec.Code)
			}
		}
		if lc, ev := lifecycleOf(t, pool, vid); lc != lc0 || ev != ev0 || lc != "VALIDATING" {
			t.Fatalf("state changed: %s/%d -> %s/%d", lc0, ev0, lc, ev)
		}
	})
}

func TestRunEndpoints_UnknownRunIs404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		h := New(pool, ws.NewHub(), e, "")
		for name, fn := range map[string]http.HandlerFunc{"content": h.GetRunContent, "drift": h.GetRunDrift} {
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("runId", "no-such-run")
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			rec := httptest.NewRecorder()
			fn(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s: code=%d body=%s", name, rec.Code, rec.Body.String())
			}
		}
	})
}
