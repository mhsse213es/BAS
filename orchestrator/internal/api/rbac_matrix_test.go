package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/ws"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type authTier int

const (
	tierAny authTier = iota // any authenticated role (viewer, analyst, admin)
	tierAnalystAdmin
	tierAdminOnly
	tierPermission
)

type routeCase struct {
	method string
	path   string // chi path template, exactly as registered in routes.go
	tier   authTier
	perm   auth.Permission // only set when tier == tierPermission
}

// routeMatrix enumerates every route mounted inside the JWT-authenticated
// group in routes.go, paired with the role tier routes.go actually applies.
// This table is the single hand-maintained source of truth for 3a; the
// TestRBACMatrix_NoDrift test below keeps it honest against the live router.
var routeMatrix = []routeCase{
	// ── any authenticated role ──────────────────────────────────────────
	{http.MethodGet, "/api/agents", tierAny, ""},
	{http.MethodGet, "/api/agents/download/{platform}", tierAny, ""},
	{http.MethodGet, "/api/scenarios", tierAny, ""},
	{http.MethodGet, "/api/scenarios/{id}", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/report", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/report.json", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/attackflow", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/variant-coverage", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/variant-coverage/{techniqueId}", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/export", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/events", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/pdf", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/forensic.csv", tierAny, ""},
	{http.MethodGet, "/api/campaigns", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}/summary", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}/report", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}/pdf", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}/forensic.csv", tierAny, ""},
	{http.MethodGet, "/api/findings", tierAny, ""},
	{http.MethodGet, "/api/findings/{id}", tierAny, ""},
	{http.MethodGet, "/api/findings/{id}/tickets", tierAny, ""},
	{http.MethodGet, "/api/remediations", tierAny, ""},
	{http.MethodGet, "/api/ticketing/candidates", tierAny, ""},
	{http.MethodGet, "/api/ticketing/revalidation", tierAny, ""},
	{http.MethodGet, "/api/ticketing/summary", tierAny, ""},
	{http.MethodGet, "/api/reports", tierAny, ""},
	{http.MethodPost, "/api/reports", tierAny, ""},
	{http.MethodGet, "/api/agents/{agentId}/logs/operational", tierAny, ""},
	{http.MethodGet, "/api/agents/{agentId}/logs/security", tierAny, ""},
	{http.MethodGet, "/api/agents/{agentId}/telemetry", tierAny, ""},
	{http.MethodGet, "/api/rules", tierAny, ""},
	{http.MethodGet, "/api/rules/{id}", tierAny, ""},
	{http.MethodGet, "/api/rules/search", tierAny, ""},
	{http.MethodGet, "/api/rules/technique/{id}", tierAny, ""},
	{http.MethodGet, "/api/rules/export", tierAny, ""},
	{http.MethodPost, "/api/scan/safe/{agentId}", tierAny, ""},
	{http.MethodGet, "/api/art/techniques", tierAny, ""},
	{http.MethodGet, "/api/caldera/abilities", tierAny, ""},
	{http.MethodGet, "/api/techniques/unified", tierAny, ""},
	{http.MethodGet, "/api/crypto/info", tierAny, ""},
	{http.MethodGet, "/api/coverage/analytics", tierAny, ""},
	{http.MethodGet, "/api/ti/readiness", tierAny, ""},
	{http.MethodGet, "/api/ti/readiness/history", tierAny, ""},
	{http.MethodGet, "/api/ti/suggest-pack", tierAny, ""},
	{http.MethodGet, "/api/ti/priority", tierAny, ""},
	{http.MethodGet, "/api/adversary-templates", tierAny, ""},
	{http.MethodGet, "/api/caldera/adversaries", tierAny, ""},
	{http.MethodGet, "/api/caldera/adversaries/{adversaryId}", tierAny, ""},
	{http.MethodGet, "/api/posture/catalog", tierAny, ""},
	{http.MethodGet, "/api/attack/matrix", tierAny, ""},
	{http.MethodGet, "/api/attack/technique/{id}", tierAny, ""},
	{http.MethodGet, "/api/attackpath/summary", tierAny, ""},
	{http.MethodGet, "/api/attackpath/history", tierAny, ""},
	{http.MethodGet, "/api/attackpath/assets", tierAny, ""},
	{http.MethodGet, "/api/attackpath/schedule", tierAny, ""},
	{http.MethodGet, "/api/attackpath/subnet/{agentId}", tierAny, ""},
	{http.MethodGet, "/api/attackpath/jobs", tierAny, ""},
	{http.MethodGet, "/api/attackpath/jobs/{id}", tierAny, ""},
	{http.MethodGet, "/api/attackpath/correlation", tierAny, ""},
	{http.MethodGet, "/api/exercises/plans", tierAny, ""},
	{http.MethodGet, "/api/exercises/plans/{id}", tierAny, ""},
	{http.MethodGet, "/api/exercises/templates", tierAny, ""},
	{http.MethodGet, "/api/exercises/templates/{id}", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/evidence", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/evidence/verify", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/events", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/report.json", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/report.html", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/report.pdf", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/report.csv", tierAny, ""},
	{http.MethodPost, "/api/exercises/executions", tierAny, ""},
	{http.MethodPost, "/api/auth/change-password", tierAny, ""},
	{http.MethodGet, "/api/report/full/html", tierAny, ""},
	{http.MethodGet, "/api/report/full/pdf", tierAny, ""},
	{http.MethodGet, "/api/report/full/csv", tierAny, ""},
	{http.MethodGet, "/api/report/audit-pack", tierAny, ""},
	{http.MethodGet, "/api/compliance/frameworks", tierAny, ""},
	{http.MethodGet, "/api/compliance/report", tierAny, ""},
	{http.MethodGet, "/api/compliance/scores", tierAny, ""},
	{http.MethodGet, "/api/me/permissions", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/verifications", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/verifications/{expectationId}/history", tierAny, ""},
	{http.MethodGet, "/api/verifications/{id}/evidence", tierAny, ""},
	{http.MethodGet, "/api/evidence/{id}/download", tierAny, ""},
	{http.MethodGet, "/api/techniques/{id}/relationships", tierAny, ""},
	{http.MethodGet, "/api/relationships/{id}", tierAny, ""},
	{http.MethodGet, "/api/relationships/{id}/evidence", tierAny, ""},

	// ── analyst + admin ──────────────────────────────────────────────────
	{http.MethodPost, "/api/scan/{agentId}", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/attackpath/collect/{agentId}", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/attackpath/jobs", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/attackpath/jobs/{id}/cancel", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/attackpath/jobs/{id}/retry", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/attackpath/assets", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/scenarios/{id}/run", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/caldera/adversaries/{adversaryId}/run", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/adversary-templates/{id}/run", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/scenarios/runs/{runId}/cancel", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/siem/correlate/{runId}", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/detectverify/run/{runId}", tierAnalystAdmin, ""},
	{http.MethodGet, "/api/siem/correlations/{runId}", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/campaigns", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/campaigns/{id}/stop", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/findings/{id}/status", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/ticketing/push", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/ticketing/push/bulk", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/scenarios", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/scenarios/upload", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/scenarios/{id}/clone", tierAnalystAdmin, ""},
	{http.MethodPut, "/api/scenarios/{id}", tierAnalystAdmin, ""},
	{http.MethodDelete, "/api/scenarios/{id}", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/variants/generate", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/variants/run", tierAnalystAdmin, ""},
	{http.MethodGet, "/api/variants/run/{id}", tierAnalystAdmin, ""},
	{http.MethodGet, "/api/variants/coverage", tierAnalystAdmin, ""},
	{http.MethodGet, "/api/variants/stats", tierAnalystAdmin, ""},
	{http.MethodGet, "/api/payload-families", tierAnalystAdmin, ""},
	{http.MethodGet, "/api/payload-families/{techniqueId}", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/exercises/executions/{id}/launch", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/exercises/executions/{id}/abort", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/exercises/executions/{id}/steps/{stepId}/approve", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/exercises/executions/{id}/evidence", tierAnalystAdmin, ""},

	// ── admin only ───────────────────────────────────────────────────────
	{http.MethodPut, "/api/agents/{agentId}/state", tierAdminOnly, ""},
	{http.MethodGet, "/api/license", tierAdminOnly, ""},
	{http.MethodGet, "/api/config/connection", tierAdminOnly, ""},
	{http.MethodGet, "/api/users", tierAdminOnly, ""},
	{http.MethodPost, "/api/users", tierAdminOnly, ""},
	{http.MethodPut, "/api/users/{id}", tierAdminOnly, ""},
	{http.MethodDelete, "/api/users/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/users/{id}/reset-password", tierAdminOnly, ""},
	{http.MethodGet, "/api/caldera/status", tierAdminOnly, ""},
	{http.MethodGet, "/api/connector/status", tierAdminOnly, ""},
	{http.MethodPost, "/api/connector/sync", tierAdminOnly, ""},
	{http.MethodDelete, "/api/connector/scenarios/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/attackpath/schedule", tierAdminOnly, ""},
	{http.MethodGet, "/api/art/content/status", tierAdminOnly, ""},
	{http.MethodPost, "/api/art/content/reseed", tierAdminOnly, ""},
	{http.MethodGet, "/api/tamper-events", tierAdminOnly, ""},
	{http.MethodPost, "/api/tamper-events/{id}/acknowledge", tierAdminOnly, ""},
	{http.MethodPost, "/api/tamper-events/acknowledge-all", tierAdminOnly, ""},
	{http.MethodGet, "/api/audit-logs", tierAdminOnly, ""},
	{http.MethodGet, "/api/ticketing/configs", tierAdminOnly, ""},
	{http.MethodPost, "/api/ticketing/configs", tierAdminOnly, ""},
	{http.MethodPut, "/api/ticketing/configs/{id}", tierAdminOnly, ""},
	{http.MethodDelete, "/api/ticketing/configs/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/ticketing/configs/{id}/test", tierAdminOnly, ""},
	{http.MethodPost, "/api/ticketing/probe", tierAdminOnly, ""},
	{http.MethodPost, "/api/ticketing/probe/projects", tierAdminOnly, ""},
	{http.MethodPost, "/api/ticketing/sync", tierAdminOnly, ""},
	{http.MethodPost, "/api/payload-families", tierAdminOnly, ""},
	{http.MethodDelete, "/api/payload-families/{id}", tierAdminOnly, ""},
	{http.MethodGet, "/api/siem/configs", tierAdminOnly, ""},
	{http.MethodPost, "/api/siem/configs", tierAdminOnly, ""},
	{http.MethodPut, "/api/siem/configs/{id}", tierAdminOnly, ""},
	{http.MethodDelete, "/api/siem/configs/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/siem/configs/{id}/test", tierAdminOnly, ""},
	{http.MethodGet, "/api/detectverify/configs", tierAdminOnly, ""},
	{http.MethodPost, "/api/detectverify/configs", tierAdminOnly, ""},
	{http.MethodPut, "/api/detectverify/configs/{id}", tierAdminOnly, ""},
	{http.MethodDelete, "/api/detectverify/configs/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/detectverify/configs/{id}/test", tierAdminOnly, ""},
	{http.MethodPost, "/api/exercises/plans", tierAdminOnly, ""},
	{http.MethodPost, "/api/exercises/plans/validate", tierAdminOnly, ""},
	{http.MethodPut, "/api/exercises/plans/{id}", tierAdminOnly, ""},
	{http.MethodDelete, "/api/exercises/plans/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/exercises/templates", tierAdminOnly, ""},
	{http.MethodPost, "/api/exercises/templates/{id}/instantiate", tierAdminOnly, ""},

	// ── fine-grained permission gates ───────────────────────────────────
	{http.MethodPost, "/api/verifications", tierPermission, auth.CanVerify},
	{http.MethodPost, "/api/verifications/{id}/evidence", tierPermission, auth.CanUploadEvidence},
	{http.MethodDelete, "/api/evidence/{id}", tierPermission, auth.CanDeleteEvidence},
	{http.MethodPost, "/api/relationships", tierPermission, auth.CanCurateThreatIntel},
	{http.MethodPut, "/api/relationships/{id}", tierPermission, auth.CanCurateThreatIntel},
	{http.MethodPost, "/api/relationships/{id}/evidence", tierPermission, auth.CanCurateThreatIntel},
	{http.MethodDelete, "/api/relationship-evidence/{id}", tierPermission, auth.CanCurateThreatIntel},
	{http.MethodPost, "/api/relationships/{id}/review", tierPermission, auth.CanReviewThreatIntel},
	{http.MethodPost, "/api/relationships/{id}/status", tierPermission, auth.CanReviewThreatIntel},
}

// publicRoutes lists every routes.go registration OUTSIDE the JWT-authenticated
// group — these are intentionally excluded from routeMatrix and from the
// drift guard's "must have a matrix entry" requirement.
var publicRoutes = map[string]bool{
	"POST /api/auth/login":                        true,
	"POST /api/auth/logout":                       true,
	"POST /api/auth/setup":                        true,
	"GET /api/agents/ping":                        true,
	"POST /api/agents/enroll":                     true,
	"POST /api/agents/events":                     true,
	"POST /api/heartbeat":                         true,
	"POST /api/scenarios/result":                  true,
	"POST /api/scenarios/events":                  true,
	"POST /api/scenarios/runs/{runId}/detections": true,
	"POST /api/attackpath/collect":                true,
	"POST /api/attackpath/sharphound":             true,
	"POST /api/attackpath/jobs/{id}/ack":          true,
	"GET /ws/agent":                               true,
	"GET /ws/browser":                             true,
	"POST /api/ticketing/webhook/{configId}":      true,
	"GET /health":                                 true,
}

func tierAllows(tier authTier, perm auth.Permission, role auth.Role) bool {
	switch tier {
	case tierAny:
		return true
	case tierAnalystAdmin:
		return role == auth.RoleAdmin || role == auth.RoleAnalyst
	case tierAdminOnly:
		return role == auth.RoleAdmin
	case tierPermission:
		return auth.HasPermission(role, perm)
	default:
		return false
	}
}

var paramPattern = regexp.MustCompile(`\{[^}]+\}`)

func concretePath(tpl string) string {
	return paramPattern.ReplaceAllString(tpl, "x")
}

func mountTestRouter(t *testing.T) http.Handler {
	t.Helper()
	h := New(sharedDB.Pool, ws.NewHub(), nil, testJWTSecret)
	return Mount(h, ws.NewHub(), testJWTSecret, "", http.NotFoundHandler())
}

func TestRBACMatrix_AuthorizationBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)

		identities := []struct {
			name string
			role auth.Role
			anon bool
		}{
			{"anonymous", "", true},
			{"viewer", auth.RoleViewer, false},
			{"analyst", auth.RoleAnalyst, false},
			{"admin", auth.RoleAdmin, false},
		}

		for _, rc := range routeMatrix {
			for _, id := range identities {
				t.Run(rc.method+" "+rc.path+"/"+id.name, func(t *testing.T) {
					req := httptest.NewRequest(rc.method, concretePath(rc.path), nil)
					if !id.anon {
						tok, err := auth.GenerateToken("matrix-"+id.name, id.role, testJWTSecret, time.Hour)
						if err != nil {
							t.Fatalf("mint token: %v", err)
						}
						req.Header.Set("Authorization", "Bearer "+tok)
					}
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)

					if id.anon {
						if rec.Code != http.StatusUnauthorized {
							t.Fatalf("anonymous: status = %d, want 401", rec.Code)
						}
						return
					}
					if tierAllows(rc.tier, rc.perm, id.role) {
						if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
							t.Fatalf("role %s should clear the authz gate for %s %s, got %d", id.role, rc.method, rc.path, rec.Code)
						}
						return
					}
					if rec.Code != http.StatusForbidden {
						t.Fatalf("role %s should be forbidden from %s %s, got %d", id.role, rc.method, rc.path, rec.Code)
					}
				})
			}
		}
	})
}

// TestRBACMatrix_NoDrift keeps routeMatrix honest against the live router in
// both directions: every authenticated route chi actually registered must
// have a matrix entry (positive drift — a new route added without a role
// decision), and every matrix entry must correspond to a route chi actually
// registered (negative drift — a stale entry for a renamed/removed route).
func TestRBACMatrix_NoDrift(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		mux, ok := router.(chi.Routes)
		if !ok {
			t.Fatalf("Mount() returned %T, not a chi.Routes", router)
		}

		walked := map[string]bool{}
		err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			if route == "/*" {
				return nil
			}
			key := method + " " + route
			if publicRoutes[key] {
				return nil
			}
			walked[key] = true
			return nil
		})
		if err != nil {
			t.Fatalf("chi.Walk: %v", err)
		}

		matrixed := map[string]bool{}
		for _, rc := range routeMatrix {
			matrixed[rc.method+" "+rc.path] = true
		}

		for k := range walked {
			if !matrixed[k] {
				t.Errorf("registered route %q has no routeMatrix entry", k)
			}
		}
		for k := range matrixed {
			if !walked[k] {
				t.Errorf("routeMatrix entry %q does not correspond to a route chi.Walk found", k)
			}
		}
	})
}

// TestRBACMatrix_MethodConfusion samples one route per tier and drives every
// HTTP method chi supports against its exact path, pinning whichever
// precedence chi's routing actually exhibits between "unregistered method on
// a known path" (405) and the auth middleware (401/403) — not presupposing
// either order.
func TestRBACMatrix_MethodConfusion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		// Each sample path is single-method in routeMatrix (verified: grepping
		// the matrix for each literal path yields exactly one entry) so the
		// method sweep below can safely treat every other method as
		// unregistered without colliding with a genuinely-registered method
		// on the same path under a different tier.
		samples := []struct {
			method string
			path   string
		}{
			{http.MethodGet, "/api/crypto/info"},        // tierAny
			{http.MethodPost, "/api/variants/generate"}, // tierAnalystAdmin
			{http.MethodGet, "/api/license"},            // tierAdminOnly
			{http.MethodPost, "/api/verifications"},     // tierPermission
		}
		methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions}

		for _, s := range samples {
			for _, m := range methods {
				t.Run(m+" "+s.path, func(t *testing.T) {
					req := httptest.NewRequest(m, s.path, nil)
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					if m == s.method {
						// The registered method — must not be a routing-level 404/405.
						if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
							t.Fatalf("registered method %s %s got routing status %d", m, s.path, rec.Code)
						}
						return
					}
					// Empirically observed (not presumed): with the "/*" catch-all
					// static handler mounted at the router root, chi falls through
					// to that wildcard route for a path+method combination with no
					// matching handler, rather than emitting a 405. It never reaches
					// the auth middleware — auth state has no bearing on this status.
					if rec.Code != http.StatusNotFound {
						t.Fatalf("unregistered method %s %s: status = %d, want 404 (falls through to the static catch-all)", m, s.path, rec.Code)
					}
				})
			}
		}
	})
}

func TestUserHandlers_MalformedPathParams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		adminID := seedUser(t, pool, "peggy", "password123", "admin", true)

		// Empty id segment.
		req := withURLParam(authedRequest(t, http.MethodDelete, "/api/users/", nil, auth.RoleAdmin, adminID), "id", "")
		rec := callAuthed(h.DeleteUser, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("empty id: status = %d, want 204 (DELETE ... WHERE id='' affects 0 rows, no error)", rec.Code)
		}

		// SQL-metacharacter id — must be treated as inert parameterized data.
		req2 := withURLParam(authedRequest(t, http.MethodDelete, "/api/users/x", nil, auth.RoleAdmin, adminID), "id", "' OR 1=1--")
		rec2 := callAuthed(h.DeleteUser, req2)
		if rec2.Code != http.StatusNoContent {
			t.Fatalf("SQL-metacharacter id: status = %d, want 204", rec2.Code)
		}
		var remaining int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM users`).Scan(&remaining); err != nil {
			t.Fatalf("count users: %v", err)
		}
		if remaining != 1 {
			t.Fatalf("user count after SQL-metacharacter delete attempt = %d, want 1 (only the untouched admin row)", remaining)
		}
	})
}
