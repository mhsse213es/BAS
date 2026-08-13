package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestGetPostureCatalog_FallsBackToDefaultForUnknownScenario proves a custom
// (unrecognized) scenario ID -- never in the agent's pre-harvested snapshot,
// since knownPostureScenarios() only covers the built-in set -- still gets a
// real catalog back via the "*" default-fallback entry, instead of an empty
// list. The agent genuinely runs every check for such a scenario via its own
// RunAllChecks() fallback at execution time; the catalog must agree.
func TestGetPostureCatalog_FallsBackToDefaultForUnknownScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, posture_catalog) VALUES ($1, $2, $3)`,
			"agent-pc-1", "HOST-PC-1",
			`{"safe-simulation":[{"id":"c1","phase":"p","name":"Known Check"}],"*":[{"id":"c2","phase":"p","name":"Default Check"}]}`)

		h := &Handler{db: pool}
		req := httptest.NewRequest(http.MethodGet, "/api/posture/catalog?agentId=agent-pc-1&scenario=my-custom-scenario", nil)
		rec := httptest.NewRecorder()
		h.GetPostureCatalog(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"id":"c2"`) {
			t.Fatalf("expected the default fallback catalog entry, got: %s", rec.Body.String())
		}
	})
}

// TestGetPostureCatalog_ReturnsExactMatchWhenPresent proves a recognized
// scenario ID's own catalog entry is returned as-is, never the default.
func TestGetPostureCatalog_ReturnsExactMatchWhenPresent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, posture_catalog) VALUES ($1, $2, $3)`,
			"agent-pc-2", "HOST-PC-2",
			`{"safe-simulation":[{"id":"c1","phase":"p","name":"Known Check"}],"*":[{"id":"c2","phase":"p","name":"Default Check"}]}`)

		h := &Handler{db: pool}
		req := httptest.NewRequest(http.MethodGet, "/api/posture/catalog?agentId=agent-pc-2&scenario=safe-simulation", nil)
		rec := httptest.NewRecorder()
		h.GetPostureCatalog(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, `"id":"c1"`) {
			t.Fatalf("expected the scenario's own catalog entry, got: %s", body)
		}
		if strings.Contains(body, `"id":"c2"`) {
			t.Fatalf("must not fall back to default when an exact match exists, got: %s", body)
		}
	})
}
