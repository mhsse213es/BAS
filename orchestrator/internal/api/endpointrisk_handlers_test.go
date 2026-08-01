package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetAgentRisk_UnknownAgent404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "no-such-agent-er")
		w := httptest.NewRecorder()
		h.GetAgentRisk(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestGetAgentRisk_KnownAgent_ReturnsAllCategories(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-h2-a1', 'ER-H2-HOST')`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-h2-run', 'er-h2-scn', 'ER H2 Run', 'er-h2-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1566","name":"Phishing","tactic":"initial-access"},"result":"pass","executedAt":"`+time.Now().UTC().Format(time.RFC3339)+`"}]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "er-h2-a1")
		w := httptest.NewRecorder()
		h.GetAgentRisk(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got endpointrisk.EndpointHealth
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got.Categories) != 9 {
			t.Errorf("got %d categories, want 9 (5 collected + 4 not-yet-collected)", len(got.Categories))
		}
	})
}
