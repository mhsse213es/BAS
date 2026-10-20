package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func postGroundTruth(h *Handler, runID, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/killchain/runs/"+runID+"/ground-truth", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("runId", runID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.RecordKillChainGroundTruth(rec, req)
	return rec
}

func TestGroundTruthHandler_RefusesRunRecordAndAcceptsIndependentSource(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('gt-a1', 'GT-HOST') ON CONFLICT DO NOTHING`)
		mustExecAPI(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, mode)
			VALUES ('gt-run', 'credential-access', 'gt', 'gt-a1', 'completed', '[]', NOW(), 'posture')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)

		refused := postGroundTruth(h, "gt-run",
			`{"source":"scenario run record (not independent of Audspect)","executed":"yes","reference":"x"}`)
		if refused.Code != http.StatusBadRequest || !strings.Contains(refused.Body.String(), "not independent") {
			t.Fatalf("run-record source: status=%d body=%s", refused.Code, refused.Body.String())
		}

		ok := postGroundTruth(h, "gt-run",
			`{"source":"dc-01 security log","sourceClass":"host_event_log","executed":"yes","reference":"gt-host:evt-42"}`)
		if ok.Code != http.StatusCreated {
			t.Fatalf("independent source: status=%d body=%s", ok.Code, ok.Body.String())
		}
	})
}

func TestGroundTruthHandler_WithoutDatabaseIs503(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	if rec := postGroundTruth(h, "x", `{}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
