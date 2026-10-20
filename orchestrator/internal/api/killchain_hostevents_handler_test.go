package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func postHostEvents(h *Handler, runID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/"+runID+"/host-events", strings.NewReader(body))
	if token != "" {
		req.Header.Set("X-Agent-Token", token)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("runId", runID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.SubmitRunHostEvents(rec, req)
	return rec
}

const hostEventsBody = `{"agentId":"he-a1","events":[{"recordId":101,"eventId":4688,"host":"WS-01",
  "ts":"2026-10-20T09:01:00Z","subject":"svc","newProcess":"rundll32.exe","commandLine":"x"}],
  "audit":{"processCreation":"disabled","logon":"enabled"}}`

func TestHostEvents_RequiresAgentAuth(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	h.agentSecret = "s3cret"
	if rec := postHostEvents(h, "r", "", hostEventsBody); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", rec.Code)
	}
}

func TestHostEvents_RefusesIdsOutsideTheRequiredSet(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		h.agentSecret = "s3cret"
		body := strings.Replace(hostEventsBody, `"eventId":4688`, `"eventId":4625`, 1)
		rec := postHostEvents(h, "anything", "s3cret", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "outside the required set") {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
	})
}

// A batch from an agent that did not run the scenario is refused, so one agent
// cannot write evidence into another agent's run.
func TestHostEvents_RefusesAnotherAgentsRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('he-owner', 'OWNER') ON CONFLICT DO NOTHING`)
		mustExecAPI(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, mode)
			VALUES ('he-run', 'credential-access', 'he', 'he-owner', 'completed', '[]', NOW(), 'posture')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		h.agentSecret = "s3cret"
		rec := postHostEvents(h, "he-run", "s3cret", hostEventsBody) // body names he-a1; the run belongs to he-owner
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 for another agent's run", rec.Code)
		}
	})
}

func TestHostEvents_AcceptsOwnAgentAndStores(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('he-a1', 'HE-A1') ON CONFLICT DO NOTHING`)
		mustExecAPI(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, mode)
			VALUES ('he-run2', 'credential-access', 'he2', 'he-a1', 'completed', '[]', NOW(), 'posture')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		h.agentSecret = "s3cret"
		rec := postHostEvents(h, "he-run2", "s3cret", hostEventsBody)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
		events, audit, _, found, err := db.KillChainStore{Pool: pool}.HostEventsForRun(context.Background(), "he-run2")
		if err != nil || !found || len(events) != 1 || string(audit.ProcessCreation) != "disabled" {
			t.Fatalf("stored: events=%d audit=%+v found=%v err=%v", len(events), audit, found, err)
		}
	})
}
