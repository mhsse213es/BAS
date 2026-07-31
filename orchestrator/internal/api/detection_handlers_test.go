package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSubmitRunDetections_ExtractsIOCs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('agent-1', 'HOST-1')`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results)
			VALUES ('run-ioc-1', 'sc-1', 'agent-1', 'test run', 'completed', $1)`,
			`[{"technique":{"id":"T1059"},"result":"fail","executedAt":"2026-07-31T00:00:00Z"}]`)

		h := &Handler{db: pool}
		body := `{"alerts":[{"channel":"edr","provider":"crowdstrike","eventId":1,
			"timestamp":"2026-07-31T00:00:05Z","threatName":"Trojan:Test",
			"processName":"powershell.exe","commandLine":"whoami /all"}]}`
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/run-ioc-1/detections", strings.NewReader(body))
		req = req.WithContext(context.Background())
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", "run-ioc-1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rec := httptest.NewRecorder()
		h.SubmitRunDetections(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM iocs WHERE value IN ('whoami /all', 'powershell.exe')`).Scan(&count); err != nil {
			t.Fatalf("count iocs: %v", err)
		}
		if count != 2 {
			t.Errorf("iocs extracted = %d, want 2", count)
		}

		var sightingScenario, techniqueID, verdict string
		if err := pool.QueryRow(context.Background(), `
			SELECT s.scenario_id, s.technique_id, s.detection_verdict FROM ioc_sightings s
			JOIN iocs i ON i.id = s.ioc_id WHERE i.value = 'whoami /all'`).
			Scan(&sightingScenario, &techniqueID, &verdict); err != nil {
			t.Fatalf("query sighting: %v", err)
		}
		if sightingScenario != "sc-1" {
			t.Errorf("sighting scenario_id = %q, want sc-1", sightingScenario)
		}
		if techniqueID != "T1059" {
			t.Errorf("sighting technique_id = %q, want T1059", techniqueID)
		}
		if verdict != "detected" {
			t.Errorf("sighting detection_verdict = %q, want detected", verdict)
		}
	})
}
