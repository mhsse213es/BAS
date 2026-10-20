package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// TestListRunDLPRecords_ReturnsStoredRecordsForRun seeds one stored DLP record
// for a real run and checks the endpoint returns it, and that an unknown run
// is a 404 rather than an empty success.
func TestListRunDLPRecords_ReturnsStoredRecordsForRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		const runID, scID = "run-dlp-records-api", "sc-dlp-records-api"
		engine := scenario.NewEngine(t.TempDir())
		if err := engine.SaveAs(ctx, &scenario.Scenario{ID: scID, Name: "DLP records API", Steps: []scenario.Step{
			{Name: "step-1", TechniqueID: "T1567.002", Framework: "custom", Command: "echo step-1"},
		}}, "user:test"); err != nil {
			t.Fatalf("save scenario: %v", err)
		}
		seedRunForScenario(t, pool, runID, "agent-dlp-records-api", scID)
		if _, err := pool.Exec(ctx,
			`INSERT INTO dlp_evidence_records (run_id, task_id, expectation_id, technique_id, scenario_id, record, created_at)
			 VALUES ($1, 'task-1', 'dlp-usb-block', 'T1567.002', $2,
			 '{"taskId":"task-1","expectationId":"dlp-usb-block","record":{"enforcement":"Blocked"}}', NOW())`,
			runID, scID); err != nil {
			t.Fatalf("seed dlp_evidence_records: %v", err)
		}

		h := New(pool, ws.NewHub(), engine, "")
		rec := httptest.NewRecorder()
		h.ListRunDLPRecords(rec, withURLParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"runId": runID}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"expectationId":"dlp-usb-block"`) || !strings.Contains(rec.Body.String(), `"Blocked"`) {
			t.Fatalf("stored record not returned: %s", rec.Body.String())
		}

		rec = httptest.NewRecorder()
		h.ListRunDLPRecords(rec, withURLParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"runId": "no-such-run"}))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("unknown run status = %d, want 404", rec.Code)
		}
	})
}
