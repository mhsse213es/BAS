package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetPhishingRunReport_NotFound_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/phishing-runs/no-such-id/report", nil, auth.RoleAnalyst, "")
		req = withURLParam(req, "id", "no-such-id")
		rec := callAuthed(h.GetPhishingRunReport, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s, want 404", rec.Code, rec.Body.String())
		}
	})
}

// TestGetPhishingRunReport_Completed_RendersHTMLFromPersistedResult
// proves the report endpoint renders from the run actually persisted
// by ExecutePhishingRun -- a real trigger, then a real report read --
// never from invented or re-evaluated data.
func TestGetPhishingRunReport_Completed_RendersHTMLFromPersistedResult(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		anchor := executionCreatedAt(t, pool, execID)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithPhishingRun(phishbridge.NewFixtureReportTicketProvider([]phishbridge.ReportTicketEvidence{{
				ExecutionID: execID, TargetID: "target-1", TicketCreated: true, Timestamp: anchor.Add(time.Hour),
			}}))
		triggerRec := callAuthed(h.TriggerPhishingRun, triggerPhishingRunReq(t, pool, map[string]any{
			"scenarioId": "PH-DET-002", "parameters": map[string]any{"executionId": execID, "targetId": "target-1"},
		}))
		if triggerRec.Code != http.StatusCreated {
			t.Fatalf("trigger status = %d, body = %s", triggerRec.Code, triggerRec.Body.String())
		}
		var triggered struct{ ID string }
		if err := json.Unmarshal(triggerRec.Body.Bytes(), &triggered); err != nil {
			t.Fatalf("decode trigger response: %v", err)
		}

		reportReq := authedRequest(t, http.MethodGet, "/api/phishing-runs/"+triggered.ID+"/report", nil, auth.RoleAnalyst, "")
		reportReq = withURLParam(reportReq, "id", triggered.ID)
		reportRec := callAuthed(h.GetPhishingRunReport, reportReq)
		if reportRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s, want 200", reportRec.Code, reportRec.Body.String())
		}
		if ct := reportRec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
		}
		body := reportRec.Body.String()
		if !strings.Contains(body, "pass") || !strings.Contains(body, "Response") {
			t.Errorf("report body missing expected content, got: %s", body)
		}
	})
}
