package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishingrun"
	"github.com/audspect/bas/internal/phishval"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// TestPhishingRunPipeline_EndToEnd proves the full vertical slice as
// one path: a real authorized trigger, a real persisted terminal
// status, and a report rendered from that same persisted result --
// never three independently-plausible but disconnected pieces.
func TestPhishingRunPipeline_EndToEnd(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithPhishingRun(phishbridge.NewFixtureReportTicketProvider([]phishbridge.ReportTicketEvidence{{
				ExecutionID: "exec-1", TargetID: "target-1", TicketCreated: true, Timestamp: time.Now(),
			}}))

		triggerRec := callAuthed(h.TriggerPhishingRun, triggerPhishingRunReq(t, pool, map[string]any{
			"scenarioId": "PH-DET-002", "parameters": map[string]any{"executionId": "exec-1", "targetId": "target-1"},
		}))
		if triggerRec.Code != http.StatusCreated {
			t.Fatalf("trigger status = %d, body = %s, want 201", triggerRec.Code, triggerRec.Body.String())
		}
		var triggered phishingrun.PhishingRun
		if err := json.Unmarshal(triggerRec.Body.Bytes(), &triggered); err != nil {
			t.Fatalf("decode trigger response: %v", err)
		}
		switch triggered.Status {
		case phishingrun.StatusPending, phishingrun.StatusRunning, phishingrun.StatusCompleted:
		default:
			t.Fatalf("trigger Status = %q, want one of pending/running/completed", triggered.Status)
		}

		getReq := authedRequest(t, http.MethodGet, "/api/phishing-runs/"+triggered.ID, nil, auth.RoleAnalyst, "")
		getReq = withURLParam(getReq, "id", triggered.ID)
		getRec := callAuthed(h.GetPhishingRun, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("GET status = %d, body = %s, want 200", getRec.Code, getRec.Body.String())
		}
		var fetched phishingrun.PhishingRun
		if err := json.Unmarshal(getRec.Body.Bytes(), &fetched); err != nil {
			t.Fatalf("decode GET: %v", err)
		}
		if fetched.Status != phishingrun.StatusCompleted {
			t.Fatalf("Status = %q, want completed", fetched.Status)
		}
		var outcome phishval.Outcome
		if err := json.Unmarshal(fetched.Result, &outcome); err != nil {
			t.Fatalf("unmarshal Result: %v", err)
		}
		if outcome.Response.Verdict != phishval.VerdictPass {
			t.Fatalf("Response.Verdict = %q, want pass", outcome.Response.Verdict)
		}

		reportReq := authedRequest(t, http.MethodGet, "/api/phishing-runs/"+triggered.ID+"/report", nil, auth.RoleAnalyst, "")
		reportReq = withURLParam(reportReq, "id", triggered.ID)
		reportRec := callAuthed(h.GetPhishingRunReport, reportReq)
		if reportRec.Code != http.StatusOK {
			t.Fatalf("report status = %d, body = %s, want 200", reportRec.Code, reportRec.Body.String())
		}
		body := strings.ToLower(reportRec.Body.String())
		if !strings.Contains(body, "pass") {
			t.Error("report body must contain the pass verdict")
		}
		if strings.Contains(reportRec.Body.String(), "EXPERIMENTAL") {
			t.Error("PH-DET-002 is not experimental -- report must not carry the EXPERIMENTAL banner")
		}
	})
}

// TestPhishingRunPipeline_NoEvidence_ReportShowsNotTestedNeverPass is
// this initiative's single most safety-critical behavior: absent
// evidence must never be reported as a passing control.
func TestPhishingRunPipeline_NoEvidence_ReportShowsNotTestedNeverPass(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithPhishingRun(phishbridge.NewFixtureReportTicketProvider(nil))

		triggerRec := callAuthed(h.TriggerPhishingRun, triggerPhishingRunReq(t, pool, map[string]any{
			"scenarioId": "PH-DET-002", "parameters": map[string]any{"executionId": "exec-1", "targetId": "target-1"},
		}))
		if triggerRec.Code != http.StatusCreated {
			t.Fatalf("trigger status = %d, body = %s, want 201", triggerRec.Code, triggerRec.Body.String())
		}
		var triggered phishingrun.PhishingRun
		_ = json.Unmarshal(triggerRec.Body.Bytes(), &triggered)

		getReq := authedRequest(t, http.MethodGet, "/api/phishing-runs/"+triggered.ID, nil, auth.RoleAnalyst, "")
		getReq = withURLParam(getReq, "id", triggered.ID)
		getRec := callAuthed(h.GetPhishingRun, getReq)
		var fetched phishingrun.PhishingRun
		if err := json.Unmarshal(getRec.Body.Bytes(), &fetched); err != nil {
			t.Fatalf("decode GET: %v", err)
		}
		var outcome phishval.Outcome
		if err := json.Unmarshal(fetched.Result, &outcome); err != nil {
			t.Fatalf("unmarshal Result: %v", err)
		}
		if outcome.Response.Verdict != phishval.VerdictNotTested {
			t.Fatalf("Response.Verdict = %q, want not_tested (absent evidence must never become pass)", outcome.Response.Verdict)
		}

		reportReq := authedRequest(t, http.MethodGet, "/api/phishing-runs/"+triggered.ID+"/report", nil, auth.RoleAnalyst, "")
		reportReq = withURLParam(reportReq, "id", triggered.ID)
		reportRec := callAuthed(h.GetPhishingRunReport, reportReq)
		if strings.Contains(strings.ToLower(reportRec.Body.String()), "pass") {
			t.Error("report body must never contain a pass verdict when no evidence was found")
		}
	})
}

// TestPhishingRunPipeline_UnconfiguredProvider_RefusedBeforeRun proves the
// shipped configuration -- a Handler built with New(...) and no WithPhishingRun
// call -- refuses PH-DET-002 before any run is created. The library reports the
// same dependency as unavailable, so a stale UI cannot start a run that cannot
// finish. No run row may exist afterwards.
func TestPhishingRunPipeline_UnconfiguredProvider_RefusedBeforeRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret) // no WithPhishingRun

		triggerRec := callAuthed(h.TriggerPhishingRun, triggerPhishingRunReq(t, pool, map[string]any{
			"scenarioId": "PH-DET-002", "parameters": map[string]any{"executionId": "exec-1", "targetId": "target-1"},
		}))
		if triggerRec.Code != http.StatusConflict {
			t.Fatalf("trigger status = %d, body = %s, want 409", triggerRec.Code, triggerRec.Body.String())
		}
		if !strings.Contains(triggerRec.Body.String(), "itsm_connector_not_configured") {
			t.Errorf("body %q must name the missing dependency", triggerRec.Body.String())
		}
		var rows int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM phishing_runs WHERE scenario_id = 'PH-DET-002'`).Scan(&rows); err != nil {
			t.Fatalf("count runs: %v", err)
		}
		if rows != 0 {
			t.Errorf("refused trigger still created %d run row(s)", rows)
		}
	})
}

// TestPhishingRunPipeline_Unauthorized_401Then403 proves the denial
// happens before ExecutePhishingRun ever runs, in both failure modes
// -- no rows created in either case, not just the right status code.
func TestPhishingRunPipeline_Unauthorized_401Then403(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		body, _ := json.Marshal(map[string]any{"scenarioId": "PH-DET-002", "parameters": map[string]any{"executionId": "exec-1", "targetId": "target-1"}})

		anonReq := httptest.NewRequest(http.MethodPost, "/api/phishing-runs", bytes.NewReader(body))
		anonRec := httptest.NewRecorder()
		router.ServeHTTP(anonRec, anonReq)
		if anonRec.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous status = %d, want 401", anonRec.Code)
		}

		tenantID := "default"
		viewerTok, err := auth.GenerateTenantToken("e2e-viewer", auth.RoleViewer, &tenantID, false, testJWTSecret, time.Hour)
		if err != nil {
			t.Fatalf("mint token: %v", err)
		}
		viewerReq := httptest.NewRequest(http.MethodPost, "/api/phishing-runs", bytes.NewReader(body))
		viewerReq.Header.Set("Authorization", "Bearer "+viewerTok)
		viewerRec := httptest.NewRecorder()
		router.ServeHTTP(viewerRec, viewerReq)
		if viewerRec.Code != http.StatusForbidden {
			t.Fatalf("viewer status = %d, want 403", viewerRec.Code)
		}

		runs, err := db.ListPhishingRuns(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("ListPhishingRuns: %v", err)
		}
		if len(runs) != 0 {
			t.Errorf("rows created = %d, want 0 (neither denied request must reach ExecutePhishingRun)", len(runs))
		}
	})
}

func TestPhishingRunPipeline_UnknownScenario_400NoRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		rec := callAuthed(h.TriggerPhishingRun, triggerPhishingRunReq(t, pool, map[string]any{"scenarioId": "PH-BEC-002"}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
		}
		runs, err := db.ListPhishingRuns(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("ListPhishingRuns: %v", err)
		}
		if len(runs) != 0 {
			t.Errorf("rows created = %d, want 0", len(runs))
		}
	})
}

// TestEnsurePhishingRunSchema_SafeAcrossRepeatedServerStartups
// simulates 3 server restarts in a row against the same pool: must
// never error, and a row inserted between calls must survive.
func TestEnsurePhishingRunSchema_SafeAcrossRepeatedServerStartups(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
			t.Fatalf("ensure #1: %v", err)
		}
		if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
			t.Fatalf("ensure #2: %v", err)
		}

		run := &phishingrun.PhishingRun{ID: "restart-run-1", ScenarioID: "PH-DET-002", Status: phishingrun.StatusCompleted, StartedAt: time.Now()}
		if err := db.InsertPhishingRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}

		if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
			t.Fatalf("ensure #3: %v", err)
		}

		got, err := db.GetPhishingRun(ctx, pool, "restart-run-1")
		if err != nil {
			t.Fatalf("get after 3 ensure calls: %v", err)
		}
		if got.Status != phishingrun.StatusCompleted {
			t.Errorf("Status = %q, want completed (schema-ensure must never be destructive)", got.Status)
		}
	})
}
