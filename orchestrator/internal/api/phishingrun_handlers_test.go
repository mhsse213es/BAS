package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishingrun"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func triggerPhishingRunReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) *http.Request {
	t.Helper()
	userID := seedUser(t, pool, fmt.Sprintf("phishingrun-op-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	return authedRequest(t, http.MethodPost, "/api/phishing-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
}

// TestTriggerPhishingRun_RouterLevel_ViewerForbidden_NoRowCreated goes
// beyond TestRBACMatrix_AuthorizationBoundary (which only checks the
// status code for every matrix row, including this one): it proves a
// denied request never reaches ExecutePhishingRun at all -- zero rows
// in phishing_runs afterward, not just a 403 response.
func TestTriggerPhishingRun_RouterLevel_ViewerForbidden_NoRowCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		tenantID := "default"
		tok, err := auth.GenerateTenantToken("phishingrun-viewer", auth.RoleViewer, &tenantID, false, testJWTSecret, time.Hour)
		if err != nil {
			t.Fatalf("mint token: %v", err)
		}
		body, _ := json.Marshal(map[string]any{"scenarioId": "PH-DET-002", "parameters": map[string]any{"executionId": "exec-1", "targetId": "target-1"}})
		req := httptest.NewRequest(http.MethodPost, "/api/phishing-runs", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, body = %s, want 403 (viewer lacks CanRunScenario)", rec.Code, rec.Body.String())
		}
		runs, err := db.ListPhishingRuns(req.Context(), pool, 10)
		if err != nil {
			t.Fatalf("ListPhishingRuns: %v", err)
		}
		if len(runs) != 0 {
			t.Errorf("rows created = %d, want 0 (a forbidden request must never reach ExecutePhishingRun)", len(runs))
		}
	})
}

func TestTriggerPhishingRun_UnregisteredScenario_400(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := triggerPhishingRunReq(t, pool, map[string]any{"scenarioId": "PH-BEC-002"})
		rec := callAuthed(h.TriggerPhishingRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusBadRequest)
		}
	})
}

func TestTriggerPhishingRun_PHDET002_201ThenGetReturnsCompletedRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithPhishingRun(phishbridge.NewFixtureReportTicketProvider([]phishbridge.ReportTicketEvidence{{
				ExecutionID: "exec-1", TargetID: "target-1", TicketCreated: true, Timestamp: time.Now(),
			}}))
		req := triggerPhishingRunReq(t, pool, map[string]any{"scenarioId": "PH-DET-002", "parameters": map[string]any{"executionId": "exec-1", "targetId": "target-1"}})
		rec := callAuthed(h.TriggerPhishingRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusCreated)
		}
		var triggered phishingrun.PhishingRun
		if err := json.Unmarshal(rec.Body.Bytes(), &triggered); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if triggered.ID == "" {
			t.Fatal("want non-empty run ID")
		}
		if triggered.InitiatedBy == "" {
			t.Error("InitiatedBy should be set from the authenticated caller, never empty")
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
			t.Errorf("Status = %q, want completed", fetched.Status)
		}
	})
}

func TestListPhishingRuns_ReturnsNewestFirst(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithPhishingRun(phishbridge.NewFixtureReportTicketProvider([]phishbridge.ReportTicketEvidence{{
				ExecutionID: "exec-1", TargetID: "target-1", TicketCreated: true, Timestamp: time.Now(),
			}}))
		params := map[string]any{"executionId": "exec-1", "targetId": "target-1"}
		first := callAuthed(h.TriggerPhishingRun, triggerPhishingRunReq(t, pool, map[string]any{"scenarioId": "PH-DET-002", "parameters": params}))
		var firstRun phishingrun.PhishingRun
		_ = json.Unmarshal(first.Body.Bytes(), &firstRun)
		time.Sleep(10 * time.Millisecond)
		second := callAuthed(h.TriggerPhishingRun, triggerPhishingRunReq(t, pool, map[string]any{"scenarioId": "PH-DET-002", "parameters": params}))
		var secondRun phishingrun.PhishingRun
		_ = json.Unmarshal(second.Body.Bytes(), &secondRun)

		listReq := authedRequest(t, http.MethodGet, "/api/phishing-runs", nil, auth.RoleAnalyst, "")
		listRec := callAuthed(h.ListPhishingRuns, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s, want 200", listRec.Code, listRec.Body.String())
		}
		var runs []phishingrun.PhishingRun
		if err := json.Unmarshal(listRec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(runs) != 2 {
			t.Fatalf("len(runs) = %d, want 2", len(runs))
		}
		if runs[0].ID != secondRun.ID || runs[1].ID != firstRun.ID {
			t.Errorf("runs = [%s, %s], want newest (%s) first", runs[0].ID, runs[1].ID, secondRun.ID)
		}
	})
}
