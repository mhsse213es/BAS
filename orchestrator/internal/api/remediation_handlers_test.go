package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestExecuteRemediation_Tier1_DispatchesFix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-ex-a1', 'ER-EX-HOST', 'windows')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h.remediationCatalog = cat

		body := strings.NewReader(`{"remediationId":"enable_windows_firewall","reason":"test"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", body), "agentId", "er-ex-a1")
		w := httptest.NewRecorder()
		h.ExecuteRemediation(w, req)

		// No agent is connected in this test, so dispatch fails and the
		// request should end in StatusFailed -- but it must still be
		// INSERTed and pre-flight-validated correctly first.
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			RequestID string `json:"requestId"`
			Status    string `json:"status"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Status != remediation.StatusFailed {
			t.Errorf("status = %q, want %q (no agent connected)", resp.Status, remediation.StatusFailed)
		}

		var dbStatus, errText string
		pool.QueryRow(context.Background(), `SELECT status, error FROM remediation_requests WHERE id=$1`, resp.RequestID).
			Scan(&dbStatus, &errText)
		if dbStatus != remediation.StatusFailed || errText != "agent not connected" {
			t.Errorf("db status/error = %s/%s, want failed/agent not connected", dbStatus, errText)
		}
	})
}

func TestExecuteRemediation_ContinuousValidation_PersistsFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('cv-h1', 'CV-H1', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h.remediationCatalog = cat

		body := strings.NewReader(`{"remediationId":"enable_windows_firewall","reason":"test","continuousValidation":true}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", body), "agentId", "cv-h1")
		w := httptest.NewRecorder()
		h.ExecuteRemediation(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var flag bool
		if err := pool.QueryRow(context.Background(), `SELECT continuous_validation FROM remediation_requests WHERE agent_id='cv-h1'`).Scan(&flag); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !flag {
			t.Error("continuous_validation = false, want true")
		}
	})
}

func TestExecuteRemediation_UnknownRemediationID_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-ex-a2', 'ER-EX-HOST-2', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		body := strings.NewReader(`{"remediationId":"no-such-remediation","reason":"test"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", body), "agentId", "er-ex-a2")
		w := httptest.NewRecorder()
		h.ExecuteRemediation(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestExecuteRemediation_Tier4_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-ex-a3', 'ER-EX-HOST-3', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		body := strings.NewReader(`{"remediationId":"enable_bitlocker","reason":"test"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", body), "agentId", "er-ex-a3")
		w := httptest.NewRecorder()
		h.ExecuteRemediation(w, req)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422 (Tier 4 is manual guidance only)", w.Code)
		}
	})
}

func TestExecuteRemediation_AlreadyCompliant_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-ex-a4', 'ER-EX-HOST-4', 'windows')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-ex-run-4', 'windows-security-config', 'Posture Run', 'er-ex-a4', 'completed', $1::jsonb, NOW())`,
			`[{"checkId":"windows-firewall-enabled","result":"pass","executedAt":"`+now.Format(time.RFC3339)+`"}]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		body := strings.NewReader(`{"remediationId":"enable_windows_firewall","reason":"test"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", body), "agentId", "er-ex-a4")
		w := httptest.NewRecorder()
		h.ExecuteRemediation(w, req)
		if w.Code != http.StatusConflict {
			t.Errorf("status = %d, want 409 (already compliant)", w.Code)
		}
	})
}

func TestExecuteRemediation_OSMismatch_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-ex-a5', 'ER-EX-HOST-5', 'linux')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		body := strings.NewReader(`{"remediationId":"enable_windows_firewall","reason":"test"}`)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", body), "agentId", "er-ex-a5")
		w := httptest.NewRecorder()
		h.ExecuteRemediation(w, req)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422 (Linux agent, Windows-only remediation)", w.Code)
		}
	})
}
