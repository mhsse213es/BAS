package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/driftanalytics"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetControlDrift_ComputesFromPooledHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('dh-a1', 'DH-A1', 'windows')`)
		seedVerificationRun(t, pool, "dh-rr-1", "dh-a1", "windows-firewall-enabled", "fail", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "dh-rr-2", "dh-a1", "windows-firewall-enabled", "pass", "2026-01-02T00:00:00Z")
		seedVerificationRun(t, pool, "dh-rr-3", "dh-a1", "windows-firewall-enabled", "pass", "2026-01-03T00:00:00Z")
		seedVerificationRun(t, pool, "dh-rr-4", "dh-a1", "windows-firewall-enabled", "pass", "2026-01-04T00:00:00Z")
		seedVerificationRun(t, pool, "dh-rr-5", "dh-a1", "windows-firewall-enabled", "fail", "2026-01-05T00:00:00Z")

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParams(httptest.NewRequest(http.MethodGet, "/x", nil), map[string]string{"agentId": "dh-a1", "checkId": "windows-firewall-enabled"})
		w := httptest.NewRecorder()
		h.GetControlDrift(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			DriftStats driftanalytics.DriftStats `json:"driftStats"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.DriftStats.DriftCount != 1 {
			t.Errorf("DriftCount = %d, want 1", resp.DriftStats.DriftCount)
		}
	})
}

func TestGetControlDrift_NoHistory_ReturnsZeroValueStats(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParams(httptest.NewRequest(http.MethodGet, "/x", nil), map[string]string{"agentId": "dh-does-not-exist", "checkId": "windows-firewall-enabled"})
		w := httptest.NewRecorder()
		h.GetControlDrift(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			DriftStats driftanalytics.DriftStats `json:"driftStats"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.DriftStats.TotalRuns != 0 {
			t.Errorf("TotalRuns = %d, want 0", resp.DriftStats.TotalRuns)
		}
	})
}
