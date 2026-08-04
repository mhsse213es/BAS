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

func TestGetAgentDriftSummary_SortsByStabilityAscending(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('ds-a1', 'DS-A1', 'windows')`)
		// windows-firewall-enabled: 100% stable (1 pass)
		seedVerificationRun(t, pool, "ds-rr-1", "ds-a1", "windows-firewall-enabled", "pass", "2026-01-01T00:00:00Z")
		// windows-defender-enabled: 50% stable (1 pass, 1 fail)
		seedVerificationRun(t, pool, "ds-rr-2", "ds-a1", "windows-defender-enabled", "pass", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "ds-rr-3", "ds-a1", "windows-defender-enabled", "fail", "2026-01-02T00:00:00Z")

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "ds-a1")
		w := httptest.NewRecorder()
		h.GetAgentDriftSummary(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			OverallStabilityPercent float64           `json:"overallStabilityPercent"`
			Checks                  []checkDriftEntry `json:"checks"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(resp.Checks) != 2 {
			t.Fatalf("got %d checks, want 2", len(resp.Checks))
		}
		if resp.Checks[0].CheckID != "windows-defender-enabled" {
			t.Errorf("Checks[0].CheckID = %q, want windows-defender-enabled (least stable first)", resp.Checks[0].CheckID)
		}
		if resp.OverallStabilityPercent != 75 { // (100 + 50) / 2
			t.Errorf("OverallStabilityPercent = %v, want 75", resp.OverallStabilityPercent)
		}
	})
}

func TestGetFleetDriftReport_BucketsControlsCorrectly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('fr-a1', 'FR-A1', 'windows')`)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('fr-a2', 'FR-A2', 'windows')`)

		// fr-a1/windows-firewall-enabled: drifts (PASS, FAIL) -- currently failing, drifted "now"
		seedVerificationRun(t, pool, "fr-rr-1", "fr-a1", "windows-firewall-enabled", "pass", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "fr-rr-2", "fr-a1", "windows-firewall-enabled", "fail", "2026-01-02T00:00:00Z")

		// fr-a2/windows-defender-enabled: never drifts (PASS, PASS)
		seedVerificationRun(t, pool, "fr-rr-3", "fr-a2", "windows-defender-enabled", "pass", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "fr-rr-4", "fr-a2", "windows-defender-enabled", "pass", "2026-01-02T00:00:00Z")

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		w := httptest.NewRecorder()
		h.GetFleetDriftReport(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			TopDrifting  []controlDriftEntry  `json:"topDrifting"`
			NeverDrifted []controlDriftEntry  `json:"neverDrifted"`
			MonthlyTrend []monthlyDriftBucket `json:"monthlyTrend"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(resp.TopDrifting) != 1 || resp.TopDrifting[0].CheckID != "windows-firewall-enabled" {
			t.Errorf("TopDrifting = %+v, want 1 entry for windows-firewall-enabled", resp.TopDrifting)
		}
		if len(resp.NeverDrifted) != 1 || resp.NeverDrifted[0].CheckID != "windows-defender-enabled" {
			t.Errorf("NeverDrifted = %+v, want 1 entry for windows-defender-enabled", resp.NeverDrifted)
		}
		if len(resp.MonthlyTrend) != 1 || resp.MonthlyTrend[0].Month != "2026-01" || resp.MonthlyTrend[0].DriftCount != 1 {
			t.Errorf("MonthlyTrend = %+v, want 1 bucket for 2026-01 with count 1", resp.MonthlyTrend)
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
