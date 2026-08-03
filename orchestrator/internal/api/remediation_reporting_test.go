package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestRemediationReportSummary_ComputesThreePercentages(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('rr-sum-a1', 'RR-SUM-HOST')`)
		// 2 requested, 1 completed (config verified) -> 50% applied/verified.
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-sum-1', 'enable_windows_firewall', 'rr-sum-a1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-sum-2', 'disable_windows_smbv1', 'rr-sum-a1', 'windows-smbv1-disabled', 2, 'failed', 'user-1', 'test')`)
		// 1 technique verification attempted, 1 pass -> 100% BAS validated.
		mustExecAPI(t, pool, `
			INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, requested_by)
			VALUES ('tvr-sum-1', 'rr-sum-1', 'rr-sum-a1', 'windows-firewall-enabled', 'T1562.004', 'blocked', 'user-1')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		w := httptest.NewRecorder()
		h.RemediationReportSummary(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var body struct {
			RemediationAppliedPct    float64 `json:"remediationAppliedPct"`
			ConfigurationVerifiedPct float64 `json:"configurationVerifiedPct"`
			BASValidatedPct          float64 `json:"basValidatedPct"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if body.RemediationAppliedPct != 50 {
			t.Errorf("RemediationAppliedPct = %v, want 50", body.RemediationAppliedPct)
		}
		if body.ConfigurationVerifiedPct != 50 {
			t.Errorf("ConfigurationVerifiedPct = %v, want 50", body.ConfigurationVerifiedPct)
		}
		if body.BASValidatedPct != 100 {
			t.Errorf("BASValidatedPct = %v, want 100 (1 of 1 technique_verification_runs is blocked, which counts as validated)", body.BASValidatedPct)
		}
	})
}
