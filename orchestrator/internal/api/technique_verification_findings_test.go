package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestTechniqueVerificationFindings_LatestFailProducesFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tv-f1', 'TV-F1')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tvf-1', 'enable_windows_firewall', 'tv-f1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, reason, requested_by, completed_at)
			VALUES ('tvr-f1', 'rr-tvf-1', 'tv-f1', 'windows-firewall-enabled', 'T1562.004', 'fail', 'reverse shell still succeeded', 'user-1', $1)`,
			now)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		got := h.techniqueVerificationFindings(context.Background(), "tv-f1", now.Add(time.Hour))
		if len(got) != 1 {
			t.Fatalf("got %d findings, want 1", len(got))
		}
		if got[0].ID != "windows-firewall-enabled:technique" {
			t.Errorf("Finding.ID = %q, want windows-firewall-enabled:technique", got[0].ID)
		}
		if got[0].Risk != "reverse shell still succeeded" {
			t.Errorf("Finding.Risk = %q, want the run's reason text", got[0].Risk)
		}
	})
}

func TestTechniqueVerificationFindings_LatestPassProducesNoFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tv-f2', 'TV-F2')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tvf-2', 'enable_windows_firewall', 'tv-f2', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, reason, requested_by, completed_at)
			VALUES ('tvr-f2', 'rr-tvf-2', 'tv-f2', 'windows-firewall-enabled', 'T1562.004', 'blocked', 'firewall blocked it', 'user-1', $1)`,
			now)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		got := h.techniqueVerificationFindings(context.Background(), "tv-f2", now.Add(time.Hour))
		if len(got) != 0 {
			t.Errorf("got %d findings, want 0 (latest status is blocked, not fail/error)", len(got))
		}
	})
}

func TestTechniqueVerificationFindings_OnlyLatestPerCheckCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tv-f3', 'TV-F3')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tvf-3a', 'enable_windows_firewall', 'tv-f3', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tvf-3b', 'enable_windows_firewall', 'tv-f3', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		early := time.Now().UTC().Add(-1 * time.Hour)
		late := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, reason, requested_by, completed_at)
			VALUES ('tvr-f3a', 'rr-tvf-3a', 'tv-f3', 'windows-firewall-enabled', 'T1562.004', 'fail', 'first attempt failed', 'user-1', $1)`,
			early)
		mustExecAPI(t, pool, `
			INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, reason, requested_by, completed_at)
			VALUES ('tvr-f3b', 'rr-tvf-3b', 'tv-f3', 'windows-firewall-enabled', 'T1562.004', 'blocked', 'second attempt blocked', 'user-1', $1)`,
			late)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		got := h.techniqueVerificationFindings(context.Background(), "tv-f3", late.Add(time.Hour))
		if len(got) != 0 {
			t.Errorf("got %d findings, want 0 -- the LATEST run (blocked) should win over the earlier fail", len(got))
		}
	})
}

func TestGetAgentRisk_TechniqueVerificationFailure_AppearsAsFindingNotScore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tv-gr-a1', 'TV-GR-HOST')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('tv-gr-run', 'windows-security-config', 'Posture Run', 'tv-gr-a1', 'completed', $1::jsonb, NOW())`,
			`[{"checkId":"windows-firewall-enabled","result":"pass","executedAt":"`+now.Format(time.RFC3339)+`"}]`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-gr-1', 'enable_windows_firewall', 'tv-gr-a1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		mustExecAPI(t, pool, `
			INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, reason, requested_by, completed_at)
			VALUES ('tvr-gr-1', 'rr-gr-1', 'tv-gr-a1', 'windows-firewall-enabled', 'T1562.004', 'fail', 'reverse shell still succeeded', 'user-1', $1)`,
			now)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		tx, err := endpointrisk.NewTaxonomy()
		if err != nil {
			t.Fatalf("NewTaxonomy: %v", err)
		}
		h.endpointRiskTaxonomy = tx

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "tv-gr-a1")
		w := httptest.NewRecorder()
		h.GetAgentRisk(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got endpointrisk.EndpointHealth
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		var secCat *endpointrisk.CategoryScore
		for i := range got.Categories {
			if got.Categories[i].ID == endpointrisk.CategorySecurityConfig {
				secCat = &got.Categories[i]
			}
		}
		if secCat == nil {
			t.Fatal("Security Configuration category missing")
		}
		// The config check itself PASSES, so postureCheckInput alone would
		// produce zero findings and a perfect score -- the technique
		// verification failure must still surface as a finding.
		found := false
		for _, f := range secCat.Findings {
			if f.ID == "windows-firewall-enabled:technique" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected a windows-firewall-enabled:technique finding even though the config check passes; findings=%+v", secCat.Findings)
		}
		if secCat.Score != 100 {
			t.Errorf("Score = %d, want 100 -- technique verification must never change the config score", secCat.Score)
		}
	})
}
