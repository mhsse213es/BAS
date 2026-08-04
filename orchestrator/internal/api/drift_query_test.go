package api

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// seedVerificationRun inserts a remediation_requests row (satisfying the
// FK) and one technique_verification_runs row for it. Each call uses a
// fresh remediationRequestID -- tests pooling across multiple separate
// remediation attempts for the same (agentID, checkID) pair, which is
// exactly what Phase 6's scope decision requires.
func seedVerificationRun(t *testing.T, pool *pgxpool.Pool, remediationRequestID, agentID, checkID, status, completedAt string) {
	t.Helper()
	mustExecAPI(t, pool, `
		INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
		VALUES ($1, 'enable_windows_firewall', $2, $3, 1, 'completed', 'user-1', 'test')`,
		remediationRequestID, agentID, checkID)
	mustExecAPI(t, pool, `
		INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, requested_by, completed_at)
		VALUES (gen_random_uuid()::text, $1, $2, $3, 'T1082', $4, 'user-1', $5::timestamptz)`,
		remediationRequestID, agentID, checkID, status, completedAt)
}

func TestVerificationOutcomesForPair_PoolsAcrossRequestIDs_ExcludesErrorSkipped_NormalizesBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('dq-a1', 'DQ-A1', 'windows')`)
		// Two SEPARATE remediation requests for the same (agent, check) pair.
		seedVerificationRun(t, pool, "dq-rr-1", "dq-a1", "windows-firewall-enabled", "pass", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "dq-rr-2", "dq-a1", "windows-firewall-enabled", "blocked", "2026-01-02T00:00:00Z")
		seedVerificationRun(t, pool, "dq-rr-3", "dq-a1", "windows-firewall-enabled", "error", "2026-01-03T00:00:00Z")
		seedVerificationRun(t, pool, "dq-rr-4", "dq-a1", "windows-firewall-enabled", "skipped", "2026-01-04T00:00:00Z")
		seedVerificationRun(t, pool, "dq-rr-5", "dq-a1", "windows-firewall-enabled", "fail", "2026-01-05T00:00:00Z")

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		outcomes, err := h.verificationOutcomesForPair(context.Background(), "dq-a1", "windows-firewall-enabled")
		if err != nil {
			t.Fatalf("verificationOutcomesForPair: %v", err)
		}
		if len(outcomes) != 3 {
			t.Fatalf("got %d outcomes, want 3 (error/skipped excluded)", len(outcomes))
		}
		if outcomes[0].Result != "pass" || outcomes[1].Result != "pass" || outcomes[2].Result != "fail" {
			t.Errorf("got results %q/%q/%q, want pass/pass/fail (blocked normalized to pass)", outcomes[0].Result, outcomes[1].Result, outcomes[2].Result)
		}
	})
}

func TestVerificationOutcomesByCheckForAgent_GroupsByCheckID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('dq-a2', 'DQ-A2', 'windows')`)
		seedVerificationRun(t, pool, "dq-rr-6", "dq-a2", "windows-firewall-enabled", "pass", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "dq-rr-7", "dq-a2", "windows-defender-enabled", "fail", "2026-01-01T00:00:00Z")

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		grouped, err := h.verificationOutcomesByCheckForAgent(context.Background(), "dq-a2")
		if err != nil {
			t.Fatalf("verificationOutcomesByCheckForAgent: %v", err)
		}
		if len(grouped) != 2 {
			t.Fatalf("got %d checks, want 2", len(grouped))
		}
		if len(grouped["windows-firewall-enabled"]) != 1 || len(grouped["windows-defender-enabled"]) != 1 {
			t.Errorf("grouped = %+v, want 1 outcome per check", grouped)
		}
	})
}

func TestVerificationOutcomesByPairFleetWide_GroupsByAgentAndCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('dq-a3', 'DQ-A3', 'windows')`)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('dq-a4', 'DQ-A4', 'windows')`)
		seedVerificationRun(t, pool, "dq-rr-8", "dq-a3", "windows-firewall-enabled", "pass", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "dq-rr-9", "dq-a4", "windows-firewall-enabled", "fail", "2026-01-01T00:00:00Z")

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		grouped, err := h.verificationOutcomesByPairFleetWide(context.Background())
		if err != nil {
			t.Fatalf("verificationOutcomesByPairFleetWide: %v", err)
		}
		if len(grouped[driftPairKey{AgentID: "dq-a3", CheckID: "windows-firewall-enabled"}]) != 1 {
			t.Error("missing dq-a3 pair")
		}
		if len(grouped[driftPairKey{AgentID: "dq-a4", CheckID: "windows-firewall-enabled"}]) != 1 {
			t.Error("missing dq-a4 pair")
		}
	})
}
