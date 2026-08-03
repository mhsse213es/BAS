package api

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTechniqueVerificationRunsTable_AcceptsFullRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tv-a1', 'TV-HOST')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tv-1', 'enable_windows_firewall', 'tv-a1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		mustExecAPI(t, pool, `
			INSERT INTO technique_verification_runs
				(id, request_id, agent_id, check_id, technique_id, status, requested_by)
			VALUES ('tvr-1', 'rr-tv-1', 'tv-a1', 'windows-firewall-enabled', 'T1562.004', 'requested', 'user-1')`)

		var status, engine string
		if err := pool.QueryRow(t.Context(),
			`SELECT status, engine FROM technique_verification_runs WHERE id = 'tvr-1'`,
		).Scan(&status, &engine); err != nil {
			t.Fatalf("query: %v", err)
		}
		if status != "requested" || engine != "art" {
			t.Errorf("status/engine = %s/%s, want requested/art", status, engine)
		}
	})
}

func TestTechniqueVerificationRunsTable_RejectsUnknownRequestID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := pool.Exec(t.Context(), `
			INSERT INTO technique_verification_runs
				(id, request_id, agent_id, check_id, technique_id, status, requested_by)
			VALUES ('tvr-2', 'no-such-request', 'tv-a2', 'windows-firewall-enabled', 'T1562.004', 'requested', 'user-1')`)
		if err == nil {
			t.Error("expected a foreign key violation for an unknown request_id")
		}
	})
}
