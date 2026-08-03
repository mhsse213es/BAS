package api

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRemediationRequestsTable_AcceptsFullRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-rm-a1', 'ER-RM-HOST')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests
				(id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available)
			VALUES ('rr-1', 'enable_windows_firewall', 'er-rm-a1', 'windows-firewall-enabled', 1, 'requested', 'user-1', 'test', true)`)

		var status string
		var tier int
		if err := pool.QueryRow(t.Context(),
			`SELECT status, tier FROM remediation_requests WHERE id = 'rr-1'`,
		).Scan(&status, &tier); err != nil {
			t.Fatalf("query: %v", err)
		}
		if status != "requested" || tier != 1 {
			t.Errorf("status/tier = %s/%d, want requested/1", status, tier)
		}
	})
}
