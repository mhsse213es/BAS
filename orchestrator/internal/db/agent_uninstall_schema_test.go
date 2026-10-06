package db_test

import (
	"context"
	"testing"
)

// The migrated schema has every agent-uninstall column on agents
// (re-running is covered by migrate.TestUp_Idempotent since H1).
func TestSchema_AgentUninstallColumns(t *testing.T) {
	ctx := context.Background()

	cols := []string{
		"uninstall_requested_by", "uninstall_requested_at", "uninstall_reason",
		"uninstall_prior_state", "uninstall_error", "uninstall_error_at",
	}
	for _, col := range cols {
		var exists bool
		err := sharedDB.Pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'agents' AND column_name = $1)`,
			col,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("checking agents.%s: %v", col, err)
		}
		if !exists {
			t.Errorf("agents.%s was not added", col)
		}
	}
}
