package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

// EnsureAgentUninstallSchema must be safe to call repeatedly (startup runs
// it every boot) and must leave every new column in place.
func TestEnsureAgentUninstallSchema_Idempotent(t *testing.T) {
	ctx := context.Background()
	if err := db.EnsureAgentUninstallSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatalf("first EnsureAgentUninstallSchema: %v", err)
	}
	if err := db.EnsureAgentUninstallSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatalf("second EnsureAgentUninstallSchema (idempotency): %v", err)
	}

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
