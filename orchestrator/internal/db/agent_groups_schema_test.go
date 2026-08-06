package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

// EnsureAgentGroupSchema must be safe to call repeatedly (startup runs it
// every boot) and must leave both the new table and the new agents column
// in place.
func TestEnsureAgentGroupSchema_Idempotent(t *testing.T) {
	ctx := context.Background()
	if err := db.EnsureAgentGroupSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatalf("first EnsureAgentGroupSchema: %v", err)
	}
	if err := db.EnsureAgentGroupSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatalf("second EnsureAgentGroupSchema (idempotency): %v", err)
	}

	var tableExists bool
	err := sharedDB.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_groups')`,
	).Scan(&tableExists)
	if err != nil {
		t.Fatalf("checking agent_groups table: %v", err)
	}
	if !tableExists {
		t.Error("agent_groups table was not created")
	}

	var columnExists bool
	err = sharedDB.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'agents' AND column_name = 'group_id')`,
	).Scan(&columnExists)
	if err != nil {
		t.Fatalf("checking agents.group_id column: %v", err)
	}
	if !columnExists {
		t.Error("agents.group_id column was not added")
	}
}
