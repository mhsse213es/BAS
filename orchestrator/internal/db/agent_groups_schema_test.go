package db_test

import (
	"context"
	"testing"
)

// The migrated schema has the agent_groups table and agents.group_id
// (re-running is covered by migrate.TestUp_Idempotent since H1).
func TestSchema_AgentGroupObjects(t *testing.T) {
	ctx := context.Background()

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
