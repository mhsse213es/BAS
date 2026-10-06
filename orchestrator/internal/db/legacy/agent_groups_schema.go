package legacy

import (
	"context"
	"fmt"
)

// EnsureAgentGroupSchema creates the agent_groups table and adds agents.group_id.
// Idempotent — safe to call on every startup. Must run after EnsureSchema
// (the agents table must already exist for the ALTER TABLE to succeed).
//
// No FK constraint from agents.group_id to agent_groups.id or from
// agent_groups.parent_id to agent_groups.id — this codebase doesn't use hard
// FKs elsewhere, and a cycle in parent_id (e.g. moving a group under its own
// descendant) has to be rejected at the application layer regardless, since a
// plain self-referencing FK can't express "no cycles."
func EnsureAgentGroupSchema(ctx context.Context, db DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS agent_groups (
			id         BIGSERIAL PRIMARY KEY,
			name       TEXT NOT NULL,
			parent_id  BIGINT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_groups_parent_id ON agent_groups(parent_id)`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS group_id BIGINT`,
		`CREATE INDEX IF NOT EXISTS idx_agents_group_id ON agents(group_id)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(ctx, s); err != nil {
			return fmt.Errorf("agent group schema: %w", err)
		}
	}
	return nil
}
