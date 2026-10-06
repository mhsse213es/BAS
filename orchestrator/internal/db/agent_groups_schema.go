package db

import (
	"context"
	"github.com/audspect/bas/internal/db/legacy"

	"github.com/jackc/pgx/v5/pgxpool"
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
func EnsureAgentGroupSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return legacy.EnsureAgentGroupSchema(ctx, pool)
}
