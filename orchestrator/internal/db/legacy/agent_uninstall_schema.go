package legacy

import (
	"context"
	"fmt"
)

// EnsureAgentUninstallSchema adds the columns needed to track a dispatched
// Uninstall Agent command through to its confirmed result. Idempotent --
// safe to call on every startup. Must run after EnsureSchema (the agents
// table must already exist).
//
// uninstall_prior_state records the agent's state immediately before
// dispatch, so a failed or timed-out attempt can restore it exactly
// instead of guessing. uninstall_error/uninstall_error_at are cleared on
// a successful attempt and set on a failed one; GetAgents additionally
// computes a live timeout message when neither is set but the agent has
// been stuck in 'uninstalling' too long (see models.EffectiveUninstallError)
// -- that computation never writes to these columns.
func EnsureAgentUninstallSchema(ctx context.Context, db DB) error {
	stmts := []string{
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstall_requested_by text`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstall_requested_at timestamptz`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstall_reason text`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstall_prior_state text`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstall_error text`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstall_error_at timestamptz`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(ctx, s); err != nil {
			return fmt.Errorf("agent uninstall schema: %w", err)
		}
	}
	return nil
}
