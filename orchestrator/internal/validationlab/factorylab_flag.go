package validationlab

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureSoleFactoryLabAgent makes labAgentID the one and only factory-lab
// agent: it sets is_factory_lab=true on that agent and clears the flag on every
// other. This lets an operator designate the validation lab with just
// VALIDATION_LAB_AGENT_ID + install.sh --upgrade -- no manual
// "UPDATE agents SET is_factory_lab" by hand after a fresh install. The flag is
// required for the lab to function (dispatchRun refuses a factory-validation
// run to an unflagged agent), so deriving it from the configured ID keeps the
// two from drifting and prevents a stale agent staying barred from normal runs.
//
// Idempotent: the WHERE clause touches only rows whose flag must change, so a
// steady-state restart updates zero rows. A labAgentID with no agent row yet
// (the ID may be configured a moment before the agent's row exists) matches
// nothing for the true case and is not an error; any stale flag is still
// cleared.
func EnsureSoleFactoryLabAgent(ctx context.Context, pool *pgxpool.Pool, labAgentID string) error {
	_, err := pool.Exec(ctx,
		`UPDATE agents SET is_factory_lab = (agent_id = $1)
		  WHERE is_factory_lab <> (agent_id = $1)`, labAgentID)
	return err
}
