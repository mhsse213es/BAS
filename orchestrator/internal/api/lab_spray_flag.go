package api

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureSoleSprayLabAgent makes sprayLabAgentID the one and only spray-lab agent:
// it sets is_spray_lab=true on that agent and clears the flag on every other.
// It runs at every server start from SPRAY_LAB_AGENT_ID, the same way the factory
// lab flag follows VALIDATION_LAB_AGENT_ID, so no operator runs SQL by hand. An
// empty ID clears every flag, so removing the setting turns the exemption off.
//
// Only the designated agent can receive the lab exemption (labExceptionFor), and
// the exemption itself stays limited to the lab scenarios listed in
// labExceptionScenarios.
func EnsureSoleSprayLabAgent(ctx context.Context, pool *pgxpool.Pool, sprayLabAgentID string) error {
	_, err := pool.Exec(ctx,
		`UPDATE agents SET is_spray_lab = (agent_id = $1)
		  WHERE is_spray_lab <> (agent_id = $1)`, sprayLabAgentID)
	return err
}
