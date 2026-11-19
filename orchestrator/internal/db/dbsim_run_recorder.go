package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DBSimRunRecorder writes the scenario_runs row for a database simulation run.
// The row is what the agent's host-event and detection handlers look up by run
// id, so it must exist before the command is sent. The api package adapts this to
// dbjobs.RunRecorder; db does not import dbjobs, because that forms an import
// cycle through verification.
type DBSimRunRecorder struct{ Pool *pgxpool.Pool }

// InsertRun inserts the run row as running, with execution_kind 'dbsim'.
func (r DBSimRunRecorder) InsertRun(ctx context.Context, id, scenarioID, agentID, name, initiatedBy string, startedAt time.Time) error {
	var initiated *string
	if initiatedBy != "" {
		initiated = &initiatedBy
	}
	_, err := r.Pool.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, initiated_by, started_at, mode, execution_kind)
		 VALUES ($1, $2, $3, $4, 'running', $5, $6, 'dbsim', 'dbsim')`,
		id, scenarioID, agentID, name, initiated, startedAt)
	return err
}

// DBSimAgentActivity reports whether an agent is running a normal scenario, so a
// database run never interrupts one (dbjobs.AgentActivity). Database runs are
// excluded: they are not normal scenarios.
type DBSimAgentActivity struct{ Pool *pgxpool.Pool }

// HasRunningScenario reports whether the agent has a running non-dbsim scenario run.
func (a DBSimAgentActivity) HasRunningScenario(ctx context.Context, agentID string) (bool, error) {
	var busy bool
	err := a.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM scenario_runs WHERE agent_id = $1 AND status = 'running' AND execution_kind <> 'dbsim')`,
		agentID).Scan(&busy)
	return busy, err
}
