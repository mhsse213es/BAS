package emsweep

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAgentAlreadySweeping is returned by Create when the partial unique
// index rejects a second running sweep for the same agent.
var ErrAgentAlreadySweeping = errors.New("agent already has a running EM sweep")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const sweepCols = `id, agent_id, layers, current_index, current_scenario_run_id,
	current_layer_started_at, completed_layers, total_layers, status, error,
	created_by, started_at, completed_at, disconnected_at`

func scanSweep(row interface {
	Scan(dest ...any) error
}) (Sweep, error) {
	var sw Sweep
	err := row.Scan(&sw.ID, &sw.AgentID, &sw.Layers, &sw.CurrentIndex, &sw.CurrentScenarioRunID,
		&sw.CurrentLayerStartedAt, &sw.CompletedLayers, &sw.TotalLayers, &sw.Status, &sw.Error,
		&sw.CreatedBy, &sw.StartedAt, &sw.CompletedAt, &sw.DisconnectedAt)
	return sw, err
}

func (s *Store) Create(ctx context.Context, sw Sweep) (Sweep, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO em_sweeps (agent_id, layers, total_layers, created_by)
		 VALUES ($1,$2,$3,$4)
		 RETURNING `+sweepCols,
		sw.AgentID, sw.Layers, sw.TotalLayers, sw.CreatedBy)
	created, err := scanSweep(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Sweep{}, ErrAgentAlreadySweeping
		}
		return Sweep{}, err
	}
	return created, nil
}

func (s *Store) Get(ctx context.Context, id string) (Sweep, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+sweepCols+` FROM em_sweeps WHERE id = $1`, id)
	return scanSweep(row)
}

func (s *Store) GetActiveForAgent(ctx context.Context, agentID string) (Sweep, bool, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+sweepCols+` FROM em_sweeps WHERE agent_id = $1 AND status IN ('running', 'agent_disconnected')`, agentID)
	sw, err := scanSweep(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Sweep{}, false, nil
		}
		return Sweep{}, false, err
	}
	return sw, true, nil
}

func (s *Store) ListRunning(ctx context.Context) ([]Sweep, error) {
	return s.ListByStatus(ctx, "running")
}

func (s *Store) ListByStatus(ctx context.Context, status string) ([]Sweep, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+sweepCols+` FROM em_sweeps WHERE status = $1 ORDER BY started_at`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sweep
	for rows.Next() {
		sw, err := scanSweep(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sw)
	}
	return out, rows.Err()
}

// ListActionable returns every sweep the Dispatcher must keep ticking:
// actively running, or paused waiting for its agent to reconnect. Distinct
// from ListRunning (status='running' only), which existing tests and the
// Dispatcher's pre-disconnect-awareness callers relied on meaning "actively
// dispatching right now".
func (s *Store) ListActionable(ctx context.Context) ([]Sweep, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+sweepCols+` FROM em_sweeps WHERE status IN ('running', 'agent_disconnected') ORDER BY started_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sweep
	for rows.Next() {
		sw, err := scanSweep(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sw)
	}
	return out, rows.Err()
}

// AdvanceToNext credits justCompleted (0 for a sweep's very first dispatch,
// 1 when advancing past an already-dispatched layer -- every EM layer is
// worth exactly 1, unlike vexsweep's variable variant-count credit) to
// completed_layers, sets current_index to nextIndex, and records the new
// current_scenario_run_id. nextScenarioRunID == "" means "no next layer" --
// the sweep is marked completed instead.
func (s *Store) AdvanceToNext(ctx context.Context, id string, justCompleted, nextIndex int, nextScenarioRunID string) error {
	if nextScenarioRunID == "" {
		_, err := s.pool.Exec(ctx,
			`UPDATE em_sweeps
			    SET completed_layers = completed_layers + $2,
			        current_index = $3,
			        current_scenario_run_id = '', current_layer_started_at = NULL,
			        status = 'completed', completed_at = NOW()
			  WHERE id = $1`,
			id, justCompleted, nextIndex)
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE em_sweeps
		    SET completed_layers = completed_layers + $2,
		        current_index = $3,
		        current_scenario_run_id = $4, current_layer_started_at = NOW()
		  WHERE id = $1`,
		id, justCompleted, nextIndex, nextScenarioRunID)
	return err
}

// MarkDisconnected pauses a sweep whose agent is no longer reachable.
// pendingIndex is the layer index to re-dispatch on reconnect -- either the
// layer already in flight when the disconnect was detected (index
// unchanged), or, when the offline failure instead surfaces from
// dispatchNext's own dispatch attempt (the ErrAgentOffline race case), the
// layer that attempt was trying to reach (current_index has not advanced to
// it in the DB yet in that case). Always clears the current run pointer:
// any in-flight run has already been separately resolved (cancelled to
// 'partial') by the caller before this is called, or never existed.
func (s *Store) MarkDisconnected(ctx context.Context, id string, pendingIndex int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE em_sweeps
		    SET status = 'agent_disconnected', disconnected_at = NOW(),
		        current_index = $2, current_scenario_run_id = '', current_layer_started_at = NULL
		  WHERE id = $1`,
		id, pendingIndex)
	return err
}

// Resume un-pauses a sweep after its agent reconnects. The caller has
// already re-dispatched Layers[current_index] as a fresh run and passes its
// ID here; current_index itself is left unchanged -- the sweep is
// continuing the same layer it was on, not advancing past it.
func (s *Store) Resume(ctx context.Context, id, scenarioRunID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE em_sweeps
		    SET status = 'running', disconnected_at = NULL,
		        current_scenario_run_id = $2, current_layer_started_at = NOW()
		  WHERE id = $1`,
		id, scenarioRunID)
	return err
}

func (s *Store) MarkStopped(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE em_sweeps SET status = 'stopped', completed_at = NOW() WHERE id = $1`, id)
	return err
}

func (s *Store) MarkFailed(ctx context.Context, id, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE em_sweeps SET status = 'failed', error = $2, completed_at = NOW() WHERE id = $1`, id, errMsg)
	return err
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
