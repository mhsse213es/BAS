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
	created_by, started_at, completed_at`

func scanSweep(row interface {
	Scan(dest ...any) error
}) (Sweep, error) {
	var sw Sweep
	err := row.Scan(&sw.ID, &sw.AgentID, &sw.Layers, &sw.CurrentIndex, &sw.CurrentScenarioRunID,
		&sw.CurrentLayerStartedAt, &sw.CompletedLayers, &sw.TotalLayers, &sw.Status, &sw.Error,
		&sw.CreatedBy, &sw.StartedAt, &sw.CompletedAt)
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
		`SELECT `+sweepCols+` FROM em_sweeps WHERE agent_id = $1 AND status = 'running'`, agentID)
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
