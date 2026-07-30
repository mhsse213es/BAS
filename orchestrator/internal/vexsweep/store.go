package vexsweep

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAgentAlreadySweeping is returned by Create when the partial unique
// index rejects a second running sweep for the same agent.
var ErrAgentAlreadySweeping = errors.New("agent already has a running sweep")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const sweepCols = `id, agent_id, mode, include_advanced, techniques, technique_variant_counts,
	current_index, current_variant_run_id, current_scenario_run_id,
	completed_variants, total_variants, status, error, created_by, started_at, completed_at`

func scanSweep(row interface {
	Scan(dest ...any) error
}) (Sweep, error) {
	var sw Sweep
	err := row.Scan(&sw.ID, &sw.AgentID, &sw.Mode, &sw.IncludeAdvanced, &sw.Techniques, &sw.TechniqueVariantCounts,
		&sw.CurrentIndex, &sw.CurrentVariantRunID, &sw.CurrentScenarioRunID,
		&sw.CompletedVariants, &sw.TotalVariants, &sw.Status, &sw.Error, &sw.CreatedBy, &sw.StartedAt, &sw.CompletedAt)
	return sw, err
}

func (s *Store) Create(ctx context.Context, sw Sweep) (Sweep, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO vex_sweeps (agent_id, mode, include_advanced, techniques, technique_variant_counts, total_variants, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING `+sweepCols,
		sw.AgentID, sw.Mode, sw.IncludeAdvanced, sw.Techniques, sw.TechniqueVariantCounts, sw.TotalVariants, sw.CreatedBy)
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
	row := s.pool.QueryRow(ctx, `SELECT `+sweepCols+` FROM vex_sweeps WHERE id = $1`, id)
	return scanSweep(row)
}

func (s *Store) GetActiveForAgent(ctx context.Context, agentID string) (Sweep, bool, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+sweepCols+` FROM vex_sweeps WHERE agent_id = $1 AND status = 'running'`, agentID)
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
	rows, err := s.pool.Query(ctx, `SELECT `+sweepCols+` FROM vex_sweeps WHERE status = $1 ORDER BY started_at`, status)
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

// AdvanceToNext credits justCompletedVariants to completed_variants, sets
// current_index to the caller-computed nextIndex (NOT current_index+1 --
// the caller already knows the correct next index: unchanged for a sweep's
// very first dispatch, current+1 only when advancing past an
// already-dispatched technique), and records the new current run IDs (both
// empty strings mean "no next technique" -- the sweep is marked completed
// instead). Called by the Dispatcher once per finished technique.
func (s *Store) AdvanceToNext(ctx context.Context, id string, justCompletedVariants, nextIndex int, nextVariantRunID, nextScenarioRunID string) error {
	if nextVariantRunID == "" && nextScenarioRunID == "" {
		_, err := s.pool.Exec(ctx,
			`UPDATE vex_sweeps
			    SET completed_variants = completed_variants + $2,
			        current_index = $3,
			        current_variant_run_id = '', current_scenario_run_id = '',
			        status = 'completed', completed_at = NOW()
			  WHERE id = $1`,
			id, justCompletedVariants, nextIndex)
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE vex_sweeps
		    SET completed_variants = completed_variants + $2,
		        current_index = $3,
		        current_variant_run_id = $4, current_scenario_run_id = $5
		  WHERE id = $1`,
		id, justCompletedVariants, nextIndex, nextVariantRunID, nextScenarioRunID)
	return err
}

func (s *Store) MarkStopped(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE vex_sweeps SET status = 'stopped', completed_at = NOW() WHERE id = $1`, id)
	return err
}

func (s *Store) MarkFailed(ctx context.Context, id, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE vex_sweeps SET status = 'failed', error = $2, completed_at = NOW() WHERE id = $1`, id, errMsg)
	return err
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
