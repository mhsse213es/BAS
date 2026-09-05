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

const sweepCols = `id, agent_id, mode, include_advanced, techniques, technique_variant_counts, base_types, base_ids,
	current_index, current_variant_run_id, current_scenario_run_id, current_technique_started_at,
	completed_variants, total_variants, status, error, created_by, started_at, completed_at, disconnected_at`

func scanSweep(row interface {
	Scan(dest ...any) error
}) (Sweep, error) {
	var sw Sweep
	err := row.Scan(&sw.ID, &sw.AgentID, &sw.Mode, &sw.IncludeAdvanced, &sw.Techniques, &sw.TechniqueVariantCounts, &sw.BaseTypes, &sw.BaseIDs,
		&sw.CurrentIndex, &sw.CurrentVariantRunID, &sw.CurrentScenarioRunID, &sw.CurrentTechniqueStartedAt,
		&sw.CompletedVariants, &sw.TotalVariants, &sw.Status, &sw.Error, &sw.CreatedBy, &sw.StartedAt, &sw.CompletedAt, &sw.DisconnectedAt)
	return sw, err
}

func (s *Store) Create(ctx context.Context, sw Sweep) (Sweep, error) {
	// Callers that haven't been updated to pass BaseTypes (existing tests,
	// any future single-source caller) default every technique to "art" --
	// matches the pre-Caldera-combination behavior and keeps the NOT NULL
	// base_types column satisfied.
	if len(sw.BaseTypes) == 0 && len(sw.Techniques) > 0 {
		sw.BaseTypes = make([]string, len(sw.Techniques))
		for i := range sw.BaseTypes {
			sw.BaseTypes[i] = "art"
		}
	}
	// Same backward-compat convention as BaseTypes above -- callers that
	// haven't been updated to pass BaseIDs (existing tests, any future
	// single-atomic-per-technique caller) default every slot to "", which
	// resolveBaseCommand already treats as "resolve to the first match".
	if len(sw.BaseIDs) == 0 && len(sw.Techniques) > 0 {
		sw.BaseIDs = make([]string, len(sw.Techniques))
	}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO vex_sweeps (agent_id, mode, include_advanced, techniques, technique_variant_counts, base_types, base_ids, total_variants, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 RETURNING `+sweepCols,
		sw.AgentID, sw.Mode, sw.IncludeAdvanced, sw.Techniques, sw.TechniqueVariantCounts, sw.BaseTypes, sw.BaseIDs, sw.TotalVariants, sw.CreatedBy)
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
		`SELECT `+sweepCols+` FROM vex_sweeps WHERE agent_id = $1 AND status IN ('running', 'agent_disconnected')`, agentID)
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

// ListActionable returns every sweep the Dispatcher must keep ticking:
// actively running, or paused waiting for its agent to reconnect. Distinct
// from ListRunning (status='running' only).
func (s *Store) ListActionable(ctx context.Context) ([]Sweep, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+sweepCols+` FROM vex_sweeps WHERE status IN ('running', 'agent_disconnected') ORDER BY started_at`)
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
			        current_variant_run_id = '', current_scenario_run_id = '', current_technique_started_at = NULL,
			        status = 'completed', completed_at = NOW()
			  WHERE id = $1`,
			id, justCompletedVariants, nextIndex)
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE vex_sweeps
		    SET completed_variants = completed_variants + $2,
		        current_index = $3,
		        current_variant_run_id = $4, current_scenario_run_id = $5, current_technique_started_at = NOW()
		  WHERE id = $1`,
		id, justCompletedVariants, nextIndex, nextVariantRunID, nextScenarioRunID)
	return err
}

// MarkDisconnected pauses a sweep whose agent is no longer reachable.
// pendingIndex is the technique index to re-dispatch on reconnect -- see
// internal/emsweep/store.go's identical method for the full rationale.
func (s *Store) MarkDisconnected(ctx context.Context, id string, pendingIndex int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE vex_sweeps
		    SET status = 'agent_disconnected', disconnected_at = NOW(),
		        current_index = $2, current_variant_run_id = '', current_scenario_run_id = '', current_technique_started_at = NULL
		  WHERE id = $1`,
		id, pendingIndex)
	return err
}

// Resume un-pauses a sweep after its agent reconnects. The caller has
// already re-dispatched Techniques[current_index] as a fresh run and passes
// both resulting IDs here; current_index itself is left unchanged.
func (s *Store) Resume(ctx context.Context, id, variantRunID, scenarioRunID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE vex_sweeps
		    SET status = 'running', disconnected_at = NULL,
		        current_variant_run_id = $2, current_scenario_run_id = $3, current_technique_started_at = NOW()
		  WHERE id = $1`,
		id, variantRunID, scenarioRunID)
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
