package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/dbsim"
)

// DBSimRun is one stored database-security-simulation run. Report is the full
// JSON (dlpreport.Record, per-dimension grades, evidence); Result is copied
// out so it can be queried without parsing it. No tenant_id column: sibling
// run stores (apibas_runs, phishing_runs) do not scope by tenant.
type DBSimRun struct {
	ID              string
	ScenarioID      string
	ScenarioVersion string
	TargetID        string
	Engine          string
	RunID           string
	Result          string // PASS, FAIL, ERROR or SKIPPED
	Report          []byte
	CreatedAt       time.Time
}

// ErrDBSimRunInvalid means a run failed validation before reaching the database.
var ErrDBSimRunInvalid = dbsim.ErrRunInvalid

// ErrDBSimRunDuplicate means the run id + scenario is already stored.
var ErrDBSimRunDuplicate = errors.New("dbsim run already stored for this run id and scenario")

// ErrDBSimRunNotFound means no stored run has the id.
var ErrDBSimRunNotFound = errors.New("dbsim run not found")

func (r DBSimRun) validate() error {
	return dbsim.ValidateStoredRun(r.ScenarioID, r.ScenarioVersion, r.TargetID, r.Engine, r.RunID, r.Result, r.Report)
}

// EnsureDBSimRunSchema creates dbsim_runs (idempotent).
func EnsureDBSimRunSchema(ctx context.Context, pool *pgxpool.Pool) error {
	for _, s := range dbsim.RunsSchemaSQL {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("dbsim_runs: ensure schema: %w", err)
		}
	}
	return nil
}

// SaveDBSimRun stores one run and returns its id.
func SaveDBSimRun(ctx context.Context, pool *pgxpool.Pool, r DBSimRun) (string, error) {
	if err := r.validate(); err != nil {
		return "", err
	}
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO dbsim_runs (scenario_id, scenario_version, target_id, engine, run_id, result, report)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
		RETURNING id`,
		r.ScenarioID, r.ScenarioVersion, r.TargetID, r.Engine, r.RunID, r.Result, string(r.Report)).Scan(&id)
	if err != nil {
		var pgErr interface{ SQLState() string }
		if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" {
			return "", ErrDBSimRunDuplicate
		}
		return "", fmt.Errorf("save dbsim run: %w", err)
	}
	return id, nil
}

// GetDBSimRun returns one stored run including its report.
func GetDBSimRun(ctx context.Context, pool *pgxpool.Pool, id string) (DBSimRun, error) {
	var r DBSimRun
	err := pool.QueryRow(ctx, `
		SELECT id, scenario_id, scenario_version, target_id, engine, run_id, result, report::text, created_at
		FROM dbsim_runs WHERE id = $1`, id).Scan(&r.ID, &r.ScenarioID, &r.ScenarioVersion, &r.TargetID,
		&r.Engine, &r.RunID, &r.Result, &r.Report, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DBSimRun{}, ErrDBSimRunNotFound
	}
	if err != nil {
		return DBSimRun{}, fmt.Errorf("get dbsim run: %w", err)
	}
	return r, nil
}

// ListDBSimRuns lists runs newest first without report bodies. Empty
// scenarioID / targetID mean no filter.
func ListDBSimRuns(ctx context.Context, pool *pgxpool.Pool, scenarioID, targetID string, limit int) ([]DBSimRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := pool.Query(ctx, `
		SELECT id, scenario_id, scenario_version, target_id, engine, run_id, result, created_at
		FROM dbsim_runs WHERE ($1 = '' OR scenario_id = $1) AND ($2 = '' OR target_id = $2)
		ORDER BY created_at DESC, id DESC LIMIT $3`, scenarioID, targetID, limit)
	if err != nil {
		return nil, fmt.Errorf("list dbsim runs: %w", err)
	}
	defer rows.Close()
	var out []DBSimRun
	for rows.Next() {
		var r DBSimRun
		if err := rows.Scan(&r.ID, &r.ScenarioID, &r.ScenarioVersion, &r.TargetID, &r.Engine, &r.RunID, &r.Result, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
