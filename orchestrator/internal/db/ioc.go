package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/ioc"
)

// EnsureIOCSchema creates the run_iocs table. Idempotent -- safe to call on
// every startup.
func EnsureIOCSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS run_iocs (
			id               BIGSERIAL PRIMARY KEY,
			run_id           TEXT NOT NULL,
			scenario_id      TEXT NOT NULL,
			indicator_type   TEXT NOT NULL,
			indicator_value  TEXT NOT NULL,
			hash_algorithm   TEXT,
			confidence       SMALLINT NOT NULL,
			indicator_source TEXT NOT NULL,
			offset_start     INT NOT NULL,
			offset_end       INT NOT NULL,
			technique_ids    JSONB NOT NULL DEFAULT '[]',
			simulation_ids   JSONB NOT NULL DEFAULT '[]',
			extracted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(run_id, indicator_type, indicator_value)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_run_iocs_run_id ON run_iocs(run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_run_iocs_value ON run_iocs(indicator_type, indicator_value)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("ioc schema: %w", err)
		}
	}
	return nil
}

// UpsertRunIOCs replaces the full set of extracted indicators for a run.
// Delete-then-insert (not a merge) mirrors the "agent always submits a
// complete snapshot" idempotency pattern SubmitScenarioResult already uses
// for scenario_runs itself -- a retried submission converges to the same
// row set instead of duplicating or double-merging arrays.
func UpsertRunIOCs(ctx context.Context, pool *pgxpool.Pool, runID, scenarioID string, indicators []ioc.RunIndicator) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("ioc upsert: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM run_iocs WHERE run_id = $1`, runID); err != nil {
		return fmt.Errorf("ioc upsert: delete: %w", err)
	}
	for _, ind := range indicators {
		techniqueIDsJSON, _ := json.Marshal(ind.TechniqueIDs)
		simulationIDsJSON, _ := json.Marshal(ind.SimulationIDs)
		var algo any
		if ind.Algorithm != "" {
			algo = ind.Algorithm
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO run_iocs
			 (run_id, scenario_id, indicator_type, indicator_value, hash_algorithm,
			  confidence, indicator_source, offset_start, offset_end, technique_ids, simulation_ids)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb)`,
			runID, scenarioID, ind.Type, ind.Value, algo,
			ind.Confidence, ind.Source, ind.OffsetStart, ind.OffsetEnd,
			techniqueIDsJSON, simulationIDsJSON,
		)
		if err != nil {
			return fmt.Errorf("ioc upsert: insert %s %s: %w", ind.Type, ind.Value, err)
		}
	}
	return tx.Commit(ctx)
}

// GetRunIOCs returns the extracted indicators for a run, optionally filtered
// by indicator type and/or a substring match against indicator_value.
func GetRunIOCs(ctx context.Context, pool *pgxpool.Pool, runID, typeFilter, search string) ([]ioc.RunIndicator, error) {
	query := `SELECT indicator_type, indicator_value, COALESCE(hash_algorithm, ''),
	                  confidence, indicator_source, offset_start, offset_end,
	                  technique_ids, simulation_ids, extracted_at
	           FROM run_iocs WHERE run_id = $1`
	args := []any{runID}
	if typeFilter != "" {
		args = append(args, typeFilter)
		query += fmt.Sprintf(" AND indicator_type = $%d", len(args))
	}
	if search != "" {
		args = append(args, "%"+search+"%")
		query += fmt.Sprintf(" AND indicator_value ILIKE $%d", len(args))
	}
	query += " ORDER BY id ASC"

	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ioc get: query: %w", err)
	}
	defer rows.Close()

	out := make([]ioc.RunIndicator, 0)
	for rows.Next() {
		var ind ioc.RunIndicator
		var techniqueIDsJSON, simulationIDsJSON []byte
		var extractedAt time.Time
		if err := rows.Scan(&ind.Type, &ind.Value, &ind.Algorithm,
			&ind.Confidence, &ind.Source, &ind.OffsetStart, &ind.OffsetEnd,
			&techniqueIDsJSON, &simulationIDsJSON, &extractedAt); err != nil {
			return nil, fmt.Errorf("ioc get: scan: %w", err)
		}
		_ = json.Unmarshal(techniqueIDsJSON, &ind.TechniqueIDs)
		_ = json.Unmarshal(simulationIDsJSON, &ind.SimulationIDs)
		ind.ExtractedAt = &extractedAt
		out = append(out, ind)
	}
	return out, rows.Err()
}
