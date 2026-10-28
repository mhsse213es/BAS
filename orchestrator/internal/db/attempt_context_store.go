package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

// AttemptExecution is one stored result that matches an attempt's technique
// and step name, with the provenance its timestamp was recorded under.
type AttemptExecution struct {
	ExecutedAt string // RFC3339 as stored; parsing is the caller's decision
	Source     string // models.ExecutedAtSource* value, or "" for legacy results
}

// AttemptRecord is the raw registration and execution facts for one attempt.
// It holds no judgement: deciding whether a timestamp is trustworthy belongs to
// the caller.
type AttemptRecord struct {
	AgentFound    bool
	Hostname      string
	IPAddress     string
	StepMetaFound bool
	Executions    []AttemptExecution
}

// LoadAttemptRecord joins a run's agent registration record and its
// dispatched step metadata, then collects every stored result matching the
// attempt's technique and step name. action is the attempt's TaskID, which is
// the key step_meta is indexed by. found is false when the run does not exist.
func LoadAttemptRecord(ctx context.Context, pool *pgxpool.Pool, runID, action string) (AttemptRecord, bool, error) {
	var rec AttemptRecord
	var stepMetaRaw []byte
	err := pool.QueryRow(ctx, `
		SELECT (a.agent_id IS NOT NULL), COALESCE(a.hostname,''), COALESCE(a.ip_address,''), r.step_meta
		FROM scenario_runs r
		LEFT JOIN agents a ON a.agent_id = r.agent_id
		WHERE r.id = $1
	`, runID).Scan(&rec.AgentFound, &rec.Hostname, &rec.IPAddress, &stepMetaRaw)
	if err == pgx.ErrNoRows {
		return AttemptRecord{}, false, nil
	}
	if err != nil {
		return AttemptRecord{}, false, fmt.Errorf("attempt context: run %s: %w", runID, err)
	}

	var meta map[string]struct {
		TechniqueID string `json:"techniqueId"`
		Name        string `json:"name"`
	}
	if len(stepMetaRaw) > 0 && json.Unmarshal(stepMetaRaw, &meta) == nil {
		if m, ok := meta[action]; ok {
			rec.StepMetaFound = true
			techniqueID := models.NormalizeID(m.TechniqueID)
			rows, err := pool.Query(ctx, `
				SELECT elem->>'executedAt', COALESCE(elem->>'executedAtSource','')
				FROM scenario_runs r, jsonb_array_elements(r.results) AS elem
				WHERE r.id = $1
				  AND elem->'technique'->>'id' = $2
				  AND elem->>'stepName' = $3
			`, runID, techniqueID, m.Name)
			if err != nil {
				return AttemptRecord{}, false, fmt.Errorf("attempt context: executions for run %s: %w", runID, err)
			}
			defer rows.Close()
			for rows.Next() {
				var e AttemptExecution
				var executedAt *string
				if err := rows.Scan(&executedAt, &e.Source); err != nil {
					return AttemptRecord{}, false, fmt.Errorf("attempt context: scan execution: %w", err)
				}
				if executedAt != nil {
					e.ExecutedAt = *executedAt
				}
				rec.Executions = append(rec.Executions, e)
			}
			if err := rows.Err(); err != nil {
				return AttemptRecord{}, false, fmt.Errorf("attempt context: iterate executions: %w", err)
			}
		}
	}
	return rec, true, nil
}
