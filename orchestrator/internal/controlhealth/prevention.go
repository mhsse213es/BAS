package controlhealth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// evidenceRow is one normalized pass/fail data point for one technique.
// Both loadPreventionEvidence and loadDetectionEvidence (Task 3) produce
// this same shape so health.go (Task 4) can treat the two evidence streams
// uniformly.
type evidenceRow struct {
	TechniqueID string // base technique ID, uppercase
	Verdict     string // "pass" | "fail"
	At          time.Time
}

// loadPreventionEvidence reads every technique result recorded since the
// given cutoff across the whole fleet, from scenario_runs.results (a JSONB
// array per run) via jsonb_array_elements -- the same query shape
// internal/threatpriority/engine.go's loadPreventionVerdicts already uses,
// except this keeps every row (not just DISTINCT ON the latest) so callers
// can both roll up the latest verdict per technique and count total
// evidence volume.
func loadPreventionEvidence(ctx context.Context, pool *pgxpool.Pool, since time.Time) ([]evidenceRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT UPPER(r->'technique'->>'id') AS tid,
		       r->>'result' AS verdict,
		       (r->>'executedAt')::timestamptz AS executed_at
		FROM scenario_runs sr, jsonb_array_elements(sr.results) r
		WHERE sr.status IN ('completed', 'partial')
		  AND r->'technique'->>'id' IS NOT NULL AND r->'technique'->>'id' <> ''
		  AND r->>'result' IN ('pass', 'fail', 'blocked')
		  AND r->>'executedAt' IS NOT NULL
		  AND (r->>'executedAt')::timestamptz >= $1`,
		since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []evidenceRow
	for rows.Next() {
		var tid, verdict string
		var at time.Time
		if err := rows.Scan(&tid, &verdict, &at); err != nil {
			return nil, err
		}
		normalized := "fail"
		if verdict == "pass" || verdict == "blocked" {
			normalized = "pass"
		}
		out = append(out, evidenceRow{TechniqueID: baseTechID(tid), Verdict: normalized, At: at})
	}
	return out, rows.Err()
}
