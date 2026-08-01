package controlhealth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/verification"
)

// loadDetectionEvidence reads every Approved, active verification record
// since the given cutoff, from the verification_history table -- the same
// table and Approved+Active convention internal/threatpriority/engine.go's
// loadValidationVerdicts and internal/pathcorrelation's SQLRunLookup already
// use ("only an Approved attestation feeds Coverage" per
// internal/verification/store.go's documented convention).
func loadDetectionEvidence(ctx context.Context, pool *pgxpool.Pool, since time.Time) ([]evidenceRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT UPPER(technique_id) AS tid, result, verified_at
		FROM verification_history
		WHERE active
		  AND workflow_state = $1
		  AND result IN ($2, $3)
		  AND verified_at >= $4`,
		verification.StateApproved, verification.ResultDetected, verification.ResultNotDetected, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []evidenceRow
	for rows.Next() {
		var tid, result string
		var at time.Time
		if err := rows.Scan(&tid, &result, &at); err != nil {
			return nil, err
		}
		verdict := "fail"
		if result == verification.ResultDetected {
			verdict = "pass"
		}
		out = append(out, evidenceRow{TechniqueID: baseTechID(tid), Verdict: verdict, At: at})
	}
	return out, rows.Err()
}
