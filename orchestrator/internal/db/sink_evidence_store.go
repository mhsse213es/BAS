package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SinkEvidenceForStep counts the DLP sink tokens issued for one run and technique,
// and how many of those tokens have at least one receipt. It reads only the
// run's own rows, so another run's receipts cannot satisfy this step.
func SinkEvidenceForStep(ctx context.Context, pool *pgxpool.Pool, runID, techniqueID string) (tokens, receipts int, err error) {
	if err = pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM dlp_sink_tokens WHERE run_id = $1 AND technique_id = $2`,
		runID, techniqueID,
	).Scan(&tokens); err != nil {
		return 0, 0, fmt.Errorf("count sink tokens: %w", err)
	}
	if err = pool.QueryRow(ctx,
		`SELECT COUNT(DISTINCT t.token) FROM dlp_sink_tokens t
		   JOIN dlp_sink_receipts r ON r.token = t.token
		  WHERE t.run_id = $1 AND t.technique_id = $2`,
		runID, techniqueID,
	).Scan(&receipts); err != nil {
		return 0, 0, fmt.Errorf("count sink receipts: %w", err)
	}
	return tokens, receipts, nil
}
