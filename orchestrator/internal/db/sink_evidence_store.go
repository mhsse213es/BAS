package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SinkEvidenceForStep counts, for one run and technique, the sink tokens issued
// and how many of those tokens have a data receipt and how many have a
// reachability-probe receipt. A probe carries no sensitive content, so it is
// reported separately and never counted as data. It reads only the run's own
// rows, so another run's receipts cannot satisfy this step.
func SinkEvidenceForStep(ctx context.Context, pool *pgxpool.Pool, runID, techniqueID string) (tokens, dataReceipts, probeReceipts int, err error) {
	err = pool.QueryRow(ctx, `
		SELECT
		  (SELECT COUNT(*) FROM dlp_sink_tokens
		    WHERE run_id = $1 AND technique_id = $2),
		  (SELECT COUNT(DISTINCT t.token) FROM dlp_sink_tokens t
		     JOIN dlp_sink_receipts r ON r.token = t.token
		    WHERE t.run_id = $1 AND t.technique_id = $2 AND r.channel <> 'reachability'),
		  (SELECT COUNT(DISTINCT t.token) FROM dlp_sink_tokens t
		     JOIN dlp_sink_receipts r ON r.token = t.token
		    WHERE t.run_id = $1 AND t.technique_id = $2 AND r.channel = 'reachability')`,
		runID, techniqueID,
	).Scan(&tokens, &dataReceipts, &probeReceipts)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("sink evidence for step: %w", err)
	}
	return tokens, dataReceipts, probeReceipts, nil
}
