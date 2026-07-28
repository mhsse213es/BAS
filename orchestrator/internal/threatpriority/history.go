package threatpriority

import (
	"context"
	"fmt"
)

// SnapshotHistory computes every actor's ActorPriority (via ScoreAll) and
// writes one threat_priority_history row per actor. Call this ONLY from a
// change-detection trigger (connector.Scheduler.sync, in this project) --
// never from a GET request, or every page view would insert rows.
func (e *Engine) SnapshotHistory(ctx context.Context) error {
	scores, err := e.ScoreAll(ctx)
	if err != nil {
		return err
	}
	for _, ap := range scores {
		_, err := e.pool.Exec(ctx,
			`INSERT INTO threat_priority_history (actor_name, score, tier, recorded_at) VALUES ($1,$2,$3,NOW())`,
			ap.ActorName, ap.Score, ap.Tier)
		if err != nil {
			return fmt.Errorf("snapshot %q: %w", ap.ActorName, err)
		}
	}
	return nil
}

// History returns an actor's most recent snapshots, newest first.
func (e *Engine) History(ctx context.Context, actorName string, limit int) ([]ActorPriorityHistory, error) {
	rows, err := e.pool.Query(ctx,
		`SELECT actor_name, score, recorded_at FROM threat_priority_history
		 WHERE actor_name=$1 ORDER BY recorded_at DESC LIMIT $2`, actorName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActorPriorityHistory
	for rows.Next() {
		var h ActorPriorityHistory
		if err := rows.Scan(&h.ActorName, &h.Score, &h.RecordedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
