package evidence

import (
	"context"
	"fmt"
	"time"
)

// RecordSync writes one source_syncs row and computes authoritative per the
// evidence layer's own rule (spec §6.1): authoritative = (completeness ==
// complete AND mode == snapshot), regardless of what the caller passes --
// the evidence layer decides this itself, never trusting an adapter's own
// say-so. A failed sync is always forced to completeness = failed.
func (s *Store) RecordSync(ctx context.Context, instanceID string, mode ObservationMode, started time.Time, status string, completeness Completeness, diagnostic string) (syncID string, authoritative bool, err error) {
	if status != "succeeded" && status != "failed" {
		return "", false, fmt.Errorf("evidence: RecordSync status must be succeeded or failed, got %q", status)
	}
	if status == "failed" {
		completeness = Failed
	}
	authoritative = completeness == Complete && mode == ModeSnapshot
	err = s.pool.QueryRow(ctx, `INSERT INTO source_syncs
		(source_instance_id, started_at, completed_at, status, completeness, authoritative, diagnostic)
		VALUES ($1, $2, NOW(), $3, $4, $5, $6) RETURNING id`,
		instanceID, started, status, completeness, authoritative, diagnostic).Scan(&syncID)
	if err != nil {
		return "", false, fmt.Errorf("evidence: record sync: %w", err)
	}
	return syncID, authoritative, nil
}

// SyncCompletedAt returns one sync's completed_at, recorded by RecordSync.
// Lets a caller that only has a syncID (the connector scheduler) start the
// intelligence clock without RecordSync threading a new return value
// through every 2B call site.
func (s *Store) SyncCompletedAt(ctx context.Context, syncID string) (time.Time, error) {
	var completedAt time.Time
	err := s.pool.QueryRow(ctx, `SELECT completed_at FROM source_syncs WHERE id = $1`, syncID).Scan(&completedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("evidence: sync completed_at for %s: %w", syncID, err)
	}
	return completedAt, nil
}
