package tcv

import (
	"context"
	"fmt"
	"time"
)

// RecordThreatClockStart writes the threat clock's start (spec §10.2):
// the earliest observed_at of a claim/observation made under a trust
// version that was trusted at observation time. Write-once -- a later
// call never moves an already-recorded start (acceptance test 28).
func RecordThreatClockStart(ctx context.Context, q Querier, threatID string, startedAt time.Time, sourceRef string) error {
	return recordClockStart(ctx, q, threatID, ClockThreat, startedAt, sourceRef)
}

// RecordIntelligenceClockStart writes the intelligence clock's start (spec
// §10.2): the first source_syncs.completed_at of a sync that produced a
// trusted claim/observation for the threat. Write-once, independent of
// the threat clock.
func RecordIntelligenceClockStart(ctx context.Context, q Querier, threatID string, startedAt time.Time, sourceRef string) error {
	return recordClockStart(ctx, q, threatID, ClockIntelligence, startedAt, sourceRef)
}

func recordClockStart(ctx context.Context, q Querier, threatID string, clock ClockKind, startedAt time.Time, sourceRef string) error {
	if _, err := q.Exec(ctx, `INSERT INTO threat_clock_starts (threat_id, clock, started_at, source_ref)
		VALUES ($1, $2, $3, $4) ON CONFLICT (threat_id, clock) DO NOTHING`,
		threatID, clock, startedAt, sourceRef); err != nil {
		return fmt.Errorf("tcv: record %s clock start for %s: %w", clock, threatID, err)
	}
	return nil
}
