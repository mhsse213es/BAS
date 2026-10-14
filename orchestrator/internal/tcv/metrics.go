package tcv

import (
	"context"
	"fmt"
	"time"
)

// Metrics computes all four TCV measurements for one threat (spec §10.4).
// No qualifying content and no clock started are both represented
// explicitly (StateNoClock, StateOpen) rather than as a zero-valued
// Metric that would be indistinguishable from a real zero-duration
// measurement.
func (s *Store) Metrics(ctx context.Context, threatID string) (ThreatTCV, error) {
	starts := map[ClockKind]time.Time{}
	rows, err := s.pool.Query(ctx, `SELECT clock, started_at FROM threat_clock_starts WHERE threat_id = $1`, threatID)
	if err != nil {
		return ThreatTCV{}, fmt.Errorf("tcv: load clock starts for %s: %w", threatID, err)
	}
	for rows.Next() {
		var clock ClockKind
		var startedAt time.Time
		if err := rows.Scan(&clock, &startedAt); err != nil {
			rows.Close()
			return ThreatTCV{}, err
		}
		starts[clock] = startedAt
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ThreatTCV{}, err
	}

	firsts := map[RelationshipKind]time.Time{}
	rows2, err := s.pool.Query(ctx, `SELECT relationship_kind, first_executable_at FROM threat_coverage_firsts WHERE threat_id = $1`, threatID)
	if err != nil {
		return ThreatTCV{}, fmt.Errorf("tcv: load coverage firsts for %s: %w", threatID, err)
	}
	for rows2.Next() {
		var kind RelationshipKind
		var firstExecutableAt time.Time
		if err := rows2.Scan(&kind, &firstExecutableAt); err != nil {
			rows2.Close()
			return ThreatTCV{}, err
		}
		firsts[kind] = firstExecutableAt
	}
	rows2.Close()
	if err := rows2.Err(); err != nil {
		return ThreatTCV{}, err
	}

	build := func(clock ClockKind, kind RelationshipKind) Metric {
		start, hasStart := starts[clock]
		if !hasStart {
			return Metric{State: StateNoClock}
		}
		covered, hasCovered := firsts[kind]
		if !hasCovered {
			elapsed := int64(time.Since(start).Seconds())
			return Metric{ClockStartedAt: &start, State: StateOpen, ElapsedSeconds: &elapsed}
		}
		if covered.Before(start) {
			var zero int64
			return Metric{ClockStartedAt: &start, CoveredAt: &covered, State: StatePreExisting, TCVSeconds: &zero}
		}
		secs := int64(covered.Sub(start).Seconds())
		return Metric{ClockStartedAt: &start, CoveredAt: &covered, State: StateMeasured, TCVSeconds: &secs}
	}

	return ThreatTCV{
		ThreatID:                 threatID,
		ThreatToEmulation:        build(ClockThreat, RelationshipEmulates),
		ThreatToGeneration:       build(ClockThreat, RelationshipGeneratedFor),
		IntelligenceToEmulation:  build(ClockIntelligence, RelationshipEmulates),
		IntelligenceToGeneration: build(ClockIntelligence, RelationshipGeneratedFor),
	}, nil
}
