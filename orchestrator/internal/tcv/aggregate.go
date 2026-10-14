package tcv

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TCVAggregate is the factory-wide threat-to-emulation TCV distribution
// (spec: docs/superpowers/specs/2026-10-13-tcf-phase11-factory-analytics-design.md).
// Scoped to ClockThreat/RelationshipEmulates only -- the canonical
// "threat-to-content velocity" the TCF pipeline names. SampleSize == 0
// means no threat has reached StateMeasured yet for this combination.
type TCVAggregate struct {
	MedianSeconds *float64
	P95Seconds    *float64
	SampleSize    int
}

// AggregateMetrics computes the median and P95 threat-to-emulation TCV
// across every threat currently in StateMeasured (clock started AND
// coverage recorded at or after the clock start -- the same condition
// Store.Metrics uses per-threat, here computed as one SQL aggregate
// instead of an N+1 loop over per-threat queries).
func AggregateMetrics(ctx context.Context, pool *pgxpool.Pool) (TCVAggregate, error) {
	var sampleSize int
	var median, p95 *float64
	err := pool.QueryRow(ctx, `
		SELECT
			count(*),
			percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (f.first_executable_at - s.started_at))),
			percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (f.first_executable_at - s.started_at)))
		FROM threat_clock_starts s
		JOIN threat_coverage_firsts f
			ON f.threat_id = s.threat_id AND f.relationship_kind = $1
		WHERE s.clock = $2 AND f.first_executable_at >= s.started_at`,
		RelationshipEmulates, ClockThreat,
	).Scan(&sampleSize, &median, &p95)
	if err != nil {
		return TCVAggregate{}, err
	}
	if sampleSize == 0 {
		return TCVAggregate{}, nil
	}
	return TCVAggregate{MedianSeconds: median, P95Seconds: p95, SampleSize: sampleSize}, nil
}
