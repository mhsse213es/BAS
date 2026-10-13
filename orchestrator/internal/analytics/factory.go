package analytics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DataState is explicit per spec's NO_DATA discipline: every factory-health
// metric says whether it was actually measured, so a caller can never
// mistake "never measured" for "measured and zero."
type DataState string

const (
	DataMeasured DataState = "measured"
	DataNoData   DataState = "no_data"
)

// Metric is one measurement in the factory-health report. Value is nil
// whenever State is DataNoData.
type Metric struct {
	State  DataState `json:"state"`
	Value  *float64  `json:"value"`
	Reason string    `json:"reason,omitempty"`
}

func measured(v float64) Metric   { return Metric{State: DataMeasured, Value: &v} }
func noData(reason string) Metric { return Metric{State: DataNoData, Reason: reason} }

// CoreCounts holds the three simplest factory-health metrics.
type CoreCounts struct {
	ThreatsProcessed          Metric
	PublishedContent          Metric
	SourceToTechniqueCoverage Metric
}

// coreCounts computes threats processed and published content -- plain
// counts, where zero is itself a real measured answer -- plus
// source-to-technique mapping coverage, a ratio that is NO_DATA when its
// denominator (threats in the window) is zero.
func coreCounts(ctx context.Context, pool *pgxpool.Pool, since time.Time) (CoreCounts, error) {
	var threatsProcessed int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM threats WHERE created_at >= $1`, since).Scan(&threatsProcessed); err != nil {
		return CoreCounts{}, err
	}

	var publishedContent int
	if err := pool.QueryRow(ctx, `SELECT count(DISTINCT id) FROM content_versions WHERE lifecycle IN ('PUBLISHED','PUBLISHED_LOCAL')`).Scan(&publishedContent); err != nil {
		return CoreCounts{}, err
	}

	var withTechniques int
	if err := pool.QueryRow(ctx, `
		SELECT count(DISTINCT t.id) FROM threats t
		JOIN threat_techniques tt ON tt.threat_id = t.id
		WHERE t.created_at >= $1`, since).Scan(&withTechniques); err != nil {
		return CoreCounts{}, err
	}

	coverage := noData("no threats recorded in the selected window")
	if threatsProcessed > 0 {
		coverage = measured(float64(withTechniques) / float64(threatsProcessed))
	}

	return CoreCounts{
		ThreatsProcessed:          measured(float64(threatsProcessed)),
		PublishedContent:          measured(float64(publishedContent)),
		SourceToTechniqueCoverage: coverage,
	}, nil
}

// staticValidationPassRate is the pass rate among STRUCTURAL/STATIC
// content_validations rows only -- the only validation level with real
// data today (spec: Phase 6 doesn't exist yet). Labeled explicitly as
// "static" everywhere it surfaces, never implying execution or detection
// validation occurred. NO_DATA and NOT_APPLICABLE outcomes are excluded
// from both numerator and denominator -- they are neither a pass nor a
// fail.
func staticValidationPassRate(ctx context.Context, pool *pgxpool.Pool, since time.Time) (Metric, error) {
	var total, passed int
	err := pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE outcome IN ('PASS','FAIL','ERROR')),
			count(*) FILTER (WHERE outcome = 'PASS')
		FROM content_validations
		WHERE level IN ('STRUCTURAL','STATIC') AND created_at >= $1`, since,
	).Scan(&total, &passed)
	if err != nil {
		return Metric{}, err
	}
	if total == 0 {
		return noData("no STRUCTURAL/STATIC validations ran in the selected window"), nil
	}
	return measured(float64(passed) / float64(total)), nil
}

// duplicateGenerationRate is always NO_DATA in this phase. Generation
// attempts happen (Scheduler.sync calls Generator.Write on every poll,
// idempotent via content_versions' dedup) but their outcomes are only
// logged to stdout and an in-memory, process-lifetime counter -- never
// persisted. Persisting a per-attempt log is Phase 9's deliverable, not
// this phase's; adding it here would be new write-path infrastructure
// this phase deliberately excludes.
func duplicateGenerationRate() Metric {
	return noData("generation-attempt telemetry is not yet persisted (tracked for Phase 9)")
}

// SourceHealth is one source instance's ingestion health. LastSuccessAt
// is nil when the source has never once synced successfully -- this is
// deliberately distinct from a non-nil-but-old timestamp (stale), which
// dataQuality reports separately.
type SourceHealth struct {
	SourceInstanceID string     `json:"sourceInstanceId"`
	DisplayName      string     `json:"displayName"`
	LastSuccessAt    *time.Time `json:"lastSuccessAt"`
	FailuresInWindow int        `json:"failuresInWindow"`
	LastDiagnostic   string     `json:"lastDiagnostic,omitempty"`
}

type IngestionHealth struct {
	Sources              []SourceHealth `json:"sources"`
	UnresolvedCandidates int            `json:"unresolvedCandidates"`
}

func ingestionHealth(ctx context.Context, pool *pgxpool.Pool, since time.Time) (IngestionHealth, error) {
	rows, err := pool.Query(ctx, `
		SELECT
			si.id, si.display_name,
			(SELECT max(completed_at) FROM source_syncs WHERE source_instance_id = si.id AND status = 'succeeded'),
			(SELECT count(*) FROM source_syncs WHERE source_instance_id = si.id AND status = 'failed' AND started_at >= $1),
			(SELECT diagnostic FROM source_syncs WHERE source_instance_id = si.id AND status = 'failed' ORDER BY started_at DESC LIMIT 1)
		FROM source_instances si
		ORDER BY si.id`, since)
	if err != nil {
		return IngestionHealth{}, err
	}
	defer rows.Close()

	var sources []SourceHealth
	for rows.Next() {
		var s SourceHealth
		var diagnostic *string
		if err := rows.Scan(&s.SourceInstanceID, &s.DisplayName, &s.LastSuccessAt, &s.FailuresInWindow, &diagnostic); err != nil {
			return IngestionHealth{}, err
		}
		if diagnostic != nil {
			s.LastDiagnostic = *diagnostic
		}
		sources = append(sources, s)
	}
	if err := rows.Err(); err != nil {
		return IngestionHealth{}, err
	}

	var unresolved int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM actor_resolution_candidates WHERE status = 'unresolved'`).Scan(&unresolved); err != nil {
		return IngestionHealth{}, err
	}

	return IngestionHealth{Sources: sources, UnresolvedCandidates: unresolved}, nil
}
