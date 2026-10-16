package analytics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/tcv"
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

// duplicateGenerationRate is the share of generation attempts that re-derived
// content already in the registry (a dedup hit) among attempts that actually
// produced content to compare. Phase 9's content_generation_attempts telemetry
// records one row per attempt with an outcome/reason_code pair (see
// connector/generator.go): created/changed='ok' produced new or updated
// content, skipped='already_registered' is the duplicate, and
// skipped='below_min_techniques'/'unresolved_identity' plus every 'failed' row
// bailed out BEFORE reaching the dedup decision -- those are excluded from both
// numerator and denominator so the rate is not diluted by inputs that never
// generated anything. NO_DATA when no attempt reached that decision in the
// window, never a misleading 0%.
func duplicateGenerationRate(ctx context.Context, pool *pgxpool.Pool, since time.Time) (Metric, error) {
	var generated, duplicates int
	if err := pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE outcome IN ('created','changed') OR reason_code = 'already_registered'),
			count(*) FILTER (WHERE reason_code = 'already_registered')
		FROM content_generation_attempts
		WHERE started_at >= $1`, since,
	).Scan(&generated, &duplicates); err != nil {
		return Metric{}, err
	}
	if generated == 0 {
		return noData("no generative attempts recorded in the selected window"), nil
	}
	return measured(float64(duplicates) / float64(generated)), nil
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

type LifecycleFunnel struct {
	Candidate int `json:"candidate"`
	Validated int `json:"validated"`
	Published int `json:"published"`
	Rejected  int `json:"rejected"`
}

// lifecycleFunnel buckets every content_versions row by its current,
// real, distinct lifecycle state -- no inference, no ambiguity between
// "candidate" and "rejected" (spec: these are unambiguous CHECK-constrained
// states, confirmed against internal/contentregistry/lifecycle.go).
func lifecycleFunnel(ctx context.Context, pool *pgxpool.Pool) (LifecycleFunnel, error) {
	var f LifecycleFunnel
	err := pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE lifecycle IN ('DRAFT','VALIDATING')),
			count(*) FILTER (WHERE lifecycle = 'VALIDATED'),
			count(*) FILTER (WHERE lifecycle IN ('PUBLISHED','PUBLISHED_LOCAL')),
			count(*) FILTER (WHERE lifecycle = 'REJECTED')
		FROM content_versions`).Scan(&f.Candidate, &f.Validated, &f.Published, &f.Rejected)
	return f, err
}

// DataQuality surfaces signals that undermine trust in the other metrics:
// sources that have gone quiet, and content stuck mid-validation.
type DataQuality struct {
	StaleSources     []string `json:"staleSources"`
	StaleValidations int      `json:"staleValidations"`
}

// dataQuality reports sources with no successful sync in staleAfter (this
// also catches a source that has NEVER synced successfully -- NOT EXISTS
// is true for both cases, and surfacing a never-synced source as "stale"
// here is correct: it IS stale, just maximally so; ingestionHealth is
// where the never-vs-stale distinction is reported precisely), and
// content_versions stuck in VALIDATING whose transition into that state
// happened more than staleAfter ago.
func dataQuality(ctx context.Context, pool *pgxpool.Pool, staleAfter time.Duration) (DataQuality, error) {
	cutoff := time.Now().Add(-staleAfter)

	rows, err := pool.Query(ctx, `
		SELECT si.display_name FROM source_instances si
		WHERE NOT EXISTS (
			SELECT 1 FROM source_syncs ss
			WHERE ss.source_instance_id = si.id AND ss.status = 'succeeded' AND ss.completed_at >= $1
		)
		ORDER BY si.id`, cutoff)
	if err != nil {
		return DataQuality{}, err
	}
	defer rows.Close()
	var staleSources []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return DataQuality{}, err
		}
		staleSources = append(staleSources, name)
	}
	if err := rows.Err(); err != nil {
		return DataQuality{}, err
	}

	var staleValidations int
	err = pool.QueryRow(ctx, `
		SELECT count(*) FROM content_versions cv
		WHERE cv.lifecycle = 'VALIDATING'
		AND EXISTS (
			SELECT 1 FROM content_version_events e
			WHERE e.content_version_id = cv.id AND e.to_lifecycle = 'VALIDATING' AND e.at < $1
		)`, cutoff).Scan(&staleValidations)
	if err != nil {
		return DataQuality{}, err
	}

	return DataQuality{StaleSources: staleSources, StaleValidations: staleValidations}, nil
}

// minTrendPoints is the smallest number of real data points the UI will
// draw as a trend line. Below this, a line would misleadingly imply more
// history than exists -- the UI shows an empty state instead (spec).
const minTrendPoints = 3

type TrendPoint struct {
	Day   time.Time `json:"day"`
	Value float64   `json:"value"`
}

type Trends struct {
	ThreatsProcessedByDay []TrendPoint `json:"threatsProcessedByDay"`
	TCVByDay              []TrendPoint `json:"tcvByDay"`
}

func threatsProcessedTrend(ctx context.Context, pool *pgxpool.Pool, since time.Time) ([]TrendPoint, error) {
	rows, err := pool.Query(ctx, `
		SELECT date_trunc('day', created_at), count(*)
		FROM threats WHERE created_at >= $1
		GROUP BY 1 ORDER BY 1`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var points []TrendPoint
	for rows.Next() {
		var p TrendPoint
		var n int
		if err := rows.Scan(&p.Day, &n); err != nil {
			return nil, err
		}
		p.Value = float64(n)
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(points) < minTrendPoints {
		return nil, nil
	}
	return points, nil
}

// tcvTrend averages threat-to-emulation TCV (seconds) by the day coverage
// first became executable, scoped to the same ClockThreat/RelationshipEmulates
// combination as tcv.AggregateMetrics.
func tcvTrend(ctx context.Context, pool *pgxpool.Pool, since time.Time) ([]TrendPoint, error) {
	rows, err := pool.Query(ctx, `
		SELECT date_trunc('day', f.first_executable_at), avg(EXTRACT(EPOCH FROM (f.first_executable_at - s.started_at)))
		FROM threat_clock_starts s
		JOIN threat_coverage_firsts f ON f.threat_id = s.threat_id AND f.relationship_kind = 'emulates'
		WHERE s.clock = 'threat' AND f.first_executable_at >= s.started_at AND f.first_executable_at >= $1
		GROUP BY 1 ORDER BY 1`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var points []TrendPoint
	for rows.Next() {
		var p TrendPoint
		if err := rows.Scan(&p.Day, &p.Value); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(points) < minTrendPoints {
		return nil, nil
	}
	return points, nil
}

type PipelineStatus struct {
	Ingestion   IngestionHealth `json:"ingestion"`
	Funnel      LifecycleFunnel `json:"funnel"`
	DataQuality DataQuality     `json:"dataQuality"`
}

// FactoryHealthReport is the full GET /api/analytics/factory-health
// response (spec: docs/superpowers/specs/2026-10-13-tcf-phase11-factory-analytics-design.md).
type FactoryHealthReport struct {
	WindowSince               time.Time      `json:"windowSince"`
	ThreatsProcessed          Metric         `json:"threatsProcessed"`
	PublishedContent          Metric         `json:"publishedContent"`
	MedianThreatToContentTCV  Metric         `json:"medianThreatToContentTcv"`
	P95ThreatToContentTCV     Metric         `json:"p95ThreatToContentTcv"`
	StaticValidationPassRate  Metric         `json:"staticValidationPassRate"`
	DuplicateGenerationRate   Metric         `json:"duplicateGenerationRate"`
	SourceToTechniqueCoverage Metric         `json:"sourceToTechniqueCoverage"`
	Pipeline                  PipelineStatus `json:"pipeline"`
	Trends                    Trends         `json:"trends"`
}

const staleAfter = 7 * 24 * time.Hour

// FactoryHealth assembles every factory-health metric for the trailing
// window. window is the lookback used by count/rate metrics and the
// trend queries; staleAfter (the data-quality staleness threshold) is
// fixed separately at 7 days regardless of window.
func FactoryHealth(ctx context.Context, pool *pgxpool.Pool, window time.Duration) (FactoryHealthReport, error) {
	since := time.Now().Add(-window)

	counts, err := coreCounts(ctx, pool, since)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	passRate, err := staticValidationPassRate(ctx, pool, since)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	ingestion, err := ingestionHealth(ctx, pool, since)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	funnel, err := lifecycleFunnel(ctx, pool)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	dq, err := dataQuality(ctx, pool, staleAfter)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	threatsTrend, err := threatsProcessedTrend(ctx, pool, since)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	tcvTrendPts, err := tcvTrend(ctx, pool, since)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	tcvAgg, err := tcv.AggregateMetrics(ctx, pool)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	dupRate, err := duplicateGenerationRate(ctx, pool, since)
	if err != nil {
		return FactoryHealthReport{}, err
	}

	median := noData("no threats have measured threat-to-emulation TCV yet")
	p95 := noData("no threats have measured threat-to-emulation TCV yet")
	if tcvAgg.SampleSize > 0 {
		median = measured(*tcvAgg.MedianSeconds)
		p95 = measured(*tcvAgg.P95Seconds)
	}

	return FactoryHealthReport{
		WindowSince:               since,
		ThreatsProcessed:          counts.ThreatsProcessed,
		PublishedContent:          counts.PublishedContent,
		MedianThreatToContentTCV:  median,
		P95ThreatToContentTCV:     p95,
		StaticValidationPassRate:  passRate,
		DuplicateGenerationRate:   dupRate,
		SourceToTechniqueCoverage: counts.SourceToTechniqueCoverage,
		Pipeline:                  PipelineStatus{Ingestion: ingestion, Funnel: funnel, DataQuality: dq},
		Trends:                    Trends{ThreatsProcessedByDay: threatsTrend, TCVByDay: tcvTrendPts},
	}, nil
}
