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
