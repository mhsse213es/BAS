package analytics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ContentFreshness is the age distribution of content currently in a published
// lifecycle. Age runs from the most recent publish event, falling back to
// creation when no publish event was recorded. Buckets are exclusive at the
// lower bound: under30 is [0,30), days31To90 is [30,91), and so on.
type ContentFreshness struct {
	Total       int `json:"total"`
	Under30Days int `json:"under30Days"`
	Days31To90  int `json:"days31To90"`
	Days91To365 int `json:"days91To365"`
	Over365Days int `json:"over365Days"`
}

// kpiSet holds the window-based factory KPIs that FactoryHealth folds into its report.
type kpiSet struct {
	ThreatsIngestedPerDay     Metric
	CandidatesGenerated       Metric
	CandidatesGeneratedPerDay Metric
	PublishedInWindow         Metric
	PublishedPerDay           Metric
	ContentFreshness          ContentFreshness
}

// perDay divides a window count by the window length in days. It is NO_DATA
// when the window has no positive length, so a zero count still reads as a
// measured zero rather than as missing data.
func perDay(count int, windowDays float64) Metric {
	if windowDays <= 0 {
		return noData("window has no positive length")
	}
	return measured(float64(count) / windowDays)
}

// factoryKPIs computes the window-based throughput and freshness KPIs.
func factoryKPIs(ctx context.Context, pool *pgxpool.Pool, since time.Time, window time.Duration) (kpiSet, error) {
	var threats int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM threats WHERE created_at >= $1`, since).Scan(&threats); err != nil {
		return kpiSet{}, err
	}

	var candidates int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM content_versions WHERE created_at >= $1`, since).Scan(&candidates); err != nil {
		return kpiSet{}, err
	}

	var published int
	if err := pool.QueryRow(ctx, `
		SELECT count(DISTINCT content_version_id) FROM content_version_events
		WHERE to_lifecycle IN ('PUBLISHED','PUBLISHED_LOCAL') AND at >= $1`, since).Scan(&published); err != nil {
		return kpiSet{}, err
	}

	var fr ContentFreshness
	if err := pool.QueryRow(ctx, `
		WITH ages AS (
			SELECT EXTRACT(EPOCH FROM (NOW() - COALESCE(p.last_at, cv.created_at))) / 86400.0 AS age_days
			FROM content_versions cv
			LEFT JOIN LATERAL (
				SELECT max(e.at) AS last_at FROM content_version_events e
				WHERE e.content_version_id = cv.id
				  AND e.to_lifecycle IN ('PUBLISHED','PUBLISHED_LOCAL')
			) p ON true
			WHERE cv.lifecycle IN ('PUBLISHED','PUBLISHED_LOCAL')
		)
		SELECT count(*),
		       count(*) FILTER (WHERE age_days < 30),
		       count(*) FILTER (WHERE age_days >= 30 AND age_days < 91),
		       count(*) FILTER (WHERE age_days >= 91 AND age_days < 366),
		       count(*) FILTER (WHERE age_days >= 366)
		FROM ages`).Scan(&fr.Total, &fr.Under30Days, &fr.Days31To90, &fr.Days91To365, &fr.Over365Days); err != nil {
		return kpiSet{}, err
	}

	days := window.Hours() / 24
	return kpiSet{
		ThreatsIngestedPerDay:     perDay(threats, days),
		CandidatesGenerated:       measured(float64(candidates)),
		CandidatesGeneratedPerDay: perDay(candidates, days),
		PublishedInWindow:         measured(float64(published)),
		PublishedPerDay:           perDay(published, days),
		ContentFreshness:          fr,
	}, nil
}
