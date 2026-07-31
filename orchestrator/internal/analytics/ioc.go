package analytics

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IOCAnalyticsEntry is one ranked row in any of IOCAnalyticsResult's lists.
type IOCAnalyticsEntry struct {
	IOCID         string `json:"iocId"`
	Type          string `json:"type"`
	Value         string `json:"value"`
	SightingCount int    `json:"sightingCount"`
}

// IOCAnalyticsResult is the §24 dashboard summary -- the subset of
// iochandling.txt's requested metrics this registry's current data can
// honestly support. HighestBypassRate is a sighting-count proxy (no
// confidence score exists to compute a true rate from), stated as such in
// its own doc comment, not presented as a percentage.
type IOCAnalyticsResult struct {
	MostDetected      []IOCAnalyticsEntry `json:"mostDetected"`
	HighestBypassRate []IOCAnalyticsEntry `json:"highestBypassRate"`
	FrequentlyReused  []IOCAnalyticsEntry `json:"frequentlyReused"`
	LongestSurviving  []IOCAnalyticsEntry `json:"longestSurviving"`
}

// IOCAnalytics computes the 4 ranked lists behind the IOC dashboard.
func IOCAnalytics(ctx context.Context, pool *pgxpool.Pool, limit int) (IOCAnalyticsResult, error) {
	if limit <= 0 {
		limit = 10
	}
	var result IOCAnalyticsResult

	mostDetected, err := iocsByVerdict(ctx, pool, limit, "detected", "prevented")
	if err != nil {
		return result, err
	}
	result.MostDetected = mostDetected

	bypassed, err := iocsByVerdictExcludingSuppressed(ctx, pool, limit, "undetected")
	if err != nil {
		return result, err
	}
	result.HighestBypassRate = bypassed

	reused, err := scanIOCEntries(ctx, pool, `
		SELECT id, type, value, sighting_count FROM iocs
		ORDER BY sighting_count DESC LIMIT $1`, limit)
	if err != nil {
		return result, err
	}
	result.FrequentlyReused = reused

	surviving, err := scanIOCEntries(ctx, pool, `
		SELECT id, type, value, sighting_count FROM iocs
		WHERE status NOT IN ('archived', 'expired')
		ORDER BY first_seen ASC LIMIT $1`, limit)
	if err != nil {
		return result, err
	}
	result.LongestSurviving = surviving

	return result, nil
}

func iocsByVerdict(ctx context.Context, pool *pgxpool.Pool, limit int, verdicts ...string) ([]IOCAnalyticsEntry, error) {
	return scanIOCEntries(ctx, pool, `
		SELECT DISTINCT i.id, i.type, i.value, i.sighting_count
		FROM iocs i JOIN ioc_sightings s ON s.ioc_id = i.id
		WHERE s.detection_verdict = ANY($2)
		ORDER BY i.sighting_count DESC LIMIT $1`, limit, verdicts)
}

// iocsByVerdictExcludingSuppressed mirrors iocsByVerdict but excludes suppressed IOCs --
// only used for HighestBypassRate (iochandling.txt §22: an operator-accepted exception
// must not be reported as an undetected bypass). MostDetected still uses the unfiltered
// iocsByVerdict; a suppressed IOC that was actually detected isn't a misleading count.
func iocsByVerdictExcludingSuppressed(ctx context.Context, pool *pgxpool.Pool, limit int, verdicts ...string) ([]IOCAnalyticsEntry, error) {
	return scanIOCEntries(ctx, pool, `
		SELECT DISTINCT i.id, i.type, i.value, i.sighting_count
		FROM iocs i JOIN ioc_sightings s ON s.ioc_id = i.id
		WHERE s.detection_verdict = ANY($2) AND NOT i.suppressed
		ORDER BY i.sighting_count DESC LIMIT $1`, limit, verdicts)
}

func scanIOCEntries(ctx context.Context, pool *pgxpool.Pool, query string, args ...any) ([]IOCAnalyticsEntry, error) {
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []IOCAnalyticsEntry{}
	for rows.Next() {
		var e IOCAnalyticsEntry
		if err := rows.Scan(&e.IOCID, &e.Type, &e.Value, &e.SightingCount); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
