package analytics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SourceReliability is one source's measured reliability over the window. Three
// independent questions, kept separate so a source weak on one is not hidden by
// strength on another:
//
//   - sync success: did its syncs complete? (succeeded / all syncs)
//   - resolution: did its records land on a known threat? (observations linked
//     to a threat / all observations)
//   - usefulness: did its threats lead to content? (threats from this source
//     that have published content / threats from this source)
//
// Each rate is NO_DATA, not 0%, when its denominator is zero. Usefulness lags:
// a threat ingested today has had little time to reach publication, so a young
// window reads low. It is the share of this window's threats that have reached
// published content so far, not a final verdict on the source.
type SourceReliability struct {
	SyncsInWindow               int    `json:"syncsInWindow"`
	SyncSuccessRate             Metric `json:"syncSuccessRate"`
	Observations                int    `json:"observations"`
	ResolvedObservations        int    `json:"resolvedObservations"`
	ResolutionRate              Metric `json:"resolutionRate"`
	ThreatsContributed          int    `json:"threatsContributed"`
	ThreatsWithPublishedContent int    `json:"threatsWithPublishedContent"`
	UsefulnessRate              Metric `json:"usefulnessRate"`
}

// sourceReliability computes SourceReliability for every source with activity in
// the window, keyed by source instance id. Sources with no activity are absent;
// the caller reports them with all three rates NO_DATA.
func sourceReliability(ctx context.Context, pool *pgxpool.Pool, since time.Time) (map[string]SourceReliability, error) {
	out := map[string]SourceReliability{}
	get := func(id string) SourceReliability { return out[id] }

	rows, err := pool.Query(ctx, `
		SELECT source_instance_id, count(*), count(*) FILTER (WHERE status = 'succeeded')
		FROM source_syncs WHERE started_at >= $1 GROUP BY 1`, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var total, ok int
		if err := rows.Scan(&id, &total, &ok); err != nil {
			rows.Close()
			return nil, err
		}
		r := get(id)
		r.SyncsInWindow = total
		r.SyncSuccessRate = ratioOrNoData(ok, total, "no syncs in the window")
		out[id] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = pool.Query(ctx, `
		SELECT o.source_instance_id, count(*), count(ts.id)
		FROM source_observations o
		LEFT JOIN threat_sources ts ON ts.observation_id = o.id
		WHERE o.observed_at >= $1 GROUP BY 1`, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var total, linked int
		if err := rows.Scan(&id, &total, &linked); err != nil {
			rows.Close()
			return nil, err
		}
		r := get(id)
		r.Observations, r.ResolvedObservations = total, linked
		r.ResolutionRate = ratioOrNoData(linked, total, "no observations in the window")
		out[id] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = pool.Query(ctx, `
		SELECT o.source_instance_id,
		       count(DISTINCT ts.threat_id),
		       count(DISTINCT ts.threat_id) FILTER (WHERE EXISTS (
		           SELECT 1 FROM content_version_threats cvt
		           JOIN content_versions cv ON cv.id = cvt.content_version_id
		           WHERE cvt.threat_id = ts.threat_id
		             AND cv.lifecycle IN ('PUBLISHED','PUBLISHED_LOCAL')))
		FROM threat_sources ts
		JOIN source_observations o ON o.id = ts.observation_id
		WHERE o.observed_at >= $1 GROUP BY 1`, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var threats, useful int
		if err := rows.Scan(&id, &threats, &useful); err != nil {
			rows.Close()
			return nil, err
		}
		r := get(id)
		r.ThreatsContributed, r.ThreatsWithPublishedContent = threats, useful
		r.UsefulnessRate = ratioOrNoData(useful, threats, "no threats from this source in the window")
		out[id] = r
	}
	rows.Close()
	return out, rows.Err()
}

// noReliability is the reading for a source with no activity in the window.
func noReliability() SourceReliability {
	return SourceReliability{
		SyncSuccessRate: noData("no syncs in the window"),
		ResolutionRate:  noData("no observations in the window"),
		UsefulnessRate:  noData("no threats from this source in the window"),
	}
}
