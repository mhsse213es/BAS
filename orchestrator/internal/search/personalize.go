package search

import (
	"context"
	"math"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

// popularityWeight keeps the org-wide popularity signal intentionally
// smaller than personal recency -- popularity is a secondary nudge, not a
// competing primary signal. See design doc §Architecture 2.
const popularityWeight = 0.1

// Personalize re-orders results (already ranked by ts_rank via Query) for a
// specific user: their favorited entities are hard-pinned first, in their
// original relevance order; the remainder is re-sorted using a small
// recency/popularity score bump layered on top of relevance -- a strong
// relevance match is never inverted by a weak recency/popularity one, since
// ties in the bump (the common case, most results have no personalization
// signal at all) fall back to original relevance order via sort.SliceStable.
func Personalize(ctx context.Context, pool *pgxpool.Pool, userID string, results []Document) ([]Document, error) {
	if len(results) == 0 || userID == "" {
		return results, nil
	}

	favSet, err := favoriteSet(ctx, pool, userID)
	if err != nil {
		return nil, err
	}
	recency, err := recencyScores(ctx, pool, userID)
	if err != nil {
		return nil, err
	}
	popularity, err := popularityScores(ctx, pool)
	if err != nil {
		return nil, err
	}

	favorited := make([]Document, 0, len(results))
	rest := make([]Document, 0, len(results))
	for _, d := range results {
		d.Favorited = favSet[key(d.DocType, d.SourceID)]
		if d.Favorited {
			favorited = append(favorited, d)
		} else {
			rest = append(rest, d)
		}
	}

	type scored struct {
		doc  Document
		bump float64
	}
	scoredRest := make([]scored, len(rest))
	for i, d := range rest {
		k := key(d.DocType, d.SourceID)
		scoredRest[i] = scored{doc: d, bump: recency[k] + popularity[k]}
	}
	sort.SliceStable(scoredRest, func(i, j int) bool {
		return scoredRest[i].bump > scoredRest[j].bump
	})

	out := make([]Document, 0, len(results))
	out = append(out, favorited...)
	for _, s := range scoredRest {
		out = append(out, s.doc)
	}
	return out, nil
}

func key(docType, sourceID string) string { return docType + ":" + sourceID }

func favoriteSet(ctx context.Context, pool *pgxpool.Pool, userID string) (map[string]bool, error) {
	rows, err := pool.Query(ctx, `SELECT doc_type, source_id FROM search_favorites WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var dt, sid string
		if err := rows.Scan(&dt, &sid); err != nil {
			return nil, err
		}
		out[key(dt, sid)] = true
	}
	return out, rows.Err()
}

// recencyScores returns, for each entity this user selected in the last 30
// days, 1.0 / (1.0 + daysSinceLastSelection) -- close to 1.0 for something
// opened moments ago, close to 0.03 for something opened 30 days ago.
func recencyScores(ctx context.Context, pool *pgxpool.Pool, userID string) (map[string]float64, error) {
	rows, err := pool.Query(ctx,
		`SELECT doc_type, source_id, EXTRACT(EPOCH FROM (NOW() - MAX(created_at))) / 86400.0
		 FROM search_selections
		 WHERE user_id = $1 AND created_at > NOW() - INTERVAL '30 days'
		 GROUP BY doc_type, source_id`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var dt, sid string
		var daysSince float64
		if err := rows.Scan(&dt, &sid, &daysSince); err != nil {
			return nil, err
		}
		out[key(dt, sid)] = 1.0 / (1.0 + daysSince)
	}
	return out, rows.Err()
}

// popularityScores returns, for each entity selected by anyone in the last
// 30 days, log(1+count)*popularityWeight -- log-scaled so 50 vs. 500
// selections isn't a 10x swing in the final bump.
func popularityScores(ctx context.Context, pool *pgxpool.Pool) (map[string]float64, error) {
	rows, err := pool.Query(ctx,
		`SELECT doc_type, source_id, COUNT(*)
		 FROM search_selections
		 WHERE created_at > NOW() - INTERVAL '30 days'
		 GROUP BY doc_type, source_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var dt, sid string
		var count int
		if err := rows.Scan(&dt, &sid, &count); err != nil {
			return nil, err
		}
		out[key(dt, sid)] = math.Log(1+float64(count)) * popularityWeight
	}
	return out, rows.Err()
}
