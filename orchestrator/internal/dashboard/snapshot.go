// Package dashboard is the Phase 6 executive-dashboard aggregator: a pure
// consumer over the already-shipped attack-path graph (internal/attackpath),
// SP3 detection correlation (internal/pathcorrelation), and SP4 exposure
// scoring (internal/exposure), reduced to fleet-wide averages for a
// time-series view. It owns no DB tables itself — internal/api's scheduler
// persists what Compute returns.
package dashboard

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
)

// Snapshot is the fleet-wide posture at the moment Compute was called.
type Snapshot struct {
	AvgRiskScore      int `json:"avgRiskScore"`
	ExposureScore     int `json:"exposureScore"`
	DetectionCoverage int `json:"detectionCoverage"`
	AssetCount        int `json:"assetCount"`
}

// Compute builds today's fleet-wide snapshot. Nil-safe: an empty fleet (no
// runs, no assets) returns a zero-value Snapshot, never an error — same
// convention as exposure.Build/pathcorrelation.Correlate.
func Compute(ctx context.Context, pool *pgxpool.Pool) (Snapshot, error) {
	riskScore, err := avgRiskScore(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}

	cols, err := loadCollections(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}
	tags, err := loadAssetTags(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}
	g, s := attackpath.BuildGraphAndAnalyze(cols, tags)

	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(ctx, g, s, paths,
		pathcorrelation.DefaultEdgeTechniqueMapper{}, pathcorrelation.NewSQLRunLookup(pool), nil)
	if err != nil {
		return Snapshot{}, err
	}

	agents, err := loadAgents(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}
	ag, err := exposure.Build(ctx, g, s, corr, nil,
		exposure.NewSQLCVEEnricher(pool), exposure.NewSQLFindingsLookup(pool), agents)
	if err != nil {
		return Snapshot{}, err
	}
	summaries := ag.Summaries()

	exposureAvg := 0
	if len(summaries) > 0 {
		total := 0
		for _, a := range summaries {
			total += a.ExposureScore
		}
		exposureAvg = total / len(summaries)
	}

	return Snapshot{
		AvgRiskScore:      riskScore,
		ExposureScore:     exposureAvg,
		DetectionCoverage: corr.Score,
		AssetCount:        len(summaries),
	}, nil
}

func avgRiskScore(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var avg int
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(ROUND(AVG((score->>'riskScore')::numeric)), 0)::int
		FROM scenario_runs
		WHERE completed_at IS NOT NULL
		  AND completed_at > NOW() - INTERVAL '30 days'
		  AND score IS NOT NULL`).Scan(&avg)
	return avg, err
}

func loadCollections(ctx context.Context, pool *pgxpool.Pool) ([]attackpath.Collection, error) {
	rows, err := pool.Query(ctx, `SELECT payload FROM attackpath_collections`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []attackpath.Collection
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			continue
		}
		var c attackpath.Collection
		if json.Unmarshal(raw, &c) == nil {
			cols = append(cols, c)
		}
	}
	return cols, rows.Err()
}

func loadAssetTags(ctx context.Context, pool *pgxpool.Pool) ([]attackpath.AssetTag, error) {
	rows, err := pool.Query(ctx, `
		SELECT host_key, label, crown_jewel, segment, high_value,
		       criticality_tier, internet_facing, identity_exposed, production, compliance_scope
		FROM attackpath_asset_tags`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []attackpath.AssetTag
	for rows.Next() {
		var t attackpath.AssetTag
		if rows.Scan(&t.HostKey, &t.Label, &t.CrownJewel, &t.Segment, &t.HighValue,
			&t.CriticalityTier, &t.InternetFacing, &t.IdentityExposed, &t.Production, &t.ComplianceScope) == nil {
			tags = append(tags, t)
		}
	}
	return tags, rows.Err()
}

func loadAgents(ctx context.Context, pool *pgxpool.Pool) ([]exposure.AgentRow, error) {
	rows, err := pool.Query(ctx, `SELECT agent_id, hostname, ip_address, os_version FROM agents`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []exposure.AgentRow
	for rows.Next() {
		var a exposure.AgentRow
		if rows.Scan(&a.AgentID, &a.Hostname, &a.IP, &a.OS) == nil {
			out = append(out, a)
		}
	}
	return out, rows.Err()
}
