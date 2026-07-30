package analytics

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/predict"
)

// FleetExposure holds the one expensive build (attack-path graph +
// detection correlation + asset exposure computation) so its accessors
// below stay cheap -- mirrors exposure.AssetGraph's own existing "Build()
// is the only expensive call" convention (internal/exposure/build.go:12-19).
type FleetExposure struct {
	corr pathcorrelation.AttackPathCorrelation
	ag   *exposure.AssetGraph
}

// BuildFleetExposure performs the one expensive pass -- the same
// attackpath.BuildGraphAndAnalyze + pathcorrelation.Correlate +
// exposure.Build sequence dashboard.Compute performed inline before this
// sub-project, moved here as the single definition. pathcorrelation.Correlate
// is computed internally because exposure.Build's existing signature
// already requires its output as an input -- this dependency predates this
// sub-project. Storing it avoids computing it twice; it does NOT make this
// sub-project the owner of Detection's canonical analytics category (see
// Correlation doc comment).
func BuildFleetExposure(ctx context.Context, pool *pgxpool.Pool) (*FleetExposure, error) {
	cols, err := loadCollections(ctx, pool)
	if err != nil {
		return nil, err
	}
	tags, err := loadAssetTags(ctx, pool)
	if err != nil {
		return nil, err
	}
	g, s := attackpath.BuildGraphAndAnalyze(cols, tags)

	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(ctx, g, s, paths,
		pathcorrelation.DefaultEdgeTechniqueMapper{}, pathcorrelation.NewSQLRunLookup(pool), nil)
	if err != nil {
		return nil, err
	}

	agents, err := loadAgents(ctx, pool)
	if err != nil {
		return nil, err
	}
	ag, err := exposure.Build(ctx, g, s, corr, nil,
		exposure.NewSQLCVEEnricher(pool), exposure.NewSQLFindingsLookup(pool), agents)
	if err != nil {
		return nil, err
	}

	return &FleetExposure{corr: corr, ag: ag}, nil
}

// Correlation returns the pathcorrelation.AttackPathCorrelation value this
// FleetExposure already computed as a prerequisite for exposure.Build --
// exposed so dashboard.Compute (Task 6) doesn't need to call Correlate a
// second time just to read corr.Score for its own DetectionCoverage field.
// This is NOT this sub-project defining Detection's canonical analytics
// API -- Sub-project C still decides what "Detection" means across
// pathcorrelation.Correlate/coverage.Compute/GetCoverageAnalytics' 3
// distinct concepts.
func (fe *FleetExposure) Correlation() pathcorrelation.AttackPathCorrelation {
	return fe.corr
}

// ExposureSummary is the fleet-wide asset exposure view.
type ExposureSummary struct {
	FleetAvgScore int                     `json:"fleetAvgScore"`
	Assets        []exposure.AssetSummary `json:"assets"`
}

// AssetExposureSummary is the cheap accessor: fleet average (same
// total/len(summaries) arithmetic dashboard.Compute performed inline
// before this sub-project) plus the full per-asset list --
// exposure.AssetGraph.Summaries()'s own []AssetSummary, unchanged, already
// served live by Operational's GetExposureAssets today via the same
// exposure.Build call. Each AssetSummary already carries both
// ExposureScore and CriticalityRisk (CriticalityRisk is computed inside
// exposure.Build itself, internal/exposure/build.go:175-183) -- there is
// no separate "asset criticality" accessor here, it was never actually a
// distinct un-unified concept.
func (fe *FleetExposure) AssetExposureSummary() ExposureSummary {
	summaries := fe.ag.Summaries()
	avg := 0
	if len(summaries) > 0 {
		total := 0
		for _, a := range summaries {
			total += a.ExposureScore
		}
		avg = total / len(summaries)
	}
	return ExposureSummary{FleetAvgScore: avg, Assets: summaries}
}

// FindingExposureWindows is unrelated to the graph/asset-based exposure
// above -- a 3rd, distinct "exposure" concept (open-finding staleness).
// Thin pass-through to predict.Build, using only its Exposure half; no
// change needed inside internal/predict, Build is already exported.
func FindingExposureWindows(ctx context.Context, pool *pgxpool.Pool) (predict.ExposureWindows, error) {
	p, err := predict.Build(ctx, pool)
	if err != nil {
		return predict.ExposureWindows{}, err
	}
	return p.Exposure, nil
}

// loadCollections and loadAssetTags and loadAgents are moved verbatim from
// internal/dashboard/snapshot.go (deleted there in Task 6, not duplicated).

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
