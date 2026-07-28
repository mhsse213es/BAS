package recommend

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

const defaultLimit = 20

// techRow is one entry in the executable universe.
type techRow struct {
	id     string
	name   string
	tactic string
}

// coverageRow is the fleet's most recent real test of a technique.
type coverageRow struct {
	lastTested time.Time
	verdict    string
}

// Build ranks the ART-testable ATT&CK techniques by how much value testing
// them next would add, and emits a runnable SuggestedScenario from the top N.
//
// The caller builds the graph (same "caller builds it once" convention as
// exposure.Build) — pass a nil graph when no attack-path collection has run
// and every technique simply scores 0 on environment relevance, rather than
// having relevance fabricated for it.
//
// Nil-safe: unseeded content returns an empty Recommendations, never an error.
func Build(ctx context.Context, pool *pgxpool.Pool, g *attackpath.Graph, s attackpath.Summary, limit int, sectors, regions []string, actorPriorityByTechnique map[string]int) (Recommendations, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	empty := Recommendations{Techniques: []RecommendedTechnique{}}

	universe, err := loadExecutableTechniques(ctx, pool)
	if err != nil {
		return Recommendations{}, err
	}
	if len(universe) == 0 {
		return empty, nil
	}

	coverage, err := loadCoverage(ctx, pool)
	if err != nil {
		return Recommendations{}, err
	}
	kev, err := loadKEVTechniques(ctx, pool)
	if err != nil {
		return Recommendations{}, err
	}
	epss, err := loadEPSSPercentiles(ctx, pool)
	if err != nil {
		return Recommendations{}, err
	}
	actors := actorCounts()
	sectorRegionRelevant, err := reporting.SectorRegionRelevantTechniques(ctx, pool, sectors, regions)
	if err != nil {
		sectorRegionRelevant = map[string]bool{}
	}
	env := buildEnvIndex(g, s, pathcorrelation.DefaultEdgeTechniqueMapper{})

	now := time.Now().UTC()
	out := make([]RecommendedTechnique, 0, len(universe))
	for _, u := range universe {
		key := strings.ToUpper(u.id)

		var lastTested *time.Time
		verdict := ""
		if c, ok := coverage[key]; ok {
			lt := c.lastTested
			lastTested = &lt
			verdict = c.verdict
		}

		t := RecommendedTechnique{
			TechniqueID:    u.id,
			Name:           u.name,
			Tactic:         u.tactic,
			CoverageState:  CoverageStateFor(lastTested, now),
			LastTestedAt:   lastTested,
			LastVerdict:    verdict,
			KEV:            kev[key],
			EPSSPercentile: epss[key],
			ThreatActors:   actors[key],
			ActorPriority:  actorPriorityByTechnique[key],
		}
		t.ThreatPriority = reporting.ComputePriorityScore(t.KEV, t.EPSSPercentile, t.ThreatActors, verdict, sectorRegionRelevant[key])
		t.CoverageGap = CoverageGap(lastTested, now)
		t.EnvironmentRisk = EnvironmentRisk(env.inGraph[key], env.onCriticalPath[key], env.targetsCritical[key])
		t.Score = RecommendationScore(t.ActorPriority, t.ThreatPriority, t.CoverageGap, t.EnvironmentRisk)
		t.Tier = reporting.PriorityTierFor(t.Score)
		t.Reasons = buildReasons(t, now)
		out = append(out, t)
	}

	// Score desc, then technique ID asc so the ranking is deterministic.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].TechniqueID < out[j].TechniqueID
	})
	if len(out) > limit {
		out = out[:limit]
	}

	ids := make([]string, len(out))
	for i, t := range out {
		ids[i] = t.TechniqueID
	}
	day := now.Format("2006-01-02")
	return Recommendations{
		Techniques: out,
		HasData:    len(out) > 0,
		SuggestedScenario: SuggestedScenario{
			ID:            "recommended-" + now.Format("20060102"),
			Name:          fmt.Sprintf("Recommended Next Simulations — %s", day),
			Description:   "Auto-ranked by threat priority, coverage gap, and environment relevance.",
			ARTTechniques: ids,
		},
	}, nil
}

// loadExecutableTechniques is the universe: every seeded technique that has at
// least one ART atomic test to actually run. Recommending something with no
// test attached would be noise.
func loadExecutableTechniques(ctx context.Context, pool *pgxpool.Pool) ([]techRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT t.technique_id, t.name, t.tactic
		FROM techniques t
		WHERE EXISTS (SELECT 1 FROM art_atomic_tests a WHERE a.technique_id = t.technique_id)
		ORDER BY t.technique_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []techRow
	for rows.Next() {
		var r techRow
		if rows.Scan(&r.id, &r.name, &r.tactic) == nil {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// loadCoverage returns each technique's most recent REAL test across the whole
// fleet. ERROR and SKIPPED are excluded deliberately: per the project's
// 4-verdict taxonomy they mean the BAS could not execute the technique, so
// they say nothing about coverage and must not suppress a recommendation.
func loadCoverage(ctx context.Context, pool *pgxpool.Pool) (map[string]coverageRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (UPPER(r->'technique'->>'id'))
		       UPPER(r->'technique'->>'id')      AS tid,
		       (r->>'executedAt')::timestamptz   AS last_tested,
		       r->>'result'                      AS verdict
		FROM scenario_runs sr, jsonb_array_elements(sr.results) r
		WHERE sr.status IN ('completed', 'partial')
		  AND r->'technique'->>'id' IS NOT NULL
		  AND r->'technique'->>'id' <> ''
		  AND r->>'executedAt' IS NOT NULL
		  AND r->>'result' NOT IN ('error', 'skipped')
		ORDER BY UPPER(r->'technique'->>'id'), (r->>'executedAt')::timestamptz DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]coverageRow{}
	for rows.Next() {
		var tid string
		var c coverageRow
		if rows.Scan(&tid, &c.lastTested, &c.verdict) == nil {
			out[tid] = c
		}
	}
	return out, rows.Err()
}

// loadKEVTechniques marks techniques linked to a CISA KEV CVE. Gated on the
// Relationship Store's Active + High/Medium confidence contract — the same
// gating reporting.populatePriorityScores uses. Never reads bare technique_cves.
func loadKEVTechniques(ctx context.Context, pool *pgxpool.Pool) (map[string]bool, error) {
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT tc.technique_id
		FROM technique_cve_relationships tc
		JOIN cves c ON c.cve_id = tc.cve_id AND c.source = 'cisa-kev'
		WHERE tc.status = 'Active' AND tc.effective_confidence IN ('High', 'Medium')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var tid string
		if rows.Scan(&tid) == nil {
			out[strings.ToUpper(tid)] = true
		}
	}
	return out, rows.Err()
}

// loadEPSSPercentiles returns the highest EPSS percentile (0-100) among each
// technique's scored CVE relationships. Same ×100 convention as
// reporting.populatePriorityScores.
func loadEPSSPercentiles(ctx context.Context, pool *pgxpool.Pool) (map[string]float64, error) {
	rows, err := pool.Query(ctx, `
		SELECT tc.technique_id, MAX(ce.percentile)
		FROM technique_cve_relationships tc
		JOIN cve_epss ce ON ce.cve_id = tc.cve_id
		WHERE tc.status = 'Active' AND tc.effective_confidence IN ('High', 'Medium')
		GROUP BY tc.technique_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var tid string
		var pct float64
		if rows.Scan(&tid, &pct) == nil {
			out[strings.ToUpper(tid)] = pct * 100
		}
	}
	return out, rows.Err()
}

// actorCounts inverts the bundled ATT&CK STIX group index into
// technique -> number of attributed groups. Always available (embedded), so
// threat priority degrades to this alone when the Relationship Store is empty.
func actorCounts() map[string]int {
	out := map[string]int{}
	for _, techIDs := range attackdata.GroupTechniqueIndex() {
		for _, tid := range techIDs {
			out[strings.ToUpper(tid)]++
		}
	}
	return out
}

// envIndex answers, per technique: does it traverse a real edge, is that edge
// on a domain-compromise/crown-jewel path, and does it target a high-criticality
// asset.
type envIndex struct {
	inGraph         map[string]bool
	onCriticalPath  map[string]bool
	targetsCritical map[string]bool
}

func buildEnvIndex(g *attackpath.Graph, s attackpath.Summary, mapper pathcorrelation.EdgeTechniqueMapper) envIndex {
	idx := envIndex{
		inGraph:         map[string]bool{},
		onCriticalPath:  map[string]bool{},
		targetsCritical: map[string]bool{},
	}
	if g == nil {
		return idx
	}
	mark := func(e attackpath.Edge, critical bool) {
		targetsCrit := false
		if n, ok := g.Node(e.To); ok {
			targetsCrit = n.CriticalityTier == "critical" || n.CriticalityTier == "high"
		}
		for _, tm := range mapper.Techniques(e.Kind) {
			tid := strings.ToUpper(tm.TechniqueID)
			idx.inGraph[tid] = true
			if critical {
				idx.onCriticalPath[tid] = true
			}
			if targetsCrit {
				idx.targetsCritical[tid] = true
			}
		}
	}
	for _, e := range g.Edges() {
		mark(e, false)
	}
	for _, p := range pathcorrelation.DefaultPaths(g, s) {
		for _, e := range p.Edges {
			mark(e, true)
		}
	}
	return idx
}
