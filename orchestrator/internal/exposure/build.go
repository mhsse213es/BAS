package exposure

import (
	"context"
	"sort"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

// AssetGraph is the result of one Build() call: every asset's profile,
// computed once. Summaries()/Profile() are cheap accessors — Build() is the
// only expensive call (one CVE enrichment batch, one findings batch,
// regardless of asset count).
type AssetGraph struct {
	profiles map[string]AssetExposureProfile
	order    []string
}

// Build computes every asset's AssetExposureProfile in one pass over an
// already-built graph/summary/correlation (same "caller builds it once"
// convention as SP3's API handler). nil rels/enricher/findingsLookup are
// safe — those sections of every profile are simply left at their zero
// value, matching this API's nil-safe-optional-subsystem convention.
func Build(ctx context.Context, g *attackpath.Graph, s attackpath.Summary,
	corr pathcorrelation.AttackPathCorrelation, rels RelationshipLookup,
	enricher CVEEnricher, findingsLookup FindingsLookup, agents []AgentRow) (*AssetGraph, error) {

	assets := unionAssets(g, agents)

	type partial struct {
		asset   assetNode
		detect  DetectionContext
		detRisk float64
		apCtx   AttackPathContext
		apRisk  float64
		techIDs []string
	}
	partials := make([]partial, 0, len(assets))
	allTechIDs := map[string]bool{}
	for _, a := range assets {
		dc, detRisk := detectionContext(corr, a.nodeID)
		apCtx, apRisk := attackPathContext(g, s, a.nodeID)
		techSet := map[string]bool{}
		for _, e := range dc.Edges {
			for _, t := range e.Status.Techniques {
				techSet[t.TechniqueID] = true
				allTechIDs[t.TechniqueID] = true
			}
		}
		techIDs := make([]string, 0, len(techSet))
		for t := range techSet {
			techIDs = append(techIDs, t)
		}
		sort.Strings(techIDs)
		partials = append(partials, partial{asset: a, detect: dc, detRisk: detRisk, apCtx: apCtx, apRisk: apRisk, techIDs: techIDs})
	}

	techIDList := make([]string, 0, len(allTechIDs))
	for t := range allTechIDs {
		techIDList = append(techIDList, t)
	}
	sort.Strings(techIDList)
	cveByTech, err := vulnerabilitiesForTechniques(ctx, techIDList, rels, enricher)
	if err != nil {
		return nil, err
	}

	var findingsByAgent map[string][]FindingSummary
	if findingsLookup != nil {
		findingsByAgent, err = findingsLookup.AllOpenFindings(ctx)
		if err != nil {
			return nil, err
		}
	}

	ag := &AssetGraph{profiles: map[string]AssetExposureProfile{}}
	for _, p := range partials {
		profile := AssetExposureProfile{
			Asset:      AssetIdentity{HostKey: p.asset.hostKey},
			AttackPath: p.apCtx,
			Detection:  p.detect,
		}
		if p.asset.nodeID != "" {
			if n, ok := g.Node(p.asset.nodeID); ok {
				profile.Asset.Label = n.Label
				profile.Asset.CrownJewel = n.CrownJewel
				profile.Asset.Segment = n.Segment
				profile.Asset.HighValue = n.HighValue
			}
		}
		if p.asset.agent != nil {
			profile.Asset.Managed = true
			profile.Asset.AgentID = p.asset.agent.AgentID
			profile.Asset.OS = p.asset.agent.OS
			profile.Asset.IP = p.asset.agent.IP
			if profile.Asset.Label == "" {
				profile.Asset.Label = p.asset.agent.Hostname
			}
		}
		if profile.Asset.Label == "" {
			profile.Asset.Label = p.asset.hostKey
		}

		seen := map[string]bool{}
		var vulns []CVEExposure
		worst := 0.0
		for _, t := range p.techIDs {
			for _, cve := range cveByTech[t] {
				if seen[cve.CVEID] {
					continue
				}
				seen[cve.CVEID] = true
				vulns = append(vulns, cve)
				if cve.Severity > worst {
					worst = cve.Severity
				}
			}
		}
		profile.Vulnerabilities = vulns

		groupTechs := map[string]map[string]bool{}
		var groupOrder []string
		for _, t := range p.techIDs {
			e := attackdata.Lookup(t)
			if e == nil {
				continue
			}
			for _, gName := range e.Groups {
				if groupTechs[gName] == nil {
					groupTechs[gName] = map[string]bool{}
					groupOrder = append(groupOrder, gName)
				}
				groupTechs[gName][t] = true
			}
		}
		sort.Strings(groupOrder)
		for _, gName := range groupOrder {
			techs := make([]string, 0, len(groupTechs[gName]))
			for t := range groupTechs[gName] {
				techs = append(techs, t)
			}
			sort.Strings(techs)
			profile.ThreatIntel = append(profile.ThreatIntel, ThreatGroupExposure{GroupName: gName, TechniqueIDs: techs})
		}

		if p.asset.agent != nil {
			profile.Findings.Collected = true
			list := findingsByAgent[p.asset.agent.AgentID]
			profile.Findings.Findings = list
			profile.Findings.OpenCount = len(list)
			for _, f := range list {
				if f.Severity == "Critical" {
					profile.Findings.CriticalCount++
				}
			}
		}

		if p.asset.nodeID != "" {
			for _, gp := range corr.Gaps {
				if gp.Edge.From == p.asset.nodeID || gp.Edge.To == p.asset.nodeID {
					profile.Recommendations = append(profile.Recommendations, gp)
				}
			}
		}

		attackPathScore := clamp100(100 - int(p.apRisk+0.5))
		detectionScore := clamp100(100 - int(p.detRisk+0.5))
		vulnScore := clamp100(100 - int(worst+0.5))
		exposureRisk := 0.40*p.apRisk + 0.35*p.detRisk + 0.25*worst
		exposureScore := clamp100(100 - int(exposureRisk+0.5))
		profile.Scores = ScoreBreakdown{
			ExposureScore:          exposureScore,
			AttackPathScore:        attackPathScore,
			DetectionCoverageScore: detectionScore,
			VulnerabilityScore:     vulnScore,
		}

		ag.profiles[p.asset.hostKey] = profile
		ag.order = append(ag.order, p.asset.hostKey)
	}
	return ag, nil
}

func clamp100(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// Profile returns the profile for hostKey (must already be normalized —
// API handlers use attackpath.NormalizeHostKey before calling this).
func (ag *AssetGraph) Profile(hostKey string) (AssetExposureProfile, bool) {
	p, ok := ag.profiles[hostKey]
	return p, ok
}

// Summaries returns the lightweight index row for every asset, in Build's
// stable asset-union order.
func (ag *AssetGraph) Summaries() []AssetSummary {
	out := make([]AssetSummary, 0, len(ag.order))
	for _, k := range ag.order {
		p := ag.profiles[k]
		var worst float64
		var kev bool
		for _, v := range p.Vulnerabilities {
			if v.Severity > worst {
				worst = v.Severity
			}
			if v.KEV {
				kev = true
			}
		}
		out = append(out, AssetSummary{
			Asset:                  p.Asset,
			ExposureScore:          p.Scores.ExposureScore,
			AttackPathScore:        p.Scores.AttackPathScore,
			DetectionCoverageScore: p.Scores.DetectionCoverageScore,
			WorstCVESeverity:       worst,
			KEVExposed:             kev,
			OpenFindingsCount:      p.Findings.OpenCount,
		})
	}
	return out
}
