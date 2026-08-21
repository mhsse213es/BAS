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
	// CVE lookup is only possible with both a relationship source and an
	// enricher (vulnerabilitiesForTechniques returns an empty map otherwise).
	// Without it "no CVEs found" is indistinguishable from "never looked",
	// and the pure-deficit score would call that a perfect 100.
	cveLookupAvailable := rels != nil && enricher != nil

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
		isDC := false
		if p.asset.nodeID != "" {
			if n, ok := g.Node(p.asset.nodeID); ok {
				profile.Asset.Label = n.Label
				profile.Asset.CrownJewel = n.CrownJewel
				profile.Asset.Segment = n.Segment
				profile.Asset.HighValue = n.HighValue
				profile.Asset.CriticalityTier = n.CriticalityTier
				profile.Asset.InternetFacing = n.InternetFacing
				profile.Asset.IdentityExposed = n.IdentityExposed
				profile.Asset.Production = n.Production
				profile.Asset.ComplianceScope = n.ComplianceScope
				isDC = n.Role == attackpath.RoleDC
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

		critRisk := float64(CriticalityRisk(AssetCriticalityInputs{
			CriticalityTier:    profile.Asset.CriticalityTier,
			InternetFacing:     profile.Asset.InternetFacing,
			IdentityExposed:    profile.Asset.IdentityExposed,
			Production:         profile.Asset.Production,
			ComplianceScope:    profile.Asset.ComplianceScope,
			IsDomainController: isDC,
			ThreatGroupCount:   len(profile.ThreatIntel),
		}))

		attackPathScore := clamp100(100 - int(p.apRisk+0.5))
		detectionScore := clamp100(100 - int(p.detRisk+0.5))
		vulnScore := clamp100(100 - int(worst+0.5))
		// SP6: criticality is a 4th weighted term, reweighted from
		// .40/.35/.25 — see docs/superpowers/specs/2026-07-17-sp6-asset-criticality-design.md
		// and ADR-009 for why (accepted trade-off: a well-defended critical
		// asset still costs up to 20 points, by design).
		exposureRisk := 0.30*p.apRisk + 0.30*p.detRisk + 0.20*worst + 0.20*critRisk
		exposureScore := clamp100(100 - int(exposureRisk+0.5))

		// Measurability -- see ScoreBreakdown's doc comment. Each of these
		// scores is 100-minus-risk, so "nothing collected" silently produces a
		// flawless score; record whether there was anything to measure at all
		// so consumers can show "not collected" instead of a green 100.
		//   - attack path: this asset is actually a node in the graph. An asset
		//     that exists only as an enrolled agent row has no path data.
		//   - detection: the correlation itself had weighted paths to score AND
		//     this asset has correlated edges of its own.
		//   - vulnerability: a CVE lookup was actually possible and this asset
		//     had at least one technique to look up.
		apMeasurable := p.asset.nodeID != ""
		detMeasurable := corr.Measurable && len(p.detect.Edges) > 0
		vulnMeasurable := cveLookupAvailable && len(p.techIDs) > 0
		profile.Scores = ScoreBreakdown{
			ExposureScore:          exposureScore,
			AttackPathScore:        attackPathScore,
			DetectionCoverageScore: detectionScore,
			VulnerabilityScore:     vulnScore,
			CriticalityRisk:        int(critRisk),

			AttackPathMeasurable:    apMeasurable,
			DetectionMeasurable:     detMeasurable,
			VulnerabilityMeasurable: vulnMeasurable,
			// The blended exposure score is only meaningful if at least one of
			// its risk terms came from real data. Criticality alone doesn't
			// count: it is asset metadata, not an observation about the
			// asset's security state.
			ExposureMeasurable: apMeasurable || detMeasurable || vulnMeasurable,
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
			CriticalityTier:        p.Asset.CriticalityTier,
			CriticalityRisk:        p.Scores.CriticalityRisk,
		})
	}
	return out
}
