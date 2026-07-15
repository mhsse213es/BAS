package exposure

import (
	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/pathcorrelation"
)

// assetNode pairs a normalized host key with its optional graph node ID
// (empty when this asset was only ever seen via an enrolled agent, never in
// the attack-path graph) and optional agent row.
type assetNode struct {
	hostKey string
	nodeID  string
	agent   *AgentRow
}

// unionAssets merges attack-path graph host nodes with enrolled agents,
// deduplicated by attackpath.NormalizeHostKey / attackpath.HostKey (same
// normalization the attackpath package itself uses for asset tagging).
func unionAssets(g *attackpath.Graph, agents []AgentRow) []assetNode {
	idx := map[string]*assetNode{}
	var order []string
	for _, n := range g.Nodes() {
		if n.Kind != attackpath.KindHost {
			continue
		}
		k := attackpath.HostKey(n)
		if k == "" {
			continue
		}
		if _, ok := idx[k]; !ok {
			order = append(order, k)
			idx[k] = &assetNode{hostKey: k}
		}
		idx[k].nodeID = n.ID
	}
	for i := range agents {
		a := &agents[i]
		k := attackpath.NormalizeHostKey(a.Hostname)
		if k == "" {
			continue
		}
		if _, ok := idx[k]; !ok {
			order = append(order, k)
			idx[k] = &assetNode{hostKey: k}
		}
		idx[k].agent = a
	}
	out := make([]assetNode, 0, len(order))
	for _, k := range order {
		out = append(out, *idx[k])
	}
	return out
}

// attackPathRisk is the per-design-spec per-asset formula (0-100, higher =
// more exposed). nodeID == "" (asset never seen in the attack-path graph)
// returns (0, false) — v1 cannot distinguish "definitely safe" from "no
// data yet"; callers must render Reachable=false distinctly from a genuine
// low-risk reachable asset.
func attackPathRisk(g *attackpath.Graph, s attackpath.Summary, nodeID string) (risk float64, reachable bool) {
	if nodeID == "" {
		return 0, false
	}
	for _, e := range s.ShortestDAPath {
		if e.From == nodeID || e.To == nodeID {
			return 100, true
		}
	}
	for _, cj := range s.ReachableCrownJewels() {
		if cj.Node == nodeID {
			return 90, true
		}
	}
	if s.MaxBlastEntry == "" {
		return 0, false
	}
	if s.MaxBlastEntry == nodeID {
		return 100, true
	}
	path := g.ShortestPath(s.MaxBlastEntry, nodeID)
	if len(path) == 0 {
		return 0, false
	}
	risk = 100 - 15*float64(len(path))
	if risk < 20 {
		risk = 20
	}
	return risk, true
}

// attackPathContext builds the per-asset AttackPathContext alongside its
// AttackPathRisk (computed once, not duplicated).
func attackPathContext(g *attackpath.Graph, s attackpath.Summary, nodeID string) (AttackPathContext, float64) {
	risk, reachable := attackPathRisk(g, s, nodeID)
	ctx := AttackPathContext{Reachable: reachable, DistanceToNearestCrownJewel: -1}
	if nodeID == "" {
		return ctx, risk
	}
	for _, e := range s.ShortestDAPath {
		if e.From == nodeID || e.To == nodeID {
			ctx.OnShortestDAPath = true
			break
		}
	}
	best := -1
	for _, cj := range s.CrownJewels {
		if !cj.Reachable {
			continue
		}
		if nodeID == cj.Node {
			best = 0
			break
		}
		if p := g.ShortestPath(nodeID, cj.Node); len(p) > 0 && (best == -1 || len(p) < best) {
			best = len(p)
		}
	}
	ctx.DistanceToNearestCrownJewel = best
	for _, cp := range s.ChokePoints {
		if cp.Node == nodeID {
			ctx.IsChokePoint = true
			ctx.ChokePointCoverage = cp.Coverage
			break
		}
	}
	return ctx, risk
}

type edgeKey struct {
	from, to string
	kind     attackpath.EdgeKind
}

// detectionEdgesForAsset collects every AnnotatedEdge across corr's paths
// and choke points whose From or To equals nodeID, deduplicated.
func detectionEdgesForAsset(corr pathcorrelation.AttackPathCorrelation, nodeID string) []pathcorrelation.AnnotatedEdge {
	seen := map[edgeKey]bool{}
	var out []pathcorrelation.AnnotatedEdge
	add := func(e pathcorrelation.AnnotatedEdge) {
		if e.Edge.From != nodeID && e.Edge.To != nodeID {
			return
		}
		k := edgeKey{e.Edge.From, e.Edge.To, e.Edge.Kind}
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, e)
	}
	for _, p := range corr.Paths {
		for _, e := range p.Edges {
			add(e)
		}
	}
	for _, cp := range corr.ChokePoints {
		for _, e := range cp.IncomingEdges {
			add(e)
		}
	}
	return out
}

// detectionRiskFactor mirrors SP3's gapFactor scale (Gap=1.0, Unknown=0.6,
// Partial=0.4, Covered=0.0) — duplicated here deliberately (a 4-line
// switch) rather than exporting pathcorrelation's unexported constants, to
// keep the two packages decoupled per the established dependency boundary
// (nothing points back into pathcorrelation from exposure).
func detectionRiskFactor(v pathcorrelation.VerifiedStatus) float64 {
	switch v {
	case pathcorrelation.VerifiedGap:
		return 1.0
	case pathcorrelation.VerifiedUnknown:
		return 0.6
	case pathcorrelation.VerifiedPartial:
		return 0.4
	default:
		return 0.0
	}
}

// detectionContext builds the per-asset DetectionContext and its 0-100
// DetectionRisk as an AVERAGE across this asset's own touching edges —
// deliberately different from SP3's per-path weakest-link scoring (see the
// design spec's rationale: a per-asset rollup of independent incoming edges
// is better read as "how many of the ways in are covered").
func detectionContext(corr pathcorrelation.AttackPathCorrelation, nodeID string) (DetectionContext, float64) {
	edges := detectionEdgesForAsset(corr, nodeID)
	dc := DetectionContext{Edges: edges}
	var weighted float64
	for _, e := range edges {
		switch e.Status.Verified {
		case pathcorrelation.VerifiedCovered:
			dc.Covered++
		case pathcorrelation.VerifiedPartial:
			dc.Partial++
		case pathcorrelation.VerifiedGap:
			dc.Gap++
		default:
			dc.Unknown++
		}
		weighted += detectionRiskFactor(e.Status.Verified)
	}
	if len(edges) == 0 {
		return dc, 0
	}
	return dc, 100 * weighted / float64(len(edges))
}
