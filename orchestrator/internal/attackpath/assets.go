package attackpath

import "strings"

// AssetTag is operator-supplied metadata for a host that neither reachability
// collection nor SharpHound can know: which machine is a crown jewel, its
// network segment, or a custom tier-0 designation. Tags are keyed by HOSTNAME
// (normalized short, uppercase) rather than node ID so a tag set before
// SharpHound arrives still applies after the host is reconciled to its SID.
type AssetTag struct {
	HostKey    string `json:"hostKey"`              // hostname (any form; normalized on apply)
	Label      string `json:"label,omitempty"`      // last-seen display name (UI convenience)
	CrownJewel string `json:"crownJewel,omitempty"` // "" clears the tag; else "ERP"/"FileServer"/…
	Segment    string `json:"segment,omitempty"`
	HighValue  bool   `json:"highValue,omitempty"`

	// SP6 asset criticality — see Node's matching fields in graph.go.
	CriticalityTier string   `json:"criticalityTier,omitempty"`
	InternetFacing  bool     `json:"internetFacing,omitempty"`
	IdentityExposed bool     `json:"identityExposed,omitempty"`
	Production      bool     `json:"production,omitempty"`
	ComplianceScope []string `json:"complianceScope,omitempty"`
}

// HostKey returns the reconciliation/tagging key for a node: its short hostname,
// uppercased. SID-keyed nodes derive it from the FQDN label. Exported so the API
// can present and match tags consistently with the engine.
func HostKey(n Node) string { return hostKey(n) }

// NormalizeHostKey applies the same normalization to a raw hostname/IP string.
func NormalizeHostKey(s string) string { return strings.ToUpper(shortHost(strings.TrimSpace(s))) }

// applyAssetTags overlays operator tags onto matching host nodes. Applied after
// BuildGraph (so it runs post-reconciliation): a tag matches whichever node now
// represents that machine. A non-empty CrownJewel/Segment overrides; HighValue
// only ever promotes (never clears an AD-derived tier-0 flag).
func (g *Graph) applyAssetTags(tags []AssetTag) {
	if len(tags) == 0 {
		return
	}
	idx := map[string]AssetTag{}
	for _, t := range tags {
		if k := NormalizeHostKey(t.HostKey); k != "" {
			idx[k] = t
		}
	}
	for id, n := range g.nodes {
		if n.Kind != KindHost {
			continue
		}
		t, ok := idx[hostKey(n)]
		if !ok {
			continue
		}
		if t.CrownJewel != "" {
			n.CrownJewel = t.CrownJewel
		}
		if t.Segment != "" {
			n.Segment = t.Segment
		}
		if t.HighValue {
			n.HighValue = true
		}
		if t.CriticalityTier != "" {
			n.CriticalityTier = t.CriticalityTier
		}
		if t.InternetFacing {
			n.InternetFacing = true
		}
		if t.IdentityExposed {
			n.IdentityExposed = true
		}
		if t.Production {
			n.Production = true
		}
		if len(t.ComplianceScope) > 0 {
			n.ComplianceScope = t.ComplianceScope
		}
		g.nodes[id] = n
	}
}

// BuildAndAnalyze is the one-call pipeline the server uses: merge collections,
// reconcile identities, overlay operator asset tags, then analyze.
func BuildAndAnalyze(cols []Collection, tags []AssetTag) Summary {
	_, s := BuildGraphAndAnalyze(cols, tags)
	return s
}

// BuildGraphAndAnalyze is BuildAndAnalyze but also returns the built graph,
// for callers (internal/pathcorrelation) that need to run further graph
// queries beyond the Summary.
func BuildGraphAndAnalyze(cols []Collection, tags []AssetTag) (*Graph, Summary) {
	g := BuildGraph(cols...)
	g.applyAssetTags(tags)
	return g, g.Analyze()
}

// HostInventory is the list of host nodes in the current graph with their
// effective tags — what the asset-tagging UI renders. Tags already applied are
// reflected so the operator sees current state.
func (g *Graph) HostInventory() []AssetTag {
	var out []AssetTag
	for _, n := range g.Nodes() {
		if n.Kind != KindHost {
			continue
		}
		out = append(out, AssetTag{
			HostKey:         hostKey(n),
			Label:           n.Label,
			CrownJewel:      n.CrownJewel,
			Segment:         n.Segment,
			HighValue:       n.HighValue,
			CriticalityTier: n.CriticalityTier,
			InternetFacing:  n.InternetFacing,
			IdentityExposed: n.IdentityExposed,
			Production:      n.Production,
			ComplianceScope: n.ComplianceScope,
		})
	}
	return out
}
