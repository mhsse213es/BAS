// Package threatgraph assembles a read-only, graph-shaped view of
// threat-intelligence relationships that already exist across
// threat_actor_profiles, internal/intelligence's Campaign/Malware/Tool
// tables, and the bundled attackdata.GroupTechniqueIndex() -- no new
// storage, nothing to keep in sync. Kept fully separate from
// internal/attackpath, which models a different domain (network
// lateral-movement paths, not threat-intel relationships) despite both
// using Node/Edge vocabulary. See
// docs/superpowers/specs/2026-07-29-knowledge-graph-design.md.
package threatgraph

// Node is one entity in the graph -- an actor, campaign, malware family,
// tool, technique, sector, or region.
type Node struct {
	ID    string `json:"id"` // "<type>:<key>" -- e.g. "actor:apt29", "technique:T1059.001"
	Type  string `json:"type"`
	Label string `json:"label"`
}

// Edge is one directed, labelled relationship between two Nodes. Direction
// is always canonical (e.g. always From: actor, To: technique for a "uses"
// edge) regardless of which node a query started from.
type Edge struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Relationship string `json:"relationship"` // "uses" | "attributed_to" | "targets" | "used_in"
}

// Neighborhood is one center node plus everything directly (1-hop)
// connected to it. Center is always Nodes[0] when the center itself
// exists; Nodes/Edges are both empty (never nil) when the requested ID
// doesn't exist -- callers/JSON encoders shouldn't need a nil guard, same
// convention internal/intelligence.ListCampaigns already uses.
type Neighborhood struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

const (
	NodeTypeActor     = "actor"
	NodeTypeCampaign  = "campaign"
	NodeTypeMalware   = "malware"
	NodeTypeTool      = "tool"
	NodeTypeTechnique = "technique"
	NodeTypeSector    = "sector"
	NodeTypeRegion    = "region"
	NodeTypeIOC       = "ioc"
	NodeTypeScenario  = "scenario"
	NodeTypeRun       = "run"
	NodeTypeAgent     = "agent"
)
