// Package networktopology models a declared, auditable Layer 3
// zone-adjacency (routing) topology, kept structurally independent of
// internal/networkpolicy's firewall-rule evaluation -- a route existing
// and a policy permitting traffic are two separate evidence questions.
// It never imports internal/networkpolicy, internal/networkgraph, or
// internal/attackpath; internal/networkpath is the one place all of
// those evidence sources are combined.
package networktopology

import "time"

// Zone is a named network segment, resolved to one or more CIDRs. Same
// shape as networkpolicy.Zone, but its own type -- networktopology and
// networkpolicy correlate only by matching Name strings at evaluation
// time (internal/networkpath), never a shared struct or foreign key.
type Zone struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

// RouteEdge is one declared L3 adjacency between two zones. Directed
// false means the edge is usable in either direction (the common case
// for a routed network); Directed true models a one-way route
// explicitly, never assumed.
type RouteEdge struct {
	FromZone string `json:"fromZone"`
	ToZone   string `json:"toZone"`
	Directed bool   `json:"directed,omitempty"`
	Note     string `json:"note,omitempty"`
}

// TopologyImport is one auditable, versioned routing-topology snapshot
// -- the same shape discipline as networkpolicy.PolicyImport.
// Limitations carries honest gaps (asymmetric routing, NAT,
// policy-based routing, dynamic convergence) rather than silently
// omitting them.
type TopologyImport struct {
	ID            string      `json:"id,omitempty"`
	SourceType    string      `json:"sourceType"`
	ImportedBy    string      `json:"importedBy,omitempty"`
	ImportedAt    time.Time   `json:"importedAt,omitempty"`
	ConfigVersion string      `json:"configVersion,omitempty"`
	Zones         []Zone      `json:"zones"`
	Edges         []RouteEdge `json:"edges"`
	Limitations   []string    `json:"limitations,omitempty"`
}
