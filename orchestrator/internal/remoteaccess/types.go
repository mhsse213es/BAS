// Package remoteaccess models on-premises VPN tunnels and
// mandatory-transit (bastion) boundary rules, kept structurally
// independent of internal/networktopology's own zone/edge model --
// configured existence and operational tunnel state are two separate
// evidence questions, the same way internal/networkpolicy and
// internal/networktopology stay independent of each other despite
// both describing on-prem zones. It never modifies networktopology,
// networkpolicy, or networkpath; it imports networktopology's types
// read-only for its own route search (routes.go). internal/networkpath
// is reused directly, unmodified, for evidence composition -- see
// docs/superpowers/specs/2026-10-14-network-bas-phase6b-remote-access-design.md
// §5 for why no new composition package exists.
package remoteaccess

import "time"

const (
	TunnelUp      = "up"      // real evidence: operationally established, usable as a route edge
	TunnelDown    = "down"    // real evidence: configured but not established -- not usable, but also not proof no path exists at all
	TunnelUnknown = "unknown" // missing evidence -- never treated as usable, never treated as confirmed-down

	MaxTunnelsPerImport  = 500
	MaxTransitsPerImport = 500
)

// VPNTunnel is one logical tunnel connecting two networktopology zones
// by name. It may connect zones with no CIDR adjacency at all (e.g. a
// branch zone and a data-centre zone reachable only across the public
// internet) -- only State == TunnelUp is ever treated as a usable
// route edge, mirroring cloudtopology.PeeringConnection's exact
// discipline for peering state.
type VPNTunnel struct {
	CanonicalID string `json:"canonicalId"`
	FromZone    string `json:"fromZone"`
	ToZone      string `json:"toZone"`
	Directed    bool   `json:"directed,omitempty"`
	State       string `json:"state"` // TunnelUp | TunnelDown | TunnelUnknown
	Note        string `json:"note,omitempty"`
}

// MandatoryTransit declares that any path between FromZone and ToZone,
// in either direction, must visit ViaZone -- e.g. "any administrative
// path between the corporate zone and the production zone must pass
// through the bastion zone," enforced the same way whether the path is
// queried as corporate->production or production->corporate. This is a
// declared-architecture constraint, validated against whatever the
// route search actually finds (routes.go, transit.go) -- never baked
// into the routing graph itself, so a real bypass route that skips the
// bastion is surfaced as a violation instead of silently disappearing
// from the search.
type MandatoryTransit struct {
	CanonicalID string `json:"canonicalId"`
	FromZone    string `json:"fromZone"`
	ToZone      string `json:"toZone"`
	ViaZone     string `json:"viaZone"`
	Note        string `json:"note,omitempty"`
}

// RemoteAccessImport is one auditable, versioned snapshot -- the same
// shape discipline as networkpolicy.PolicyImport /
// networktopology.TopologyImport. Tunnels/Transits reference zone
// names declared in a separate networktopology.TopologyImport; this
// package never cross-validates those names against a real import
// (they stay independently sourced -- spec §3).
type RemoteAccessImport struct {
	ID            string             `json:"id,omitempty"`
	SourceType    string             `json:"sourceType"`
	ImportedBy    string             `json:"importedBy,omitempty"`
	ImportedAt    time.Time          `json:"importedAt,omitempty"`
	ConfigVersion string             `json:"configVersion,omitempty"`
	Tunnels       []VPNTunnel        `json:"tunnels"`
	Transits      []MandatoryTransit `json:"transits,omitempty"`
	Limitations   []string           `json:"limitations,omitempty"`
}
