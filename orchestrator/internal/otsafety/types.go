package otsafety

import "time"

const (
	// TierOT is the single sensitivity tier for this increment --
	// deliberately not a broader taxonomy until a real need for finer
	// granularity appears.
	TierOT = "ot"

	MaxSensitiveZonesPerImport   = 500
	MaxRequiredTransitsPerImport = 500
)

// SensitiveZone declares that a networktopology zone (referenced by
// name only, never cross-validated against a real
// networktopology.TopologyImport) requires the stricter active-testing
// safeguards of CheckActiveTestAuthorization (authz.go). Tier is
// currently always TierOT; the field exists so a future increment can
// add tiers without a breaking schema change.
type SensitiveZone struct {
	ZoneName string `json:"zoneName"`
	Tier     string `json:"tier"` // TierOT
	Note     string `json:"note,omitempty"`
}

// RequiredTransit declares that any path between FromZone and ToZone,
// in either direction, must visit ViaZone -- e.g. "any path between
// the corporate zone and the OT zone must pass through the DMZ zone."
// This is a declared-architecture constraint, validated against
// whatever the route search actually finds (transit.go), never baked
// into the routing graph itself. Structurally identical to
// remoteaccess.MandatoryTransit, re-implemented fresh here rather than
// imported -- internal/otsafety and internal/remoteaccess never import
// each other.
type RequiredTransit struct {
	CanonicalID string `json:"canonicalId"`
	FromZone    string `json:"fromZone"`
	ToZone      string `json:"toZone"`
	ViaZone     string `json:"viaZone"`
	Note        string `json:"note,omitempty"`
}

// OTSafetyImport is one auditable, versioned snapshot -- the same
// shape discipline as remoteaccess.RemoteAccessImport /
// networktopology.TopologyImport.
type OTSafetyImport struct {
	ID               string            `json:"id,omitempty"`
	SourceType       string            `json:"sourceType"`
	ImportedBy       string            `json:"importedBy,omitempty"`
	ImportedAt       time.Time         `json:"importedAt,omitempty"`
	ConfigVersion    string            `json:"configVersion,omitempty"`
	SensitiveZones   []SensitiveZone   `json:"sensitiveZones"`
	RequiredTransits []RequiredTransit `json:"requiredTransits,omitempty"`
	Limitations      []string          `json:"limitations,omitempty"`
}
