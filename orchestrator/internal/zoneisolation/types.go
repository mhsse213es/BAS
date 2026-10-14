package zoneisolation

import "time"

// MaxZonePairIsolationsPerImport bounds one IsolationImport, same cap
// discipline as otsafety.MaxSensitiveZonesPerImport.
const MaxZonePairIsolationsPerImport = 500

// ZonePairIsolation declares that ZoneA and ZoneB (referenced by name
// only, never cross-validated against a real networktopology import --
// same discipline as otsafety.SensitiveZone/RequiredTransit) are
// expected to have no network path between them at all, in either
// direction.
type ZonePairIsolation struct {
	CanonicalID string `json:"canonicalId"`
	ZoneA       string `json:"zoneA"`
	ZoneB       string `json:"zoneB"`
	Note        string `json:"note,omitempty"`
}

// IsolationImport is one auditable, versioned snapshot -- the same
// shape discipline as otsafety.OTSafetyImport / remoteaccess.RemoteAccessImport.
type IsolationImport struct {
	ID                 string              `json:"id,omitempty"`
	SourceType         string              `json:"sourceType"`
	ImportedBy         string              `json:"importedBy,omitempty"`
	ImportedAt         time.Time           `json:"importedAt,omitempty"`
	ConfigVersion      string              `json:"configVersion,omitempty"`
	ZonePairIsolations []ZonePairIsolation `json:"zonePairIsolations"`
	Limitations        []string            `json:"limitations,omitempty"`
}
