// Package intelligence holds Campaign and Malware -- the two entities the
// Intelligence Expansion project adds. Everything else in the originally
// envisioned "Intelligence Repository" (Actors, IOCs, CVEs) already has a
// home elsewhere (threat_actor_profiles, internal/ioc's ioc_enrichment
// table, the CVE Relationship Store) -- see
// docs/superpowers/specs/2026-07-28-intelligence-expansion-design.md's
// Problem section for why this package doesn't duplicate those.
//
// No relationship/join tables here -- Campaign/Malware carry denormalized
// []string ID-list fields and get normalized only in a future phase, once
// more than one provider contributes overlapping data.
package intelligence

import (
	"strings"
	"time"
)

// SourceRef is provenance metadata carried by every Campaign/Malware
// record. Exists from day one so a future multi-provider reconciliation
// phase has a mechanism already in place rather than requiring a schema
// redesign when other providers start contributing the same entities.
type SourceRef struct {
	Provider    string    `json:"provider"`   // "misp" (only value today)
	ExternalID  string    `json:"externalId"` // MISP event ID (Campaign) / galaxy cluster value (Malware)
	LastUpdated time.Time `json:"lastUpdated"`
	// Confidence uses the same "high"|"medium"|"low"|"" convention as
	// connector.ThreatActor.Confidence and threatpriority.ConfidenceFactor
	// -- deliberately not a numeric scale, to avoid two parallel confidence
	// representations for the same concept across the codebase.
	Confidence string `json:"confidence"`
}

// Campaign is one MISP event that qualified as ATT&CK-relevant (the same
// gate connector.MISPClient already applies for actor extraction). The
// event itself is the campaign container -- MISP doesn't expose a distinct
// "campaign" galaxy type separate from its events in what this client
// parses.
type Campaign struct {
	ID             string    `json:"id"` // = Source.ExternalID for MISP (event ID, already unique)
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	ThreatActorIDs []string  `json:"threatActorIds"` // threat_actor_profiles.name values
	TechniqueIDs   []string  `json:"techniqueIds"`
	Objective      string    `json:"objective,omitempty"` // OpenCTI-only; empty for MISP-sourced campaigns
	Source         SourceRef `json:"source"`
}

// Malware is one mitre-malware GalaxyCluster entry, deduplicated by
// normalized name across every event that references it (MalwareKey).
type Malware struct {
	ID             string    `json:"id"` // = MalwareKey(Name) -- cross-event dedup key
	Name           string    `json:"name"`
	Aliases        []string  `json:"aliases"`
	TechniqueIDs   []string  `json:"techniqueIds"`
	ThreatActorIDs []string  `json:"threatActorIds"`
	CampaignIDs    []string  `json:"campaignIds"`
	MalwareTypes   []string  `json:"malwareTypes,omitempty"` // e.g. "ransomware", "trojan" -- OpenCTI-only
	Source         SourceRef `json:"source"`
}

// MalwareKey normalizes a malware name into a stable dedup key -- the same
// normalization connector.actorKey() already applies to actor names
// (lowercase, strip spaces/hyphens). Duplicated here (not exported from
// internal/connector) to keep the connector<->intelligence dependency
// strictly one-way: connector imports intelligence for types, never the
// reverse.
func MalwareKey(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}
