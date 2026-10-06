// Package connector polls MISP and OpenCTI for threat-actor TTP profiles and
// auto-generates BAS scenario YAMLs from them.
package connector

import "time"

// ThreatActor is a normalised threat-actor profile extracted from MISP, OpenCTI,
// or an air-gapped bundle. json tags are explicit so the bundle file format is
// stable under the garble build (field-name reflection would otherwise break).
type ThreatActor struct {
	Name        string         `json:"name"`
	Aliases     []string       `json:"aliases,omitempty"`
	Description string         `json:"description,omitempty"`
	Techniques  []TechniqueRef `json:"techniques"`
	Sectors     []string       `json:"sectors,omitempty"`
	Regions     []string       `json:"regions,omitempty"`
	Source      string         `json:"source,omitempty"`    // "misp" | "opencti" | "bundle"
	SourceID    string         `json:"source_id,omitempty"` // MISP event ID or OpenCTI object ID
	LastSeen    time.Time      `json:"last_seen,omitempty"`
	Confidence  string         `json:"confidence,omitempty"` // "high" | "medium" | "low"
	// CanonicalGroupID is the resolved MITRE ATT&CK Group-ID (G####, via
	// attackdata.GroupByID), or "" if MergeActors couldn't confidently
	// resolve one. See
	// docs/superpowers/specs/2026-08-11-canonical-mitre-actor-identity-design.md.
	CanonicalGroupID string `json:"canonical_group_id,omitempty"`
}

// TechniqueRef is one MITRE ATT&CK technique from a threat-actor profile.
type TechniqueRef struct {
	ID     string `json:"id"`               // T1059.001
	Name   string `json:"name,omitempty"`   // PowerShell
	Tactic string `json:"tactic,omitempty"` // execution
}

// SourceStat is one threat-intel source's numbers from its most recent fetch.
// RawCount and ActorCount differ because MISP/OpenCTI results are filtered to
// actors with 2+ mapped ATT&CK techniques before being merged — RawCount is
// what the source returned before that filter (MISP: events; OpenCTI: raw
// threat-actor nodes), ActorCount is what passed it. The bundle source applies
// no such filter, so its RawCount and ActorCount are always equal.
type SourceStat struct {
	Name       string    `json:"name"` // "misp" | "opencti" | "bundle"
	RawCount   int       `json:"rawCount"`
	ActorCount int       `json:"actorCount"`
	FetchedAt  time.Time `json:"fetchedAt"`
	Error      string    `json:"error,omitempty"` // set instead of counts when this source's fetch failed
}

// StatsSource is implemented by sources that can report their last fetch's raw
// numbers. Checked via type assertion in Scheduler.sync (the same pattern
// already used there for *BundleSource's Version()) — sources that don't
// implement it are simply skipped, not an error.
type StatsSource interface {
	Stats() SourceStat
}

// ConnectorStatus is the live state of the connector — returned by the API.
type ConnectorStatus struct {
	MISPEnabled    bool `json:"mispEnabled"`
	OpenCTIEnabled bool `json:"openctiEnabled"`
	BundleEnabled  bool `json:"bundleEnabled"`
	// OTXEnabled reflects Scheduler.activitySources, set by
	// WithActivitySources/ReconfigureActivitySources -- tracked separately
	// from the other three because OTX is not in the sources/Reconfigure
	// list at all (it's an ActivitySource, not a Source). Previously this
	// field didn't exist, so the frontend's `s.otxEnabled` check
	// (index.html:15196) always read undefined/false regardless of actual
	// OTX config.
	OTXEnabled       bool                  `json:"otxEnabled"`
	BundleVersion    string                `json:"bundleVersion,omitempty"`
	LastSyncAt       time.Time             `json:"lastSyncAt"`
	LastSyncStatus   string                `json:"lastSyncStatus"` // "ok" | "error" | "never"
	LastError        string                `json:"lastError,omitempty"`
	ScenariosCreated int                   `json:"scenariosCreated"`
	ScenariosUpdated int                   `json:"scenariosUpdated"`
	TotalActors      int                   `json:"totalActors"`
	NextSyncAt       time.Time             `json:"nextSyncAt"`
	BySource         map[string]SourceStat `json:"bySource,omitempty"` // keyed by Source.Name()
}
