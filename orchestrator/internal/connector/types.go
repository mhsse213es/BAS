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
}

// TechniqueRef is one MITRE ATT&CK technique from a threat-actor profile.
type TechniqueRef struct {
	ID     string `json:"id"`               // T1059.001
	Name   string `json:"name,omitempty"`   // PowerShell
	Tactic string `json:"tactic,omitempty"` // execution
}

// ConnectorStatus is the live state of the connector — returned by the API.
type ConnectorStatus struct {
	MISPEnabled      bool      `json:"mispEnabled"`
	OpenCTIEnabled   bool      `json:"openctiEnabled"`
	BundleEnabled    bool      `json:"bundleEnabled"`
	BundleVersion    string    `json:"bundleVersion,omitempty"`
	LastSyncAt       time.Time `json:"lastSyncAt"`
	LastSyncStatus   string    `json:"lastSyncStatus"` // "ok" | "error" | "never"
	LastError        string    `json:"lastError,omitempty"`
	ScenariosCreated int       `json:"scenariosCreated"`
	ScenariosUpdated int       `json:"scenariosUpdated"`
	TotalActors      int       `json:"totalActors"`
	NextSyncAt       time.Time `json:"nextSyncAt"`
}
