// Package connector polls MISP and OpenCTI for threat-actor TTP profiles and
// auto-generates BAS scenario YAMLs from them.
package connector

import "time"

// ThreatActor is a normalised threat-actor profile extracted from MISP or OpenCTI.
type ThreatActor struct {
	Name        string
	Aliases     []string
	Description string
	Techniques  []TechniqueRef
	Sectors     []string
	Regions     []string
	Source      string // "misp" | "opencti"
	SourceID    string // MISP event ID or OpenCTI object ID
	LastSeen    time.Time
	Confidence  string // "high" | "medium" | "low"
}

// TechniqueRef is one MITRE ATT&CK technique from a threat-actor profile.
type TechniqueRef struct {
	ID     string // T1059.001
	Name   string // PowerShell
	Tactic string // execution
}

// ConnectorStatus is the live state of the connector — returned by the API.
type ConnectorStatus struct {
	MISPEnabled      bool      `json:"mispEnabled"`
	OpenCTIEnabled   bool      `json:"openctiEnabled"`
	LastSyncAt       time.Time `json:"lastSyncAt"`
	LastSyncStatus   string    `json:"lastSyncStatus"` // "ok" | "error" | "never"
	LastError        string    `json:"lastError,omitempty"`
	ScenariosCreated int       `json:"scenariosCreated"`
	ScenariosUpdated int       `json:"scenariosUpdated"`
	TotalActors      int       `json:"totalActors"`
	NextSyncAt       time.Time `json:"nextSyncAt"`
}
