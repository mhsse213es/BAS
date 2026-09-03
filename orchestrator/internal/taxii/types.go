package taxii

import "time"

// ConnectorConfig is one configured TAXII 2.1 server (e.g. FS-ISAC). Unlike
// threat_intel_config's one-row-per-connector-TYPE singleton, this is
// genuinely multi-instance.
type ConnectorConfig struct {
	ID              string
	Name            string
	ServerURL       string
	APIRoot         string // resolved from Discover() on first sync if left blank
	CollectionID    string
	AuthType        string // "none" | "basic"
	Username        string
	Password        string // plaintext at rest, matching threat_intel_config.api_key's precedent
	ClientCert      string // reserved, unused Phase 1
	ClientKey       string // reserved, unused Phase 1
	InsecureTLS     bool   // skip TLS verification (self-signed on-prem TAXII servers)
	Enabled         bool
	LastPollAt      *time.Time
	LastPollStatus  string // "never" | "ok" | "error"
	LastPollSummary PollSummary
	LastError       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// PollSummary is one sync cycle's outcome counts.
type PollSummary struct {
	Processed int `json:"processed"` // indicator SDOs successfully written/updated
	Skipped   int `json:"skipped"`   // recognized-but-unsupported (composite pattern, non-indicator SDO type)
	Malformed int `json:"malformed"` // failed to parse as valid STIX
}
