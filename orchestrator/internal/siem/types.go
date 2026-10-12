package siem

import "time"

// Provider identifies the SIEM vendor. Only qradar has a working client in
// this correlator (see queryAlerts/TestConnectivity below) -- splunk, wazuh
// and sentinel were never implemented here and are rejected at config
// creation (see api.CreateSIEMConfig), so no stray constants for them exist
// to be mistaken for support. Splunk/Sentinel/Elastic/Defender/CrowdStrike/
// Trellix detection validation lives in the separate detectverify package.
type Provider string

const (
	ProviderQRadar Provider = "qradar"
)

// Config holds the connection settings for one SIEM integration.
// Stored in siem_configs; the token/password is the only sensitive field.
type Config struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Provider Provider `json:"provider"`
	Enabled  bool     `json:"enabled"`

	// QRadar / Splunk / Sentinel: base URL of the console (https://qradar.corp:8443)
	ConsoleURL string `json:"consoleUrl"`
	// QRadar: SEC token (preferred) or username:password basic auth
	Token    string `json:"token,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Sentinel: tenant ID + workspace ID + client credentials
	TenantID     string `json:"tenantId,omitempty"`
	WorkspaceID  string `json:"workspaceId,omitempty"`
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
	// TLS: skip verification for self-signed certs (common in on-prem deployments)
	InsecureSkipVerify bool `json:"insecureSkipVerify"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// SIEMAlert is a normalised alert record returned from any supported SIEM.
type SIEMAlert struct {
	EventID     string         `json:"eventId"`
	RuleName    string         `json:"ruleName"`
	Category    string         `json:"category"`
	Severity    string         `json:"severity"`
	SourceIP    string         `json:"sourceIp"`
	DestIP      string         `json:"destIp"`
	Username    string         `json:"username"`
	ProcessName string         `json:"processName"`
	CommandLine string         `json:"commandLine"`
	Message     string         `json:"message"`
	Timestamp   time.Time      `json:"timestamp"`
	RawFields   map[string]any `json:"rawFields,omitempty"`
}

// TechniqueCorrelation is the SIEM detection verdict for one executed technique.
type TechniqueCorrelation struct {
	TechniqueID   string      `json:"techniqueId"`
	TechniqueName string      `json:"techniqueName"`
	BASVerdict    string      `json:"basVerdict"`       // pass|fail|blocked|error|skipped
	SIEMVerdict   string      `json:"siemVerdict"`      // detected|undetected|not_executed
	Alerts        []SIEMAlert `json:"alerts,omitempty"` // matching alerts (up to 5)
	AlertCount    int         `json:"alertCount"`
}

// CorrelationReport is the full SIEM correlation result for one scenario run.
type CorrelationReport struct {
	RunID       string                 `json:"runId"`
	AgentID     string                 `json:"agentId"`
	AgentIP     string                 `json:"agentIp"`
	Provider    Provider               `json:"provider"`
	ConfigID    string                 `json:"configId"`
	WindowStart time.Time              `json:"windowStart"`
	WindowEnd   time.Time              `json:"windowEnd"`
	TotalAlerts int                    `json:"totalAlerts"`
	Techniques  []TechniqueCorrelation `json:"techniques"`
	// Summary counts
	Detected    int `json:"detected"`
	Undetected  int `json:"undetected"`
	NotExecuted int `json:"notExecuted"`
	// Computed rates (over BAS-executed techniques only)
	DetectionRate  int       `json:"detectionRate"`
	UndetectedRate int       `json:"undetectedRate"`
	CorrelatedAt   time.Time `json:"correlatedAt"`
}
