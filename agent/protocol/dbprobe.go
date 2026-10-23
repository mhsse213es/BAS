package protocol

import "time"

// DBExecMode selects where a database probe may run. Mirrored (not
// imported) by orchestrator/internal/dbsim/wire.go; the two are tied by
// testdata/dbprobe_spec.golden.json.
type DBExecMode string

const (
	DBModeLab    DBExecMode = "lab"
	DBModeClient DBExecMode = "client"
)

// DBProbeLimits bounds a single probe execution.
type DBProbeLimits struct {
	MaxRows    int `json:"maxRows"`
	TimeoutSec int `json:"timeoutSec"`
	MaxConns   int `json:"maxConns"`
}

// DBProbeSpec is the wire form of one named database probe. It carries a
// credential REFERENCE only, never a secret, and never free-form SQL.
type DBProbeSpec struct {
	Engine   string `json:"engine"`
	ProbeID  string `json:"probeId"`
	TargetID string `json:"targetId"`
	// Connection target. Host/Port/Database/TLSMode say where to connect;
	// ExpectedIdentity is the pre-registered PG system_identifier / MySQL
	// server_uuid the agent gate compares against the observed identity.
	// None of these is a secret (credentials stay a CredentialRef).
	Host             string            `json:"host"`
	Port             int               `json:"port"`
	Database         string            `json:"database,omitempty"`
	TLSMode          string            `json:"tlsMode,omitempty"`
	ExpectedIdentity string            `json:"expectedIdentity"`
	CredentialRef    string            `json:"credentialRef"`
	RunID            string            `json:"runId"`
	Marker           string            `json:"marker"`
	FixtureID        string            `json:"fixtureId,omitempty"`
	Mode             DBExecMode        `json:"mode"`
	Limits           DBProbeLimits     `json:"limits"`
	Params           map[string]string `json:"params,omitempty"`
}

// DBProbeResult is the typed observation returned by a probe. The agent
// never scores; the orchestrator derives verdicts from this.
type DBProbeResult struct {
	Denied     bool      `json:"denied"`
	RowsRead   int       `json:"rowsRead"`
	ErrorClass string    `json:"errorClass,omitempty"`
	DBTime     time.Time `json:"dbTime"`
	AgentTime  time.Time `json:"agentTime"`
	Notes      []string  `json:"notes,omitempty"`
}
