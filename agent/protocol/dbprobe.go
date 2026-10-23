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
	// AuditStatus says what the audit-source readback found for this probe's
	// marker: one of the DBAudit* values. Empty means no audit attempt was
	// recorded (older agents). "unsupported" and "error" are never a pass.
	AuditStatus string `json:"auditStatus,omitempty"`
	// AuditEvents are the marker-bearing audit records (minimised: at most 50,
	// statements redacted and cut to 512 bytes).
	AuditEvents []DBProbeAuditEvent `json:"auditEvents,omitempty"`
	// CleanupStatus reports the synthetic-fixture teardown for this run: one of
	// the DBCleanup* values. Empty means an older agent (treated as not
	// applicable). SafetyIncident is true when a fixture cleanup or its
	// verification failed or left residual objects; such a result must never be
	// usable as a PASS, even if the probe itself succeeded.
	CleanupStatus  string `json:"cleanupStatus,omitempty"`
	SafetyIncident bool   `json:"safetyIncident,omitempty"`
}

// Cleanup status values (DBProbeResult.CleanupStatus). Mirrored by
// orchestrator/internal/dbsim/wire.go.
const (
	DBCleanupNotApplicable = "not_applicable" // no fixture was used
	DBCleanupOK            = "ok"             // fixture removed and verified gone
	DBCleanupResidual      = "residual"       // verification found leftover objects
	DBCleanupFailed        = "failed"         // cleanup or verification itself failed
)

// Audit status values (DBProbeResult.AuditStatus). Mirrored by
// orchestrator/internal/dbsim/wire.go.
const (
	DBAuditUnsupported = "unsupported" // no queryable audit source on this target
	DBAuditAbsent      = "absent"      // source healthy, window covered, no marker event
	DBAuditFound       = "found"       // at least one marker event, evidence complete
	DBAuditIncomplete  = "incomplete"  // window rotated/evicted or cap hit; absence proves nothing
	DBAuditError       = "error"       // collection failed; never absent
)

// DBProbeAuditEvent is one audit-source record that carried the probe marker.
type DBProbeAuditEvent struct {
	Time      time.Time `json:"time"`
	Principal string    `json:"principal,omitempty"`
	Statement string    `json:"statement"`
	Source    string    `json:"source,omitempty"`
}
