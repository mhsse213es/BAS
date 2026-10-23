// Package dbsim holds the orchestrator side of database security simulation.
// This file mirrors the agent wire types (agent/protocol/dbprobe.go); the
// orchestrator never imports agent code. The two are tied by an identical
// golden JSON vector in each module (testdata/dbprobe_spec.golden.json).
package dbsim

import "time"

type ExecMode string

const (
	ModeLab    ExecMode = "lab"
	ModeClient ExecMode = "client"
)

type Limits struct {
	MaxRows    int `json:"maxRows"`
	TimeoutSec int `json:"timeoutSec"`
	MaxConns   int `json:"maxConns"`
}

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
	Mode             ExecMode          `json:"mode"`
	Limits           Limits            `json:"limits"`
	Params           map[string]string `json:"params,omitempty"`
}

type DBProbeResult struct {
	Denied     bool      `json:"denied"`
	RowsRead   int       `json:"rowsRead"`
	ErrorClass string    `json:"errorClass,omitempty"`
	DBTime     time.Time `json:"dbTime"`
	AgentTime  time.Time `json:"agentTime"`
	Notes      []string  `json:"notes,omitempty"`
}

type ProbeClass string

const (
	ClassReadOnly         ProbeClass = "read_only"
	ClassBoundedSynthetic ProbeClass = "bounded_synthetic"
	ClassMutation         ProbeClass = "mutation"
)

// ProbeRegistryEntry is the orchestrator's data-only view of an agent probe.
type ProbeRegistryEntry struct {
	ID          string
	Class       ProbeClass
	Engines     []string
	ParamSchema map[string]string // param name -> kind ("string"|"int"|"bool")
}

var probeRegistry = map[string]ProbeRegistryEntry{
	"read_roles":            {ID: "read_roles", Class: ClassReadOnly, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}},
	"read_grants":           {ID: "read_grants", Class: ClassReadOnly, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{"role": "string"}},
	"auth_check":            {ID: "auth_check", Class: ClassReadOnly, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}},
	"read_restricted_table": {ID: "read_restricted_table", Class: ClassReadOnly, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{"table": "string"}},
}

// LookupProbeEntry returns the registry entry for a probe id.
func LookupProbeEntry(id string) (ProbeRegistryEntry, bool) {
	e, ok := probeRegistry[id]
	return e, ok
}
