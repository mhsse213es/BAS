// Package dbprobe holds the agent-side database probe types, catalog and
// spec validation. Wire types live in agent/protocol and are aliased here.
// No adapter code lives in this file (see postgres/ and mysql/ later).
package dbprobe

import (
	"time"

	"audspect/agent/protocol"
)

// Wire types (aliases so there is exactly one definition).
type (
	DBProbeSpec = protocol.DBProbeSpec
	ExecMode    = protocol.DBExecMode
	Limits      = protocol.DBProbeLimits
	ProbeResult = protocol.DBProbeResult
)

const (
	ModeLab    = protocol.DBModeLab
	ModeClient = protocol.DBModeClient
)

// ProbeClass classifies a probe's blast radius.
type ProbeClass string

const (
	ClassReadOnly         ProbeClass = "read_only"
	ClassBoundedSynthetic ProbeClass = "bounded_synthetic"
	ClassMutation         ProbeClass = "mutation"
)

// ParamKind is the declared type of a probe parameter.
type ParamKind string

const (
	ParamString ParamKind = "string"
	ParamInt    ParamKind = "int"
	ParamBool   ParamKind = "bool"
)

// ProbeDef is a catalog entry: a named operation with a parameter schema.
type ProbeDef struct {
	ID          string
	Class       ProbeClass
	ParamSchema map[string]ParamKind
	Engines     []string
}

// ConnectionConfig describes how to reach a target. Secrets are resolved
// from CredentialRef at run time and must never be logged or serialised.
type ConnectionConfig struct {
	Engine        string `json:"engine"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Database      string `json:"database"`
	CredentialRef string `json:"credentialRef"`
	TLSMode       string `json:"tlsMode,omitempty"`
	TargetID      string `json:"targetId,omitempty"` // pre-registered system_identifier / server_uuid
}

// Role is a database role/user as observed or created by a fixture.
type Role struct {
	Name      string `json:"name"`
	Login     bool   `json:"login"`
	Superuser bool   `json:"superuser,omitempty"`
}

// Grant is one privilege grant observed or applied.
type Grant struct {
	Role      string `json:"role"`
	Object    string `json:"object"`
	Privilege string `json:"privilege"`
}

// AuditQuery asks an adapter for audit events about a marker.
type AuditQuery struct {
	Marker string    `json:"marker"`
	Since  time.Time `json:"since"`
	Until  time.Time `json:"until"`
}

// AuditEvent is one audit-log record read back from the database.
type AuditEvent struct {
	Time    time.Time `json:"time"`
	User    string    `json:"user,omitempty"`
	Action  string    `json:"action,omitempty"`
	Object  string    `json:"object,omitempty"`
	Message string    `json:"message,omitempty"`
}

// Capabilities states what an adapter/target supports; anything missing
// drives a SKIPPED outcome upstream, never a pass.
type Capabilities struct {
	ProbeIDs            []string `json:"probeIds"`
	AuditSources        []string `json:"auditSources,omitempty"`
	MarkerInQueryText   bool     `json:"markerInQueryText"`
	MarkerInAuditRecord bool     `json:"markerInAuditRecord"`
}

// FixtureSpec requests a synthetic fixture (no real PANs/customer data).
type FixtureSpec struct {
	Kind  string            `json:"kind"`
	RunID string            `json:"runId"`
	Opts  map[string]string `json:"opts,omitempty"`
}

// Fixture identifies a created fixture so it can be cleaned up.
type Fixture struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"`
	Objects []string `json:"objects,omitempty"`
}

// CleanupResult reports fixture teardown. Residual objects mean cleanup
// failed, which is a safety incident.
type CleanupResult struct {
	Removed  []string `json:"removed,omitempty"`
	Residual []string `json:"residual,omitempty"`
	Error    string   `json:"error,omitempty"`
}
