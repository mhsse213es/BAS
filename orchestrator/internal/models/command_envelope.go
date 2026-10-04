package models

import (
	"encoding/json"
	"time"
)

// CommandEnvelope wraps every execution-triggering WS command dispatched
// to an agent (see the 8 command types this covers in
// docs/superpowers/specs/2026-09-28-command-envelope-signing-design.md).
// It is signed by internal/cmdsigning's deployment command-signing key --
// a wholly separate trust domain from both the mTLS deployment CA
// (internal/pki) and the offline vendor scenario-signing key
// (internal/integrity), per that spec's "Two independent cryptographic
// domains" section. Never touch either of those from code that also
// touches this type.
type CommandEnvelope struct {
	Version     int             `json:"version"`
	CommandID   string          `json:"commandId"`
	CommandType string          `json:"commandType"`
	AgentID     string          `json:"agentId"`
	RunID       string          `json:"runId,omitempty"`
	ScenarioID  string          `json:"scenarioId,omitempty"`
	StepID      string          `json:"stepId,omitempty"`
	Mode        string          `json:"mode,omitempty"`
	Policy      json.RawMessage `json:"policy,omitempty"`
	IssuedAt    time.Time       `json:"issuedAt"`
	ExpiresAt   time.Time       `json:"expiresAt"`
	Nonce       string          `json:"nonce"`
	Payload     json.RawMessage `json:"payload"`
	// ExecutionClass/DestructiveAction/BlastRadius are the AGGREGATE
	// (most-restrictive-across-Steps) classification, for dispatch-level
	// audit visibility only -- see docs/superpowers/specs/
	// 2026-09-29-destructive-action-guardrail-b5-design.md. NEVER the
	// authorization signal: the agent's B5 gate reads each ScenarioStep's
	// own ExecutionClass (agent/protocol.ScenarioStep, Task 2), not this
	// field.
	ExecutionClass    string `json:"executionClass,omitempty"`
	DestructiveAction string `json:"destructiveAction,omitempty"`
	BlastRadius       string `json:"blastRadius,omitempty"`
	Signature         []byte `json:"signature,omitempty"`
}

// CommandEnvelopeVersion is the current envelope wire-format version.
// Verifiers reject any envelope whose Version doesn't match a version
// they understand -- see the agent-side verification checklist.
const CommandEnvelopeVersion = 1

// CanonicalJSON returns the exact byte sequence internal/cmdsigning signs
// and the agent verifies: json.Marshal of every field except Signature.
// A fixed struct (never a map[string]any) makes Go's deterministic
// per-type field ordering the canonical form -- no separate
// canonicalization scheme (JCS etc.) is needed. Signature is excluded
// because the anonymous struct below has no Signature field (not by tag
// tricks), so this stays correct even if CommandEnvelope's fields are ever
// reordered.
func (e CommandEnvelope) CanonicalJSON() ([]byte, error) {
	unsigned := e
	return json.Marshal(struct {
		Version           int             `json:"version"`
		CommandID         string          `json:"commandId"`
		CommandType       string          `json:"commandType"`
		AgentID           string          `json:"agentId"`
		RunID             string          `json:"runId,omitempty"`
		ScenarioID        string          `json:"scenarioId,omitempty"`
		StepID            string          `json:"stepId,omitempty"`
		Mode              string          `json:"mode,omitempty"`
		Policy            json.RawMessage `json:"policy,omitempty"`
		IssuedAt          time.Time       `json:"issuedAt"`
		ExpiresAt         time.Time       `json:"expiresAt"`
		Nonce             string          `json:"nonce"`
		Payload           json.RawMessage `json:"payload"`
		ExecutionClass    string          `json:"executionClass,omitempty"`
		DestructiveAction string          `json:"destructiveAction,omitempty"`
		BlastRadius       string          `json:"blastRadius,omitempty"`
	}{
		Version: unsigned.Version, CommandID: unsigned.CommandID, CommandType: unsigned.CommandType,
		AgentID: unsigned.AgentID, RunID: unsigned.RunID, ScenarioID: unsigned.ScenarioID,
		StepID: unsigned.StepID, Mode: unsigned.Mode, Policy: unsigned.Policy,
		IssuedAt: unsigned.IssuedAt, ExpiresAt: unsigned.ExpiresAt, Nonce: unsigned.Nonce,
		Payload:        unsigned.Payload,
		ExecutionClass: unsigned.ExecutionClass, DestructiveAction: unsigned.DestructiveAction,
		BlastRadius: unsigned.BlastRadius,
	})
}

// SignedCommandTypes is the exact, closed set of WS message types this
// envelope mechanism covers. Anything outside this set is neither signed
// by the orchestrator nor accepted (even unsigned) by an agent that
// checks IsSignedCommandType before dispatch -- see the agent-side
// verification checklist's hard rule that an unrecognized type is
// rejected before signature verification is even attempted.
var SignedCommandTypes = map[string]bool{
	"command_scenario":           true,
	"command_simulate":           true,
	"command_attackpath_collect": true,
	"command_cancel":             true,
	"command_pause":              true,
	"command_resume":             true,
	"command_stop_agent":         true,
	"command_uninstall_agent":    true,
}

// IsSignedCommandType reports whether msgType is one of the 8 command
// types this envelope mechanism covers.
func IsSignedCommandType(msgType string) bool {
	return SignedCommandTypes[msgType]
}
