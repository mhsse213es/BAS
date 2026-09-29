package protocol

import (
	"encoding/json"
	"time"
)

// CommandEnvelope is the agent's verification-side counterpart to
// orchestrator/internal/models.CommandEnvelope -- a deliberately separate
// Go type (separate module) that must agree on wire shape, pinned by
// this package's own tests rather than a shared dependency. See
// docs/superpowers/specs/2026-09-28-command-envelope-signing-design.md.
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

// CommandEnvelopeVersion is the current envelope wire-format version this
// agent understands. Must match orchestrator's
// models.CommandEnvelopeVersion.
const CommandEnvelopeVersion = 1

// CanonicalJSON returns the exact byte sequence the orchestrator signed --
// must stay byte-for-byte identical to orchestrator/internal/models.
// CommandEnvelope.CanonicalJSON's field set and order, or every signature
// verification fails. See that function's doc comment for why a fixed
// struct needs no separate canonicalization scheme.
func (e CommandEnvelope) CanonicalJSON() ([]byte, error) {
	unsigned := e
	unsigned.Signature = nil
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

// SignedCommandTypes mirrors orchestrator/internal/models's set exactly --
// the closed list of 8 command types this envelope mechanism covers. Any
// other type is rejected before an envelope is even looked for (see
// agent/commandsig.go's verifyCommandEnvelope caller in agent.go).
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
