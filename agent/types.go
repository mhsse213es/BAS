package main

import (
	"encoding/json"
	"time"

	"github.com/audspect/bas-agent/sched"
)

// ── Wire Protocol ─────────────────────────────────────────────────────────────

// schemaVersion is bumped whenever the wire protocol changes in a breaking way.
const schemaVersion = 1

// protocolVersion advertises the agent's run-protocol capabilities to the server.
// 2 = emits run-event stream (Phase B-1).
const protocolVersion = 2

type Heartbeat struct {
	AgentID       string `json:"agentId"`
	Hostname      string `json:"hostname"`
	IPAddress     string `json:"ipAddress"`
	OSVersion     string `json:"osVersion"`
	Username      string `json:"username"`
	Status        string `json:"status"`
	EnvLabel      string `json:"envLabel"`
	BinaryHash    string `json:"binaryHash,omitempty"`
	AgentVersion  string `json:"agentVersion,omitempty"`
	SchemaVersion int    `json:"schemaVersion,omitempty"`

	ProtocolVersion int  `json:"protocolVersion,omitempty"`
	EmitsEvents     bool `json:"emitsEvents,omitempty"`
}

// HeartbeatResponse is returned by the server on every POST /api/heartbeat.
// The agent must act on State immediately: quarantined agents must not run scenarios.
type HeartbeatResponse struct {
	State  string     `json:"state"`
	Policy PolicyConf `json:"policy"`
}

// PolicyConf carries server-side policy down to the agent on enroll + heartbeat.
type PolicyConf struct {
	LogLevel          string   `json:"logLevel"`
	AllowedScenarios  []string `json:"allowedScenarios"`
	ExecutionWindow   string   `json:"executionWindow"`
	MaxConcurrentRuns int      `json:"maxConcurrentRuns"`
	HeartbeatInterval int      `json:"heartbeatIntervalS"`
}

// EnrollRequest is sent by the agent on first contact with the server.
type EnrollRequest struct {
	AgentID      string `json:"agentId"`
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ipAddress"`
	OSVersion    string `json:"osVersion"`
	Username     string `json:"username"`
	EnvLabel     string `json:"envLabel"`
	BinaryHash   string `json:"binaryHash,omitempty"`
	AgentVersion string `json:"agentVersion,omitempty"`
}

// EnrollResponse is returned by POST /api/agents/enroll.
type EnrollResponse struct {
	AgentID string     `json:"agentId"`
	State   string     `json:"state"`
	Policy  PolicyConf `json:"policy"`
	Trusted bool       `json:"trusted"`
}

type WSMessage struct {
	Type    string          `json:"type"`
	AgentID string          `json:"agentId,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type ScenarioCommand struct {
	RunID      string         `json:"runId"`
	ScenarioID string         `json:"scenarioId"`
	Name       string         `json:"name"`
	Steps      []ScenarioStep `json:"steps"`
	Mode       string         `json:"mode,omitempty"`   // telemetry | lab (live runs)
	Policy     *LivePolicy    `json:"policy,omitempty"` // guardrails enforced by the agent
	// Workers caps concurrent step execution. 0 → the agent picks a default
	// (one per CPU, capped). Steps still run only as concurrently as their
	// resource profiles allow; unlabeled steps run serially regardless.
	Workers int `json:"workers,omitempty"`
}

// LivePolicy mirrors the server-side guardrails the agent must honour for live runs.
type LivePolicy struct {
	BlockOnDomainController bool     `json:"blockOnDomainController,omitempty"`
	RequireDCReachable      bool     `json:"requireDcReachable,omitempty"`
	MaxSprayAttempts        int      `json:"maxSprayAttempts,omitempty"`
	SprayAccountAllowlist   []string `json:"sprayAccountAllowlist,omitempty"`
	ExecutionWindow         string   `json:"executionWindow,omitempty"`
}

// SimCheckResult carries the pre-interpreted result of a single built-in
// local check — preserves all technique metadata so the orchestrator does
// not have to re-derive it from empty step definitions.
type SimCheckResult struct {
	ID            string    `json:"id"`
	TechniqueID   string    `json:"techniqueId"`
	TechniqueName string    `json:"techniqueName"`
	Tactic        string    `json:"tactic"`
	Result        string    `json:"result"` // pass | fail | skipped
	Severity      string    `json:"severity"`
	ThreatImpact  string    `json:"threatImpact"`
	Details       string    `json:"details"`
	Remediation   string    `json:"remediation"`
	Framework     string    `json:"framework"`
	DurationMs    int64     `json:"durationMs"`
	ExecutedAt    time.Time `json:"executedAt"`
}

type RawRunResult struct {
	RunID      string           `json:"runId"`
	ScenarioID string           `json:"scenarioId"`
	AgentID    string           `json:"agentId"`
	Results    []ExecResult     `json:"results"`
	Checks     []SimCheckResult `json:"checks,omitempty"` // local_check scenarios only
	Partial    bool             `json:"partial,omitempty"`
	Reverted   []string         `json:"reverted,omitempty"`
}

// ── Executor Types ────────────────────────────────────────────────────────────

type Payload struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type ScenarioStep struct {
	TaskID      string    `json:"taskId"`
	TechniqueID string    `json:"techniqueId"`
	Name        string    `json:"name"`
	Executor    string    `json:"executor"`
	Command     string    `json:"command"`
	TimeoutSec  int       `json:"timeoutSec"`
	Payloads    []Payload `json:"payloads,omitempty"`
	Cleanup     string    `json:"cleanup,omitempty"`
	PayloadDir  string    `json:"-"`
	// Resource is the step's lock profile, used by the scheduler to decide which
	// steps may run concurrently. nil → the step runs serially (always safe).
	Resource *sched.ResourceProfile `json:"resource,omitempty"`
	// Timeout bounds the step's schedule/execute/grace windows. nil or zero fields
	// fall back to engine defaults.
	Timeout *sched.TimeoutProfile `json:"timeout,omitempty"`
	// Env holds runtime-only policy variables (BAS_RUN_MODE, BAS_MAX_SPRAY_ATTEMPTS,
	// BAS_SPRAY_ALLOWLIST) injected by the runner; never wire-serialised.
	Env map[string]string `json:"-"`
}

type ExecResult struct {
	TaskID        string    `json:"taskId"`
	ExitCode      int       `json:"exitCode"`
	Stdout        string    `json:"stdout"`
	Stderr        string    `json:"stderr"`
	DurationMs    int64     `json:"durationMs"`
	ExecutedAt    time.Time `json:"executedAt"`
	Events        []string  `json:"events,omitempty"`
	Blocked       bool      `json:"blocked,omitempty"`
	BlockedReason string    `json:"blockedReason,omitempty"`
	// TimedOut marks a step that ran but exceeded its execute timeout (or hit a
	// schedule timeout before running). An explicit "ran, did not return" verdict —
	// never conflated with a clean skip or a security block.
	TimedOut bool `json:"timedOut,omitempty"`
}
