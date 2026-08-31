package protocol

import (
	"encoding/json"
	"time"
)

// SchemaVersion is bumped whenever the wire protocol changes in a breaking way.
const SchemaVersion = 1

// ProtocolVersion advertises the agent's run-protocol capabilities to the server.
// 2 = emits run-event stream (Phase B-1).
const ProtocolVersion = 2

// Execution stage constants — must match server-side APStage* constants.
const (
	APStageInitializing        = "initializing"
	APStageProbing             = "probing"
	APStageEnumeratingAdmins   = "enumerating_admins"
	APStageEnumeratingSessions = "enumerating_sessions"
	APStageRunningSharpHound   = "running_sharphound"
	APStageBuildingGraph       = "building_graph"
	APStageUploading           = "uploading"
)

// PolicyConf carries server-side policy down to the agent on enroll + heartbeat.
type PolicyConf struct {
	LogLevel          string   `json:"logLevel"`
	AllowedScenarios  []string `json:"allowedScenarios"`
	ExecutionWindow   string   `json:"executionWindow"`
	MaxConcurrentRuns int      `json:"maxConcurrentRuns"`
	HeartbeatInterval int      `json:"heartbeatIntervalS"`
}

// LivePolicy mirrors the server-side guardrails the agent must honour for live runs.
type LivePolicy struct {
	BlockOnDomainController bool     `json:"blockOnDomainController,omitempty"`
	RequireDCReachable      bool     `json:"requireDcReachable,omitempty"`
	MaxSprayAttempts        int      `json:"maxSprayAttempts,omitempty"`
	SprayAccountAllowlist   []string `json:"sprayAccountAllowlist,omitempty"`
	ExecutionWindow         string   `json:"executionWindow,omitempty"`
}

type WSMessage struct {
	Type    string          `json:"type"`
	AgentID string          `json:"agentId,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type ScenarioCommand struct {
	RunID                string         `json:"runId"`
	ScenarioID           string         `json:"scenarioId"`
	Name                 string         `json:"name"`
	Steps                []ScenarioStep `json:"steps"`
	Mode                 string         `json:"mode,omitempty"`
	Policy               *LivePolicy    `json:"policy,omitempty"`
	Workers              int            `json:"workers,omitempty"`
	PreventScreenTimeout bool           `json:"preventScreenTimeout,omitempty"`
	SweepID              string         `json:"sweepId,omitempty"`
	SweepName            string         `json:"sweepName,omitempty"`
	SweepLabel           string         `json:"sweepLabel,omitempty"`
	SweepFinal           bool           `json:"sweepFinal,omitempty"`
}

// ScenarioStep's Resource/Timeout fields reference internal scheduling types
// (audspect/agent/sched) that stay agent-side. To avoid agent/protocol
// depending on agent-only internals, both fields are carried as opaque
// json.RawMessage here -- the real agent decodes them into its own
// sched.ResourceProfile/sched.TimeoutProfile after receiving a
// ScenarioCommand; loadgen has no reason to decode them at all (it never
// schedules real execution).
type ScenarioStep struct {
	TaskID               string            `json:"taskId"`
	TechniqueID          string            `json:"techniqueId"`
	Name                 string            `json:"name"`
	Executor             string            `json:"executor"`
	Command              string            `json:"command"`
	TimeoutSec           int               `json:"timeoutSec"`
	Payloads             []Payload         `json:"payloads,omitempty"`
	Cleanup              string            `json:"cleanup,omitempty"`
	PayloadDir           string            `json:"-"`
	Resource             json.RawMessage   `json:"resource,omitempty"`
	Timeout              json.RawMessage   `json:"timeout,omitempty"`
	Env                  map[string]string `json:"-"`
	RequiresPriv         string            `json:"requiresPriv,omitempty"`
}

type Payload struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type ExecResult struct {
	TaskID          string    `json:"taskId"`
	PID             int       `json:"pid,omitempty"`
	StartedAt       time.Time `json:"startedAt,omitempty"`
	ExitCode        int       `json:"exitCode"`
	Stdout          string    `json:"stdout"`
	Stderr          string    `json:"stderr"`
	DurationMs      int64     `json:"durationMs"`
	ExecutedAt      time.Time `json:"executedAt"`
	Events          []string  `json:"events,omitempty"`
	Blocked         bool      `json:"blocked,omitempty"`
	BlockedReason   string    `json:"blockedReason,omitempty"`
	TimedOut        bool      `json:"timedOut,omitempty"`
	CleanupVerdict  string    `json:"cleanupVerdict,omitempty"`
	CleanupResidual []string  `json:"cleanupResidual,omitempty"`
	RequestedPriv   string    `json:"requestedPriv,omitempty"`
	ExecutedAs      string    `json:"executedAs,omitempty"`
}

// SimCheckResult carries the pre-interpreted result of a single built-in
// local check.
type SimCheckResult struct {
	ID            string    `json:"id"`
	TechniqueID   string    `json:"techniqueId"`
	TechniqueName string    `json:"techniqueName"`
	Tactic        string    `json:"tactic"`
	Result        string    `json:"result"`
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
	Checks     []SimCheckResult `json:"checks,omitempty"`
	Partial    bool             `json:"partial,omitempty"`
	Reverted   []string         `json:"reverted,omitempty"`
}

// AlertRecord is one raw defensive event collected from the endpoint.
type AlertRecord struct {
	Channel     string    `json:"channel"`
	Provider    string    `json:"provider"`
	EventID     int       `json:"eventId"`
	Level       string    `json:"level"`
	Timestamp   time.Time `json:"timestamp"`
	ThreatName  string    `json:"threatName,omitempty"`
	ProcessName string    `json:"processName,omitempty"`
	ProcessPath string    `json:"processPath,omitempty"`
	CommandLine string    `json:"commandLine,omitempty"`
	User        string    `json:"user,omitempty"`
	Message     string    `json:"message,omitempty"`
}

// RunDetections is the agent's post-result detection submission for one run.
type RunDetections struct {
	RunID      string        `json:"runId"`
	AgentID    string        `json:"agentId"`
	Alerts     []AlertRecord `json:"alerts"`
	WindowFrom time.Time     `json:"windowFrom"`
	WindowTo   time.Time     `json:"windowTo"`
	Truncated  bool          `json:"truncated"`
}
