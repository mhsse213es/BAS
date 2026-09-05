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
	// Termination records HOW a step ended when the agent itself ended it, and
	// what it was doing at that instant. Nil for a step that exited on its own,
	// and nil from agents predating the field -- readers must treat nil as "not
	// reported", never as "no output". A pooled step (Windows warm-host path)
	// that times out gets a partial record: Reason and ElapsedMs are real, but
	// OutputBytes and SilenceMs are always 0 -- the pooled protocol has no live
	// buffer to measure them from once a response never arrives. Do not read a
	// pooled termination's OutputBytes==0/SilenceMs==0 as "produced no output"
	// or "fully silent"; it means "not measurable here", same spirit as nil.
	Termination *StepTermination `json:"termination,omitempty"`
}

// Termination reasons. Single-valued, in this precedence order: the execute
// deadline is why WE killed the step, so it outranks a cancel that arrived in
// the same instant, and both outrank the pipe-abandonment backstop.
const (
	TermExecutionTimeout = "execution_timeout"  // our own execute deadline fired
	TermScenarioCancel   = "scenario_cancelled" // operator Stop / run abort / agent shutdown
	TermPipesAbandoned   = "pipes_abandoned"    // cmd.WaitDelay elapsed; a descendant held the pipes
)

// StepTermination is structured evidence about an agent-terminated step, kept
// separate from the human-readable error text so analysis never has to parse a
// sentence.
//
// It deliberately carries measurements only. The execute deadline is pure
// wall-clock and cannot tell a slow-but-working step from a wedged one; these
// fields do not resolve that either. A step still writing when it was killed
// suggests its timeout is too tight; one silent for the whole window suggests
// it was stuck. Both are suggestions. Nothing here feeds scoring -- a
// terminated step stays ERROR and stays excluded from the score, exactly as
// before.
type StepTermination struct {
	// Reason is one of the Term* constants above.
	Reason string `json:"reason"`
	// ElapsedMs is how long the step ran before it was terminated.
	ElapsedMs int64 `json:"elapsedMs"`
	// OutputBytes is stdout and stderr combined, counting bytes discarded past
	// the retention cap as well as those kept.
	OutputBytes int64 `json:"outputBytes"`
	// SilenceMs is how long the step had been producing nothing when it was
	// terminated. Equal to ElapsedMs when it never wrote at all.
	SilenceMs int64 `json:"silenceMs"`
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
