package main

import (
	"encoding/json"
	"time"

	"audspect/agent/sched"
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

	SecurityProducts []string `json:"securityProducts,omitempty"` // installed AV/EDR inventory (presence only)

	// Attack-path job progress — only set when actively running a collection job.
	CurrentJobID string               `json:"currentJobId,omitempty"`
	JobProgress  HeartbeatJobProgress `json:"jobProgress,omitempty"`
}

// HeartbeatJobProgress carries per-job collection progress in a heartbeat.
type HeartbeatJobProgress struct {
	Stage            string `json:"stage"`
	TargetsCompleted int    `json:"targetsCompleted"`
	TargetsTotal     int    `json:"targetsTotal"`
	ProgressPercent  int    `json:"progressPercent"` // 0–100, pre-computed
}

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

	// PostureCatalog maps each local-check scenarioId to its selectable checks.
	PostureCatalog map[string][]PostureCheckMeta `json:"postureCatalog,omitempty"`
}

// PostureCheckMeta is one selectable posture check (no result — catalog only).
type PostureCheckMeta struct {
	ID          string `json:"id"`
	Phase       string `json:"phase"`
	TechniqueID string `json:"techniqueId"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
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
	// PreventScreenTimeout, when true, holds a display/system wake lock for the
	// entire run via SetThreadExecutionState. Opt-in per scenario only — never
	// applied globally so enterprise idle/lock policies are respected by default.
	PreventScreenTimeout bool `json:"preventScreenTimeout,omitempty"`
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
	// RequiresPriv is the privilege tier the server tagged this step with.
	// "" or "user" → run as the logged-in interactive user (WTS token).
	// "admin" / "system" → run in the agent's own elevated context.
	RequiresPriv string `json:"requiresPriv,omitempty"`
}

type ExecResult struct {
	TaskID        string    `json:"taskId"`
	PID           int       `json:"pid,omitempty"`
	StartedAt     time.Time `json:"startedAt,omitempty"`
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
	// CleanupVerdict records whether the step's cleanup command restored the host.
	// "reverted" = cleanup ran and exited 0; "partial" = non-zero exit;
	// "leaked" = cleanup timed out or failed to start; "" = no cleanup defined.
	CleanupVerdict string `json:"cleanupVerdict,omitempty"`
	// RequestedPriv is the requires_priv value from the scenario step as declared
	// by the scenario author. Empty means the step was unannotated (legacy).
	RequestedPriv string `json:"requestedPriv,omitempty"`
	// ExecutedAs records the actual privilege context the step ran under:
	//   "user"       → ran as the logged-in interactive user (WTS token)
	//   "user→admin" → requires_priv=user but no session found; ran as agent
	//   "admin"      → ran in the agent's elevated context
	//   "system"     → ran as NT AUTHORITY\SYSTEM
	//   ""           → unannotated step, ran in agent's own context (legacy)
	ExecutedAs string `json:"executedAs,omitempty"`
}

// AlertRecord is one raw defensive event collected from the endpoint. The agent
// fills every field it can extract; the SERVER interprets them (verdict,
// confidence). The agent never classifies. Mirrored server-side in internal/detect.
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
