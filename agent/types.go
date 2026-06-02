package main

import (
	"encoding/json"
	"time"
)

// ── Wire Protocol ─────────────────────────────────────────────────────────────

type Heartbeat struct {
	AgentID    string `json:"agentId"`
	Hostname   string `json:"hostname"`
	IPAddress  string `json:"ipAddress"`
	OSVersion  string `json:"osVersion"`
	Username   string `json:"username"`
	Status     string `json:"status"`
	EnvLabel   string `json:"envLabel"`
	BinaryHash string `json:"binaryHash,omitempty"`
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
}
