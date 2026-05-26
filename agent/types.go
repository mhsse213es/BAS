package main

import (
	"encoding/json"
	"time"
)

// ── Wire Protocol ─────────────────────────────────────────────────────────────

type Heartbeat struct {
	AgentID   string `json:"agentId"`
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ipAddress"`
	OSVersion string `json:"osVersion"`
	Username  string `json:"username"`
	Status    string `json:"status"`
	EnvLabel  string `json:"envLabel"`
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
}

type RawRunResult struct {
	RunID      string       `json:"runId"`
	ScenarioID string       `json:"scenarioId"`
	AgentID    string       `json:"agentId"`
	Results    []ExecResult `json:"results"`
	Partial    bool         `json:"partial,omitempty"`
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
