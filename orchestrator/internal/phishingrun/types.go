// Package phishingrun holds the lifecycle record for one real phishing
// scenario run -- mirrors internal/emailgwrun in shape (same five-state
// Status, same id/result/error/initiated_by/started_at/completed_at
// columns) deliberately, since this is the same kind of real-evidence
// BAS scenario run emailgwrun already models. It departs from
// emailgwrun by omitting the dwell-window columns
// (injected_at/window_start/window_end/verified_at): this slice's one
// registered scenario (PH-DET-002) evaluates synchronously against
// whatever evidence already exists, with no real SMTP send or
// dwell-window wait to perform. A future scenario that does need a
// real dwell window extends this struct then, the same way emailgwrun
// itself grew its own `environment` column later via
// `ALTER TABLE ADD COLUMN IF NOT EXISTS`, rather than speculatively
// building that machinery now for a scenario that doesn't need it.
package phishingrun

import (
	"encoding/json"
	"time"
)

// Status is a phishing_runs.status value, identical in values and
// meaning to emailgwrun.Status.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusPartial   Status = "partial"
)

// PhishingRun is one real execution of one registered phishing
// scenario. Result is deliberately the marshaled phishval.Outcome --
// the one unified evidence shape across every phishing evidence
// source (emailgwefficacy, phishidentity, internal/actions, and the
// EXPERIMENTAL heuristics), never a scenario-specific shape.
type PhishingRun struct {
	ID          string          `json:"id"`
	ScenarioID  string          `json:"scenarioId"`
	Status      Status          `json:"status"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
	InitiatedBy string          `json:"initiatedBy,omitempty"`
	// ExecutionID names the exercise execution this run belongs to, when the operator
	// linked it. Empty for an unlinked run.
	ExecutionID string `json:"executionId,omitempty"`
	StartedAt   time.Time       `json:"startedAt"`
	CompletedAt *time.Time      `json:"completedAt,omitempty"`
}
