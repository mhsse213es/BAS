// Package cloudrun holds the lifecycle record for one cloud scenario run.
// Kept separate from cloudgraph since lifecycle/persistence tracking is a
// different concern from cloudgraph's pure graph/evaluation scope -- mirrors
// how rwevidence is its own domain package, distinct from adprimitive/adchain.
package cloudrun

import (
	"encoding/json"
	"time"
)

// Status is a cloud_runs.status value.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusPartial   Status = "partial"
)

// CloudRun is one execution of one cloud scenario against one account
// scope. Result is deliberately opaque -- this package defines the
// lifecycle a run goes through, not what a given scenario's execution
// harness (a later sub-project) actually produces as evidence.
type CloudRun struct {
	ID          string          `json:"id"`
	ScenarioID  string          `json:"scenarioId"`
	Provider    string          `json:"provider"`
	AccountID   string          `json:"accountId"`
	TenantID    string          `json:"tenantId,omitempty"`
	Region      string          `json:"region,omitempty"`
	Status      Status          `json:"status"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
	InitiatedBy string          `json:"initiatedBy,omitempty"`
	StartedAt   time.Time       `json:"startedAt"`
	CompletedAt *time.Time      `json:"completedAt,omitempty"`
}
