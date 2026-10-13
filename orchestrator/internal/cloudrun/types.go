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
	ID          string
	ScenarioID  string
	Provider    string
	AccountID   string
	TenantID    string
	Region      string
	Status      Status
	Result      json.RawMessage
	Error       string
	InitiatedBy string
	StartedAt   time.Time
	CompletedAt *time.Time
}
