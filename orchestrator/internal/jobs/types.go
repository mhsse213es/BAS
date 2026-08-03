// Package jobs is generic fleet-job infrastructure -- a persisted Job/JobTarget
// model with a Tick()-driven dispatch loop. It knows nothing about what a
// given Job.Type actually does; that's supplied by the caller via
// DispatchFn/StatusFn (see dispatch.go). See
// docs/superpowers/specs/2026-08-03-fleet-job-engine-design.md.
package jobs

import (
	"encoding/json"
	"time"
)

const (
	JobStateRequested = "requested"
	JobStateRunning   = "running"
	JobStateCompleted = "completed" // every target terminal, all succeeded
	JobStatePartial   = "partial"   // every target terminal, some succeeded and some didn't
	JobStateFailed    = "failed"    // every target terminal, none succeeded
	JobStateCancelled = "cancelled"
)

const (
	TargetStatePending    = "pending"
	TargetStateDispatched = "dispatched"
	TargetStateCompleted  = "completed"
	TargetStateFailed     = "failed"
	TargetStateCancelled  = "cancelled"
	TargetStateDeferred   = "deferred" // frozen at dispatch time; non-terminal, auto-resumes when the freeze lifts
)

// Job is one logical fleet-wide operation -- e.g. "apply remediation X to
// these N agents".
type Job struct {
	ID          string
	Type        string
	State       string
	Payload     json.RawMessage // type-specific, e.g. {"remediationId":"...","reason":"..."}
	CreatedBy   string
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	ScheduledAt *time.Time // nil = dispatch immediately; non-nil = don't dispatch before this
}

// JobTarget is one agent's independently tracked execution within a Job.
type JobTarget struct {
	ID          string
	JobID       string
	AgentID     string
	State       string
	RefID       string // e.g. the remediation_requests.id created for this target, once dispatched
	Error       string
	RetryCount  int // no auto-retry logic built this cycle; column exists for forward-compat
	MaxRetries  int
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
}
