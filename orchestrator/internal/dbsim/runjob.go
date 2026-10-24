package dbsim

import (
	"errors"
	"time"
)

// JobKind says what a job runs on the bound agent.
type JobKind string

const (
	// JobKindRun runs the selected scenarios.
	JobKindRun JobKind = "run"
	// JobKindIdentityCheck runs the read-only probe check_readonly_identity.
	JobKindIdentityCheck JobKind = "identity_check"
)

// JobStatus is the lifecycle state of a dispatched run job.
type JobStatus string

const (
	JobPending   JobStatus = "pending"
	JobRunning   JobStatus = "running"
	JobCompleted JobStatus = "completed"
	JobFailed    JobStatus = "failed"
	JobPartial   JobStatus = "partial"
	JobCancelled JobStatus = "cancelled"
)

// Valid reports whether s is a known status.
func (s JobStatus) Valid() bool {
	switch s {
	case JobPending, JobRunning, JobCompleted, JobFailed, JobPartial, JobCancelled:
		return true
	}
	return false
}

// Terminal reports whether no further transition is possible.
func (s JobStatus) Terminal() bool {
	switch s {
	case JobCompleted, JobFailed, JobPartial, JobCancelled:
		return true
	}
	return false
}

// Active reports whether the job still occupies its target and agent.
func (s JobStatus) Active() bool { return s == JobPending || s == JobRunning }

// CanTransitionTo reports whether next is a legal move from s. Terminal states
// are final.
func (s JobStatus) CanTransitionTo(next JobStatus) bool {
	switch s {
	case JobPending:
		return next == JobRunning || next == JobFailed || next == JobCancelled
	case JobRunning:
		return next == JobCompleted || next == JobFailed || next == JobPartial || next == JobCancelled
	}
	return false
}

// PlannedStep is one compiled probe of a job. The spec carries the run id, the
// marker and the credential REFERENCE only; the secret never leaves the agent.
type PlannedStep struct {
	ScenarioID string      `json:"scenarioId"`
	Index      int         `json:"index"`
	Spec       DBProbeSpec `json:"spec"`
}

// RunJob is one dispatched job: a pending-run record, kept apart from the
// terminal-only dbsim_runs rows.
type RunJob struct {
	ID              string        `json:"id"`
	Kind            JobKind       `json:"kind"`
	TargetID        string        `json:"targetId"`
	AgentID         string        `json:"agentId"`
	Mode            ExecMode      `json:"mode"`
	ScenarioIDs     []string      `json:"scenarioIds"`
	Plan            []PlannedStep `json:"plan"`
	Status          JobStatus     `json:"status"`
	Reason          string        `json:"reason,omitempty"`
	CreatedBy       string        `json:"createdBy"`
	LabConfirmation string        `json:"labConfirmation,omitempty"`
	CreatedAt       time.Time     `json:"createdAt"`
	StartedAt       time.Time     `json:"startedAt,omitempty"`
	Deadline        time.Time     `json:"deadline"`
}

// ErrJobBusy means the target or its agent already has an active job. The
// store returns it when its partial unique index refuses a second active job.
var ErrJobBusy = errors.New("dbsim: a job is already active for this target or agent")

// ErrJobNotFound means no job has the requested id.
var ErrJobNotFound = errors.New("dbsim: job not found")

// Deadline budget (spec 6.8): 90 seconds per selected scenario plus 120.
const (
	jobSecondsPerScenario = 90
	jobSecondsBase        = 120
)

// DeadlineFor is the job deadline: created + 90s per scenario + 120s. A job
// always budgets at least one scenario.
func DeadlineFor(created time.Time, nScenarios int) time.Time {
	if nScenarios < 1 {
		nScenarios = 1
	}
	return created.Add(time.Duration(jobSecondsPerScenario*nScenarios+jobSecondsBase) * time.Second)
}

// JobsSchemaSQL is the DDL of dbsim_run_jobs (statements run in order). The two
// partial unique indexes make a second ACTIVE job for the same target or agent
// impossible even under a race.
var JobsSchemaSQL = []string{
	`CREATE TABLE IF NOT EXISTS dbsim_run_jobs (
		id               text        PRIMARY KEY,
		kind             text        NOT NULL DEFAULT 'run',
		target_id        text        NOT NULL,
		agent_id         text        NOT NULL,
		mode             text        NOT NULL,
		scenario_ids     jsonb       NOT NULL DEFAULT '[]'::jsonb,
		plan             jsonb       NOT NULL DEFAULT '[]'::jsonb,
		status           text        NOT NULL,
		reason           text        NOT NULL DEFAULT '',
		created_by       text        NOT NULL,
		lab_confirmation text        NOT NULL DEFAULT '',
		created_at       timestamptz NOT NULL,
		started_at       timestamptz,
		deadline         timestamptz NOT NULL,
		updated_at       timestamptz NOT NULL DEFAULT NOW(),
		CONSTRAINT dbsim_run_jobs_status_chk CHECK (status IN ('pending','running','completed','failed','partial','cancelled'))
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS dbsim_run_jobs_one_active_target
		ON dbsim_run_jobs (target_id) WHERE status IN ('pending','running')`,
	`CREATE UNIQUE INDEX IF NOT EXISTS dbsim_run_jobs_one_active_agent
		ON dbsim_run_jobs (agent_id) WHERE status IN ('pending','running')`,
	`CREATE INDEX IF NOT EXISTS dbsim_run_jobs_active_deadline
		ON dbsim_run_jobs (deadline) WHERE status IN ('pending','running')`,
}
