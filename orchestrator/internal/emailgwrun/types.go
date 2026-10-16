// Package emailgwrun holds the lifecycle record for one real EmailGW
// scenario run -- the real-message counterpart to internal/cloudrun,
// which this package deliberately mirrors in shape (same five-state
// Status, same id/result/error/initiated_by/started_at/completed_at
// columns) and deliberately departs from in lifecycle: cloudrun's own
// CloudPlan evaluation has zero I/O and so finishes inside the same
// HTTP request that triggered it; this package's own equivalent
// (sending a real SMTP message via emailgwefficacy.InjectScenarioMessage,
// then waiting for a real mail gateway and vendor API to produce
// evidence) cannot, so a run here spends real wall-clock time sitting
// at StatusRunning before anything completes it -- see
// internal/db/emailgwrun_executor.go's own package comment for the
// asynchronous executor this implies.
package emailgwrun

import (
	"encoding/json"
	"time"
)

// Status is an email_gw_runs.status value. Unlike cloudrun.Status,
// StatusFailed here is reserved specifically for a failure to even
// send the test message (e.g. the target mail gateway refused the
// SMTP connection) -- emailgwefficacy.VerifyMailExpectation itself
// never returns an error, so once injection succeeds a run always
// reaches StatusCompleted or StatusPartial, never StatusFailed.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusPartial   Status = "partial"
)

// Environment is an email_gw_runs.environment value: an explicit,
// operator-set declaration of whether a run's evidence came from a
// lab/test tenant or a genuine customer tenant -- never inferred from
// an evidence record's own Source (emailgwefficacy.SourceLive means
// "proven through the real adapter's HTTP/JSON code path", which has
// always meant httptest-proven in this initiative, never "a genuine
// customer tenant" -- the two questions are orthogonal). Set once,
// deployment-wide, from AUDSPECT_EMAILGW_TENANT_ENVIRONMENT (default
// EnvironmentLab when unset), not per-run: whether a given deployment
// is pointed at a lab tenant or a real customer's is a fact about the
// deployment, not about any one scenario. Every email_gw_runs row
// persists this value at insert time so time-based metrics can keep
// lab and customer evidence in two separate, never-merged buckets
// even after the deployment's own setting later changes.
type Environment string

const (
	EnvironmentLab      Environment = "lab"
	EnvironmentCustomer Environment = "customer"
)

// EmailGWRun is one real execution of one emailgwefficacy scenario
// expectation. Result is deliberately opaque -- the marshaled
// emailgwefficacy.EfficacyResult, same "this package owns the
// lifecycle, not the evaluated content" discipline as
// cloudrun.CloudRun.Result.
//
// InjectedAt/WindowStart/WindowEnd/VerifiedAt are the timing evidence
// a real dwell-window default needs to ever be set from real Defender
// behavior rather than assumption (see the executor's own package
// comment) -- and, together with Status, exactly what a startup
// recovery sweep needs to tell an abandoned-but-still-waiting run
// apart from one whose window had already closed when the process
// restarted.
type EmailGWRun struct {
	ID                string          `json:"id"`
	ScenarioID        string          `json:"scenarioId"` // an emailgwefficacy expectation ID, e.g. "EG-002.known-bad" -- not just "EG-002"
	MessageClass      string          `json:"messageClass,omitempty"`
	Environment       Environment     `json:"environment"`
	Status            Status          `json:"status"`
	Result            json.RawMessage `json:"result,omitempty"`
	Error             string          `json:"error,omitempty"`
	InitiatedBy       string          `json:"initiatedBy,omitempty"`
	SenderPayloadHash string          `json:"senderPayloadHash,omitempty"`
	InjectedAt        *time.Time      `json:"injectedAt,omitempty"`
	WindowStart       *time.Time      `json:"windowStart,omitempty"`
	WindowEnd         *time.Time      `json:"windowEnd,omitempty"`
	VerifiedAt        *time.Time      `json:"verifiedAt,omitempty"`
	StartedAt         time.Time       `json:"startedAt"`
	CompletedAt       *time.Time      `json:"completedAt,omitempty"`
}
