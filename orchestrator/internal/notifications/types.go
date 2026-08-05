package notifications

import "time"

type EventType string

const (
	EventJobStarted   EventType = "job_started"
	EventJobCompleted EventType = "job_completed"
	EventJobPartial   EventType = "job_partially_completed"
	EventJobFailed    EventType = "job_failed"
	EventJobCancelled EventType = "job_cancelled"

	EventTargetFailed   EventType = "target_failed"
	EventTargetDeferred EventType = "target_deferred"
	EventTargetAssigned EventType = "target_assigned"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// severityRank orders severities low-to-high for min_severity webhook
// filtering -- a webhook configured with min_severity=warning receives
// warning, error, and critical events, not info.
func severityRank(s Severity) int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityWarning:
		return 1
	case SeverityError:
		return 2
	case SeverityCritical:
		return 3
	default:
		return 0
	}
}

// Event is one emitted notification -- persisted, pushed live over
// WebSocket, and optionally fanned out to configured webhooks.
type Event struct {
	ID        string
	Type      EventType
	JobID     string
	TargetID  string // "" for job-level events
	AgentID   string // "" for job-level events
	Severity  Severity
	Message   string
	Metadata  map[string]any
	Timestamp time.Time
}
