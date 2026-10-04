package remediation

import "time"

const (
	StatusRequested          = "requested"
	StatusDispatched         = "dispatched"
	StatusRunning            = "running"
	StatusVerifying          = "verifying"
	StatusCompleted          = "completed"
	StatusFailed             = "failed"              // the fix command itself failed
	StatusVerificationFailed = "verification_failed" // fix command exited cleanly, but the check still fails
	StatusTimedOut           = "timed_out"
	StatusCancelled          = "cancelled"
)

// IsTerminal reports whether status is a terminal state -- no further
// state-machine transitions happen once a request reaches one of these.
func IsTerminal(status string) bool {
	switch status {
	case StatusCompleted, StatusFailed, StatusVerificationFailed, StatusTimedOut, StatusCancelled:
		return true
	}
	return false
}

// RemediationRequest is the full record of one endpoint's attempt to run
// one remediation -- every field is a column in internal/api's
// remediation_requests table, mirroring how internal/actions.Action maps
// onto action_requests.
type RemediationRequest struct {
	ID                      string
	RemediationID           string
	AgentID                 string
	CheckID                 string
	Tier                    Tier
	Status                  string
	FixRunID                string
	VerifyRunID             string
	Error                   string
	RequestedBy             string
	ApprovedBy              string
	Reason                  string
	RollbackAvailable       bool
	RollbackStatus          string
	RollbackRunID           string
	RollbackVerifyRunID     string
	RequestedAt             time.Time
	DispatchedAt            *time.Time
	ExecutionCompletedAt    *time.Time
	VerificationCompletedAt *time.Time
	CompletedAt             *time.Time
}
