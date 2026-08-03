package remediation

import "time"

// TechniqueVerificationRun is the full record of one attempt to re-run a
// finding's real ATT&CK technique after its remediation reached Completed
// -- proving the control actually stops the attack, not just that its
// configuration is correct. Deliberately independent of RemediationRequest's
// own fix/verify/rollback lifecycle (see design spec §2.1): a single
// dispatch, not a state machine.
type TechniqueVerificationRun struct {
	ID           string
	RequestID    string // remediation_requests.id
	AgentID      string
	CheckID      string
	TechniqueID  string
	Engine       string // "art" only in V1
	RunID        string // scenario_runs.id for the dispatch
	Status       string // requested | dispatched | pass | fail | blocked | error | skipped
	Reason       string // copied verbatim from the result's Details field
	RequestedBy  string
	RequestedAt  time.Time
	DispatchedAt *time.Time
	CompletedAt  *time.Time
}

const (
	TechniqueVerificationStatusRequested  = "requested"
	TechniqueVerificationStatusDispatched = "dispatched"
)
