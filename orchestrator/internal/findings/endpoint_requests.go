package findings

import (
	"sort"
	"time"
)

// Phase 2: per-endpoint remediation requests. A request is one run of a catalog
// remediation on one endpoint. Its status is the execution status mapped to the
// four labels; closure is shown as verified only when an independent ATT&CK
// verification run for that request passed. Completed execution alone is not
// proof that the finding is closed.
const (
	RequestPending    = "Pending"
	RequestInProgress = "In Progress"
	RequestCompleted  = "Completed"
	RequestFailed     = "Failed"
	RequestCancelled  = "Cancelled"
	RequestUnknown    = "Unknown"
)

// RemediationRequest is one remediation_requests row plus its latest independent
// verification run, if any.
type RemediationRequest struct {
	ID                 string
	AgentID            string
	RemediationID      string
	CheckID            string
	Status             string
	Error              string
	RequestedBy        string
	RequestedAt        time.Time
	CompletedAt        *time.Time
	FixRunID           string
	VerifyRunID        string
	VerificationStatus string
	VerificationReason string
	VerificationAt     *time.Time
}

// EndpointRequest is the Phase 2 view of one request on an endpoint.
type EndpointRequest struct {
	RequestID          string     `json:"requestId"`
	RemediationID      string     `json:"remediationId"`
	CheckID            string     `json:"checkId"`
	Status             string     `json:"status"`
	ExecutionStatus    string     `json:"executionStatus"`
	Error              string     `json:"error,omitempty"`
	RequestedBy        string     `json:"requestedBy"`
	RequestedAt        time.Time  `json:"requestedAt"`
	CompletedAt        *time.Time `json:"completedAt,omitempty"`
	FixRunID           string     `json:"fixRunId,omitempty"`
	VerifyRunID        string     `json:"verifyRunId,omitempty"`
	VerificationStatus string     `json:"verificationStatus,omitempty"`
	VerificationReason string     `json:"verificationReason,omitempty"`
	VerificationAt     *time.Time `json:"verificationAt,omitempty"`
	ClosureVerified    bool       `json:"closureVerified"`
}

// MapRequestStatus maps an execution status to the Phase 2 label. An unrecognised
// status is labelled Unknown, never guessed.
func MapRequestStatus(status string) string {
	switch status {
	case "requested":
		return RequestPending
	case "dispatched", "running", "verifying":
		return RequestInProgress
	case "completed":
		return RequestCompleted
	case "failed", "verification_failed", "timed_out":
		return RequestFailed
	case "cancelled":
		return RequestCancelled
	}
	return RequestUnknown
}

// AttachRequests adds each endpoint's requests, newest first. Requests whose agent
// has no endpoint row are dropped rather than creating an endpoint.
func AttachRequests(eps []EndpointRemediation, reqs []RemediationRequest) []EndpointRemediation {
	byAgent := map[string][]EndpointRequest{}
	for _, r := range reqs {
		byAgent[r.AgentID] = append(byAgent[r.AgentID], EndpointRequest{
			RequestID:          r.ID,
			RemediationID:      r.RemediationID,
			CheckID:            r.CheckID,
			Status:             MapRequestStatus(r.Status),
			ExecutionStatus:    r.Status,
			Error:              r.Error,
			RequestedBy:        r.RequestedBy,
			RequestedAt:        r.RequestedAt,
			CompletedAt:        r.CompletedAt,
			FixRunID:           r.FixRunID,
			VerifyRunID:        r.VerifyRunID,
			VerificationStatus: r.VerificationStatus,
			VerificationReason: r.VerificationReason,
			VerificationAt:     r.VerificationAt,
			ClosureVerified:    r.VerificationStatus == "pass",
		})
	}
	for i := range eps {
		list := byAgent[eps[i].AgentID]
		sort.SliceStable(list, func(a, b int) bool { return list[a].RequestedAt.After(list[b].RequestedAt) })
		eps[i].Requests = list
	}
	return eps
}
