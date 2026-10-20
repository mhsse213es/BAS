// Package injectionapproval decides whether one pipeline injection or cleanup may run. It holds
// no state of its own: the caller stores the Record and calls Verify immediately before acting.
package injectionapproval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// ApprovalTTL is how long an approval stays usable. An expired approval cannot be renewed; a
// new one is needed.
const ApprovalTTL = 15 * time.Minute

// Kind says what the approval authorizes.
type Kind string

const (
	KindInjection Kind = "injection"
	KindCleanup   Kind = "cleanup"
)

// Classification is the deployment class. Customer is the stricter default.
type Classification string

const (
	Customer Classification = "customer"
	Lab      Classification = "lab"
)

// ParseClassification maps a configured value to a classification. Anything other than
// "lab" is Customer.
func ParseClassification(v string) Classification {
	if v == string(Lab) {
		return Lab
	}
	return Customer
}

var (
	ErrNotApproved  = errors.New("injection approval: not approved")
	ErrExpired      = errors.New("injection approval: expired")
	ErrConsumed     = errors.New("injection approval: already used")
	ErrScopeChanged = errors.New("injection approval: scope differs from the approved scope")
	ErrSelfApproval = errors.New("injection approval: requester cannot approve their own request in this deployment")
)

// Scope is everything an approval binds to. A change to any field invalidates it.
type Scope struct {
	Kind           Kind   `json:"kind"`
	CampaignID     string `json:"campaignId"`
	StageKey       string `json:"stageKey"`
	ConnectorID    string `json:"connectorId"`
	Target         string `json:"target"`
	PayloadHash    string `json:"payloadHash"`
	TestScope      string `json:"testScope"`
	ExpectedChange string `json:"expectedChange"`
	// Payload is the canonical JSON of the tagged document, so an approver sees exactly what is
	// being approved. It is part of the scope hash.
	Payload string `json:"payload,omitempty"`
}

// Hash is a stable digest of the scope. Fields are encoded in struct order, so the same scope
// always gives the same hash.
func (s Scope) Hash() string {
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Record is one approval request and its state.
type Record struct {
	ID          string
	Scope       Scope
	ScopeHash   string
	RequestedBy string
	ApprovedBy  string
	ApprovedAt  time.Time
	ExpiresAt   time.Time
	ConsumedAt  time.Time
}

// Approve records an approval. It refuses self-approval in a customer deployment and refuses
// a record that has already been used.
func Approve(r *Record, approver string, now time.Time, c Classification) error {
	if !r.ConsumedAt.IsZero() {
		return ErrConsumed
	}
	if approver == "" {
		return ErrNotApproved
	}
	if approver == r.RequestedBy && c != Lab {
		return ErrSelfApproval
	}
	r.ApprovedBy = approver
	r.ApprovedAt = now
	r.ExpiresAt = now.Add(ApprovalTTL)
	return nil
}

// Verify checks an approval against the scope about to run. It is called immediately before
// the action. Checks run in this order: approved, unused, unexpired, unchanged, not
// self-approved in customer deployments.
func Verify(r Record, presented Scope, now time.Time, c Classification) error {
	if r.ApprovedBy == "" {
		return ErrNotApproved
	}
	if !r.ConsumedAt.IsZero() {
		return ErrConsumed
	}
	if !now.Before(r.ExpiresAt) {
		return ErrExpired
	}
	if presented.Hash() != r.ScopeHash {
		return ErrScopeChanged
	}
	if r.ApprovedBy == r.RequestedBy && c != Lab {
		return ErrSelfApproval
	}
	return nil
}
