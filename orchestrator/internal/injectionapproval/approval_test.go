package injectionapproval

import (
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func baseScope() Scope {
	return Scope{
		Kind: KindInjection, CampaignID: "c1", StageKey: "inject", ConnectorID: "dc-elastic",
		Target: "logs-bas-test", PayloadHash: "sha256:abc", TestScope: "one event",
		ExpectedChange: "event with marker appears in index",
	}
}

func approvedBy(t *testing.T, requester, approver string, c Classification) Record {
	t.Helper()
	s := baseScope()
	r := Record{ID: "a1", Scope: s, ScopeHash: s.Hash(), RequestedBy: requester}
	if err := Approve(&r, approver, t0, c); err != nil {
		t.Fatalf("approve: %v", err)
	}
	return r
}

func TestApprove_SetsFifteenMinuteWindow(t *testing.T) {
	r := approvedBy(t, "alice", "bob", Customer)
	if got := r.ExpiresAt.Sub(r.ApprovedAt); got != 15*time.Minute {
		t.Fatalf("window = %s, want 15m", got)
	}
}

// Missing approval: a request that nobody approved is refused.
func TestVerify_MissingApprovalRefused(t *testing.T) {
	s := baseScope()
	r := Record{ID: "a1", Scope: s, ScopeHash: s.Hash(), RequestedBy: "alice"}
	if err := Verify(r, s, t0, Customer); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err = %v, want ErrNotApproved", err)
	}
}

// Expired: the window closes exactly at ExpiresAt, not after it.
func TestVerify_ExpiredRefusedAtBoundary(t *testing.T) {
	r := approvedBy(t, "alice", "bob", Customer)
	if err := Verify(r, baseScope(), r.ExpiresAt.Add(-time.Second), Customer); err != nil {
		t.Fatalf("one second before expiry refused: %v", err)
	}
	if err := Verify(r, baseScope(), r.ExpiresAt, Customer); !errors.Is(err, ErrExpired) {
		t.Fatalf("at expiry: err = %v, want ErrExpired", err)
	}
}

// Expired approvals are not renewed implicitly: Approve on a spent record is refused.
func TestApprove_ConsumedRecordCannotBeReapproved(t *testing.T) {
	r := approvedBy(t, "alice", "bob", Customer)
	r.ConsumedAt = t0.Add(time.Minute)
	if err := Approve(&r, "carol", t0.Add(2*time.Minute), Customer); !errors.Is(err, ErrConsumed) {
		t.Fatalf("err = %v, want ErrConsumed", err)
	}
}

// Reuse: once consumed, the same approval authorizes nothing else.
func TestVerify_ReusedApprovalRefused(t *testing.T) {
	r := approvedBy(t, "alice", "bob", Customer)
	r.ConsumedAt = t0.Add(time.Minute)
	if err := Verify(r, baseScope(), t0.Add(2*time.Minute), Customer); !errors.Is(err, ErrConsumed) {
		t.Fatalf("err = %v, want ErrConsumed", err)
	}
}

// Modified scope: changing the target, payload, scope or expected change invalidates it.
func TestVerify_ModifiedScopeRefused(t *testing.T) {
	r := approvedBy(t, "alice", "bob", Customer)
	cases := map[string]func(s *Scope){
		"target":     func(s *Scope) { s.Target = "logs-prod" },
		"payload":    func(s *Scope) { s.PayloadHash = "sha256:def" },
		"test scope": func(s *Scope) { s.TestScope = "all events" },
		"expected":   func(s *Scope) { s.ExpectedChange = "anything" },
		"connector":  func(s *Scope) { s.ConnectorID = "dc-other" },
		"campaign":   func(s *Scope) { s.CampaignID = "c2" },
		"stage":      func(s *Scope) { s.StageKey = "other" },
		"kind":       func(s *Scope) { s.Kind = KindCleanup },
	}
	for name, mutate := range cases {
		s := baseScope()
		mutate(&s)
		if err := Verify(r, s, t0, Customer); !errors.Is(err, ErrScopeChanged) {
			t.Fatalf("%s changed: err = %v, want ErrScopeChanged", name, err)
		}
	}
}

// Self-approval: in a customer deployment the requester cannot approve their own request.
func TestApprove_SelfApprovalRefusedInCustomer(t *testing.T) {
	s := baseScope()
	r := Record{ID: "a1", Scope: s, ScopeHash: s.Hash(), RequestedBy: "alice"}
	if err := Approve(&r, "alice", t0, Customer); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("err = %v, want ErrSelfApproval", err)
	}
}

// Self-approval is allowed only in an explicitly classified lab deployment.
func TestApprove_SelfApprovalAllowedInLab(t *testing.T) {
	s := baseScope()
	r := Record{ID: "a1", Scope: s, ScopeHash: s.Hash(), RequestedBy: "alice"}
	if err := Approve(&r, "alice", t0, Lab); err != nil {
		t.Fatalf("lab self-approval refused: %v", err)
	}
}

// Defence in depth: a record that already names requester == approver is refused at verify
// time in a customer deployment, even if it was created another way.
func TestVerify_SelfApprovedRecordRefusedInCustomer(t *testing.T) {
	r := approvedBy(t, "alice", "bob", Customer)
	r.ApprovedBy = r.RequestedBy
	if err := Verify(r, baseScope(), t0, Customer); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("err = %v, want ErrSelfApproval", err)
	}
}

// An unknown classification is treated as customer, the stricter default.
func TestClassify_UnknownIsCustomer(t *testing.T) {
	if got := ParseClassification("lab-ish"); got != Customer {
		t.Fatalf("unknown = %v, want Customer", got)
	}
	if got := ParseClassification("lab"); got != Lab {
		t.Fatalf("lab = %v, want Lab", got)
	}
	if got := ParseClassification(""); got != Customer {
		t.Fatalf("empty = %v, want Customer", got)
	}
}

// The hash changes when any bound field changes, and is stable for the same scope.
func TestScopeHash_BoundToEveryField(t *testing.T) {
	a := baseScope()
	if a.Hash() != baseScope().Hash() {
		t.Fatal("hash not stable for an identical scope")
	}
	b := baseScope()
	b.Target = "other"
	if a.Hash() == b.Hash() {
		t.Fatal("hash ignores the target")
	}
}
