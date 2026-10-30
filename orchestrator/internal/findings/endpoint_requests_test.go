package findings

import (
	"testing"
	"time"
)

// Phase 2: per-endpoint remediation requests. Each request carries the status of
// its execution, the independent verification evidence, and whether the fix was
// independently verified. A request is never shown as a closed finding on its own.

func TestMapRequestStatus(t *testing.T) {
	cases := map[string]string{
		"requested":           RequestPending,
		"dispatched":          RequestInProgress,
		"running":             RequestInProgress,
		"verifying":           RequestInProgress,
		"completed":           RequestCompleted,
		"failed":              RequestFailed,
		"verification_failed": RequestFailed,
		"timed_out":           RequestFailed,
		"cancelled":           RequestCancelled,
		"something_new":       RequestUnknown, // never invented into a known label
		"":                    RequestUnknown,
	}
	for in, want := range cases {
		if got := MapRequestStatus(in); got != want {
			t.Errorf("MapRequestStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAttachRequests_GroupsByEndpointNewestFirst(t *testing.T) {
	eps := []EndpointRemediation{{AgentID: "a1", Hostname: "FINANCE-PC-01"}, {AgentID: "a2", Hostname: "HR"}}
	old := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	reqs := []RemediationRequest{
		{ID: "r1", AgentID: "a1", CheckID: "windows-firewall-enabled", Status: "completed", RequestedAt: old},
		{ID: "r2", AgentID: "a1", CheckID: "windows-smbv1-disabled", Status: "running", RequestedAt: newer},
		{ID: "r3", AgentID: "a2", CheckID: "windows-firewall-enabled", Status: "requested", RequestedAt: old},
	}
	got := AttachRequests(eps, reqs)
	if len(got[0].Requests) != 2 || got[0].Requests[0].RequestID != "r2" {
		t.Fatalf("a1 requests = %+v, want r2 (newest) then r1", got[0].Requests)
	}
	if got[0].Requests[0].Status != RequestInProgress || got[0].Requests[1].Status != RequestCompleted {
		t.Fatalf("a1 statuses = %q / %q", got[0].Requests[0].Status, got[0].Requests[1].Status)
	}
	if len(got[1].Requests) != 1 || got[1].Requests[0].Status != RequestPending {
		t.Fatalf("a2 requests = %+v", got[1].Requests)
	}
}

func TestAttachRequests_ClosureVerifiedOnlyByPassingVerification(t *testing.T) {
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	reqs := []RemediationRequest{
		// Execution completed and the independent technique run passed: verified.
		{ID: "pass", AgentID: "a1", Status: "completed", RequestedAt: now, VerificationStatus: "pass", VerificationReason: "blocked"},
		// Execution completed, but there is no verification run: not verified.
		{ID: "none", AgentID: "a1", Status: "completed", RequestedAt: now.Add(-time.Hour)},
		// Execution completed, verification failed: not verified.
		{ID: "fail", AgentID: "a1", Status: "completed", RequestedAt: now.Add(-2 * time.Hour), VerificationStatus: "fail"},
	}
	got := AttachRequests([]EndpointRemediation{{AgentID: "a1"}}, reqs)[0].Requests
	verified := map[string]bool{}
	for _, r := range got {
		verified[r.RequestID] = r.ClosureVerified
	}
	if !verified["pass"] || verified["none"] || verified["fail"] {
		t.Fatalf("closureVerified = %v, want only the passing run", verified)
	}
}

func TestAttachRequests_UnknownAgentIsDropped(t *testing.T) {
	// A request for an agent with no endpoint row has nowhere to attach; it is not
	// invented into a new endpoint.
	got := AttachRequests([]EndpointRemediation{{AgentID: "a1"}}, []RemediationRequest{{ID: "x", AgentID: "gone"}})
	if len(got) != 1 || len(got[0].Requests) != 0 {
		t.Fatalf("got %+v", got)
	}
}
