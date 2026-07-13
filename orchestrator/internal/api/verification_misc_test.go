package api

import (
	"testing"
)

// GetMyPermissions already has thorough coverage in user_handlers_test.go
// (TestGetMyPermissions_NoClaimsUnauthorized, TestGetMyPermissions_PerRole —
// all 3 roles) — not duplicated here.

// TestQueueStatus_Table pins the display-status derivation: the concrete
// result once Approved, otherwise the workflow state itself (so a reviewer
// sees "NeedsReview"/"Rejected"/"Pending" rather than a stale result).
func TestQueueStatus_Table(t *testing.T) {
	cases := []struct {
		workflow, result, want string
	}{
		{"Approved", "Detected", "Detected"},
		{"Approved", "NotDetected", "NotDetected"},
		{"Pending", "Detected", "Pending"},
		{"NeedsReview", "Detected", "NeedsReview"},
		{"Rejected", "Detected", "Rejected"},
	}
	for _, c := range cases {
		if got := queueStatus(c.workflow, c.result); got != c.want {
			t.Errorf("queueStatus(%q,%q) = %q, want %q", c.workflow, c.result, got, c.want)
		}
	}
}

// TestQueueOrder_Table pins the queue sort priority: outstanding work first.
func TestQueueOrder_Table(t *testing.T) {
	cases := []struct {
		status string
		want   int
	}{
		{"Pending", 0},
		{"NeedsReview", 1},
		{"Rejected", 2},
		{"Detected", 3},
		{"NotDetected", 3},
		{"NotApplicable", 3},
	}
	for _, c := range cases {
		if got := queueOrder(c.status); got != c.want {
			t.Errorf("queueOrder(%q) = %d, want %d", c.status, got, c.want)
		}
	}
	if queueOrder("Pending") >= queueOrder("NeedsReview") {
		t.Error("Pending should sort before NeedsReview")
	}
	if queueOrder("NeedsReview") >= queueOrder("Rejected") {
		t.Error("NeedsReview should sort before Rejected")
	}
	if queueOrder("Rejected") >= queueOrder("Detected") {
		t.Error("Rejected should sort before a terminal result")
	}
}

func TestValidResult_Table(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"Detected", true}, {"NotDetected", true}, {"NotApplicable", true},
		{"detected", false}, {"", false}, {"Maybe", false},
	}
	for _, c := range cases {
		if got := validResult(c.s); got != c.want {
			t.Errorf("validResult(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestValidWorkflow_Table(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"Pending", true}, {"NeedsReview", true}, {"Approved", true}, {"Rejected", true},
		{"pending", false}, {"", false}, {"Bogus", false},
	}
	for _, c := range cases {
		if got := validWorkflow(c.s); got != c.want {
			t.Errorf("validWorkflow(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

// TestProviderDisplayName_Table pins the registry lookup + unknown-key
// passthrough (so an unrecognized provider key still renders as *something*
// in the queue rather than an empty label).
func TestProviderDisplayName_Table(t *testing.T) {
	if got := providerDisplayName("microsoft_sentinel"); got != "Microsoft Sentinel" {
		t.Errorf("providerDisplayName(microsoft_sentinel) = %q, want Microsoft Sentinel", got)
	}
	if got := providerDisplayName("not_a_real_provider"); got != "not_a_real_provider" {
		t.Errorf("providerDisplayName(unknown) = %q, want passthrough of the key", got)
	}
}
