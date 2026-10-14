package cloudgraph

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCloudAggregate_PartialAccountFailureDoesNotCorruptOthers verifies isolation:
// one account's failure must not zero-out or exclude the other accounts' real outcomes.
func TestCloudAggregate_PartialAccountFailureDoesNotCorruptOthers(t *testing.T) {
	healthyRun := &CloudChildRun{
		Account: &AccountScope{AccountID: "111111111111"},
		Status:  "completed",
		Outcomes: []*CloudControlOutcome{
			{ExecutionOutcome: "Allowed", PrerequisiteState: PolicySupported},
			{ExecutionOutcome: "Blocked", PrerequisiteState: Blocked},
		},
	}

	failedRun := &CloudChildRun{
		Account:    &AccountScope{AccountID: "222222222222"},
		Status:     "skipped",
		SkipReason: "discovery failed: no cloud access",
	}

	summary := CloudAggregate([]*CloudChildRun{healthyRun, failedRun})

	if summary.Dispatched != 2 {
		t.Errorf("Expected 2 dispatched (both accounts attempted), got %d", summary.Dispatched)
	}
	if summary.Skipped != 1 {
		t.Errorf("Expected 1 skipped, got %d", summary.Skipped)
	}
	if summary.Prevented != 1 {
		t.Errorf("Expected 1 prevented (Blocked outcome) from healthy account, got %d", summary.Prevented)
	}
	if summary.Missed != 1 {
		t.Errorf("Expected 1 missed (Allowed outcome, assuming no detection) from healthy account, got %d", summary.Missed)
	}
}

// TestCloudAggregate_EmptyRunsReturnsZeroSummary verifies no-accounts edge case
func TestCloudAggregate_EmptyRunsReturnsZeroSummary(t *testing.T) {
	summary := CloudAggregate([]*CloudChildRun{})

	if summary.Dispatched != 0 {
		t.Errorf("Expected 0 dispatched, got %d", summary.Dispatched)
	}
	if summary.Targets != 0 {
		t.Errorf("Expected 0 targets, got %d", summary.Targets)
	}
}

// TestRunMultiAccount_RespectsMaxConcurrency verifies the concurrency limit is enforced
func TestRunMultiAccount_RespectsMaxConcurrency(t *testing.T) {
	accounts := []*AccountScope{
		{AccountID: "1"}, {AccountID: "2"}, {AccountID: "3"},
		{AccountID: "4"}, {AccountID: "5"},
	}

	scope := NewCloudCampaignScope(accounts)
	scope.MaxConcurrency = 2

	var currentConcurrent int32
	var maxObservedConcurrent int32
	var mu sync.Mutex

	execute := func(acc *AccountScope) *CloudChildRun {
		cur := atomic.AddInt32(&currentConcurrent, 1)
		mu.Lock()
		if cur > maxObservedConcurrent {
			maxObservedConcurrent = cur
		}
		mu.Unlock()

		time.Sleep(20 * time.Millisecond) // hold the slot briefly to force overlap

		atomic.AddInt32(&currentConcurrent, -1)
		return &CloudChildRun{Account: acc, Status: "completed"}
	}

	runs := RunMultiAccount(scope, execute)

	if len(runs) != 5 {
		t.Fatalf("Expected 5 child runs, got %d", len(runs))
	}
	if maxObservedConcurrent > 2 {
		t.Errorf("Expected max concurrency 2, observed %d", maxObservedConcurrent)
	}
}

// TestRunMultiAccount_OneAccountFailureDoesNotStopOthers verifies isolation under failure
func TestRunMultiAccount_OneAccountFailureDoesNotStopOthers(t *testing.T) {
	accounts := []*AccountScope{
		{AccountID: "1"}, {AccountID: "2"}, {AccountID: "3"},
	}
	scope := NewCloudCampaignScope(accounts)

	execute := func(acc *AccountScope) *CloudChildRun {
		if acc.AccountID == "2" {
			return &CloudChildRun{Account: acc, Status: "skipped", SkipReason: "discovery failed: timeout"}
		}
		return &CloudChildRun{Account: acc, Status: "completed"}
	}

	runs := RunMultiAccount(scope, execute)

	if len(runs) != 3 {
		t.Fatalf("Expected 3 child runs despite account 2 failing, got %d", len(runs))
	}

	completedCount := 0
	skippedCount := 0
	for _, r := range runs {
		if r.Status == "completed" {
			completedCount++
		}
		if r.Status == "skipped" {
			skippedCount++
		}
	}
	if completedCount != 2 || skippedCount != 1 {
		t.Errorf("Expected 2 completed + 1 skipped, got %d completed + %d skipped", completedCount, skippedCount)
	}
}
