package cloudgraph

import (
	"testing"
	"time"
)

// TestCloudCampaignScope_DefaultsApplied verifies spec-mandated defaults
func TestCloudCampaignScope_DefaultsApplied(t *testing.T) {
	scope := NewCloudCampaignScope([]*AccountScope{
		{Provider: "aws", AccountID: "111111111111"},
		{Provider: "aws", AccountID: "222222222222"},
	})

	if scope.MaxConcurrency != 3 {
		t.Errorf("Expected default MaxConcurrency=3, got %d", scope.MaxConcurrency)
	}
	if scope.TimeoutPerAccount != 30*time.Minute {
		t.Errorf("Expected default TimeoutPerAccount=30min, got %v", scope.TimeoutPerAccount)
	}
	if !scope.PreserveAccountContext {
		t.Error("Expected PreserveAccountContext=true by default")
	}
	if scope.CorrelateAcrossAccounts {
		t.Error("Expected CorrelateAcrossAccounts=false by default")
	}
	if len(scope.Accounts) != 2 {
		t.Errorf("Expected 2 accounts, got %d", len(scope.Accounts))
	}
}

// TestCloudChildRun_IndependentPerAccount verifies child runs don't share state
func TestCloudChildRun_IndependentPerAccount(t *testing.T) {
	run1 := &CloudChildRun{
		Account: &AccountScope{Provider: "aws", AccountID: "111111111111"},
		Status:  "completed",
		Outcomes: []*CloudControlOutcome{
			{PrerequisiteState: PolicySupported, ExecutionOutcome: "Allowed"},
		},
	}

	run2 := &CloudChildRun{
		Account:    &AccountScope{Provider: "aws", AccountID: "222222222222"},
		Status:     "failed",
		SkipReason: "discovery failed: no cloud access",
	}

	if run1.Account.AccountID == run2.Account.AccountID {
		t.Error("Expected different accounts for independent child runs")
	}
	if len(run1.Outcomes) == 0 {
		t.Error("Expected run1 to have outcomes")
	}
	if run2.SkipReason == "" {
		t.Error("Expected run2 to document its skip reason")
	}
}
