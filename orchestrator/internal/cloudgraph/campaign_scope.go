package cloudgraph

import "time"

// CloudCampaignScope defines which accounts a cloud campaign targets and how
// it isolates and bounds execution across them. Campaign scope is distinct
// from scenario scope: scenarios are provider/account-agnostic; campaigns
// apply a scenario to a set of accounts.
type CloudCampaignScope struct {
	Accounts                []*AccountScope
	MaxConcurrency          int
	TimeoutPerAccount       time.Duration
	PreserveAccountContext  bool
	CorrelateAcrossAccounts bool
}

// NewCloudCampaignScope builds a scope with spec-mandated defaults:
// MaxConcurrency=3, TimeoutPerAccount=30min, PreserveAccountContext=true,
// CorrelateAcrossAccounts=false.
func NewCloudCampaignScope(accounts []*AccountScope) *CloudCampaignScope {
	return &CloudCampaignScope{
		Accounts:                accounts,
		MaxConcurrency:          3,
		TimeoutPerAccount:       30 * time.Minute,
		PreserveAccountContext:  true,
		CorrelateAcrossAccounts: false,
	}
}

// CloudChildRun is one account's independent execution within a campaign:
// its own discovery, prerequisite check, execution, and evidence, isolated
// from every other account's child run.
type CloudChildRun struct {
	Account    *AccountScope
	Status     string // "running", "completed", "partial", "failed", "skipped"
	Outcomes   []*CloudControlOutcome
	SkipReason string // populated when Status == "skipped" (e.g. discovery failed)
}
