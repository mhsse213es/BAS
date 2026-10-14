package cloudgraph

import "sync"

// CloudCampaignSummary is the compute-on-read rollup of a cloud campaign across
// accounts. Mirrors the shape of the existing campaign.Summary pattern (same
// Prevented/Detected/Missed/Errored taxonomy), built on CloudControlOutcome
// instead of models.SimulationResult.
type CloudCampaignSummary struct {
	Targets    int
	Dispatched int
	Skipped    int
	Prevented  int // outcome Blocked (control stopped the attack)
	Detected   int // outcome Allowed but flagged by a detection control (not modeled yet; reserved)
	Missed     int // outcome Allowed and not detected - the real gap
	Errored    int // outcome Unknown (evidence unavailable; cannot be scored)
}

// CloudAggregate rolls child runs into a campaign summary. A skipped account
// contributes to Dispatched and Skipped but contributes no outcomes - it never
// zeroes out or excludes other accounts' real results.
func CloudAggregate(runs []*CloudChildRun) *CloudCampaignSummary {
	summary := &CloudCampaignSummary{
		Dispatched: len(runs),
	}
	summary.Targets = summary.Dispatched

	for _, run := range runs {
		if run.Status == "skipped" {
			summary.Skipped++
			continue
		}
		for _, outcome := range run.Outcomes {
			switch outcome.ExecutionOutcome {
			case "Blocked":
				summary.Prevented++
			case "Allowed":
				summary.Missed++
			case "Unknown":
				summary.Errored++
			}
		}
	}

	return summary
}

// RunMultiAccount executes `execute` once per account in scope, bounded by
// scope.MaxConcurrency, and returns every account's CloudChildRun. Each
// account's execution is fully independent: a failure in one account's
// execute call produces a CloudChildRun reflecting that failure (the caller's
// `execute` is responsible for catching its own errors and returning a
// "skipped"/"failed" CloudChildRun rather than letting the goroutine panic).
func RunMultiAccount(scope *CloudCampaignScope, execute func(*AccountScope) *CloudChildRun) []*CloudChildRun {
	results := make([]*CloudChildRun, len(scope.Accounts))
	sem := make(chan struct{}, scope.MaxConcurrency)
	var wg sync.WaitGroup

	for i, acc := range scope.Accounts {
		wg.Add(1)
		go func(idx int, account *AccountScope) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = execute(account)
		}(i, acc)
	}

	wg.Wait()
	return results
}
