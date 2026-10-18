package dlpcorrelate

import (
	"fmt"

	"github.com/audspect/bas/internal/reporting"
)

// ConsistencyVerdict classifies a set of independently-evaluated channel
// results. Unlike CorrelationChain's ordered stages, these channels have
// no sequence -- the finding that matters is whether they AGREE with
// each other, not whether one happened before another.
type ConsistencyVerdict string

const (
	// ConsistentEnforcement: every channel with informative evidence
	// (Match or Mismatch) enforced correctly.
	ConsistentEnforcement ConsistencyVerdict = "consistent_enforcement"
	// ConsistentFailure: every channel with informative evidence failed
	// to enforce -- a uniform policy gap, not a channel-specific one.
	// Deliberately a different verdict from InconsistentEnforcement: the
	// remediation for "every channel is broken the same way" differs from
	// "channels disagree with each other."
	ConsistentFailure ConsistencyVerdict = "consistent_failure"
	// InconsistentEnforcement: at least one channel enforced correctly
	// and at least one other did not -- the real risk dlp.txt's Campaign
	// 02 names: a successful block on one channel does not protect
	// every channel.
	InconsistentEnforcement ConsistencyVerdict = "inconsistent_enforcement"
	// InsufficientEvidence: no channel produced a Match or Mismatch at
	// all. Never defaulted to ConsistentEnforcement -- an absence of
	// evidence is not a safety claim.
	InsufficientEvidence ConsistencyVerdict = "insufficient_evidence"
)

// ChannelResult is one independently-evaluated channel's already-computed
// enforcement comparison -- the caller obtained Comparison from the real
// live dlpVerifier pipeline (internal/reporting/dlp.go) per scenario step;
// this package never calls that evaluator itself.
type ChannelResult struct {
	Channel    string
	Comparison reporting.ComparisonResult
	Reason     string
}

// ChannelConsistencyResult is the aggregate verdict over N independent
// channel results.
type ChannelConsistencyResult struct {
	ChannelResults []ChannelResult
	Verdict        ConsistencyVerdict
	Reason         string
}

// EvaluateChannelConsistency classifies results into one of the 4
// ConsistencyVerdict values. Only Match/Mismatch comparisons are
// informative; MissingEvidence/NotApplicable/Unknown entries are kept in
// ChannelResults but never move the verdict.
func EvaluateChannelConsistency(results []ChannelResult) (ChannelConsistencyResult, error) {
	if len(results) == 0 {
		return ChannelConsistencyResult{}, fmt.Errorf("no channel results provided -- nothing to assess consistency over")
	}

	matchCount, mismatchCount := 0, 0
	for _, r := range results {
		switch r.Comparison {
		case reporting.Match:
			matchCount++
		case reporting.Mismatch:
			mismatchCount++
		}
	}

	var verdict ConsistencyVerdict
	var reason string
	switch {
	case matchCount > 0 && mismatchCount > 0:
		verdict = InconsistentEnforcement
		reason = fmt.Sprintf("%d of %d informative channels enforced correctly, %d did not -- enforcement is channel-dependent", matchCount, matchCount+mismatchCount, mismatchCount)
	case matchCount > 0:
		verdict = ConsistentEnforcement
		reason = fmt.Sprintf("all %d channel(s) with informative evidence enforced correctly", matchCount)
	case mismatchCount > 0:
		verdict = ConsistentFailure
		reason = fmt.Sprintf("all %d channel(s) with informative evidence failed to enforce -- a uniform policy gap, not channel-specific", mismatchCount)
	default:
		verdict = InsufficientEvidence
		reason = "no channel produced a Match or Mismatch comparison -- cannot assess consistency"
	}

	return ChannelConsistencyResult{
		ChannelResults: append([]ChannelResult{}, results...),
		Verdict:        verdict,
		Reason:         reason,
	}, nil
}

// Campaign02EndpointToCloudLeakage is dlp.txt §3C's Campaign 02:
// "Endpoint-to-cloud leakage" -- place a synthetic confidential file on a
// managed endpoint, attempt controlled USB, browser-upload and
// approved-cloud-transfer variants, compare enforcement across them. This
// function only names the 3 channel variants and delegates to
// EvaluateChannelConsistency; it never calls any real evaluator itself.
//
// dlp.txt's own text also asks to "compare enforcement and telemetry" --
// no telemetry-correlation evidence source exists in this repo today, so
// this closes the enforcement-consistency half only. See
// docs/dlp-mastery-qa-log.md for the named telemetry gap.
func Campaign02EndpointToCloudLeakage(usb, browserUpload, cloudTransfer ChannelResult) (ChannelConsistencyResult, error) {
	return EvaluateChannelConsistency([]ChannelResult{usb, browserUpload, cloudTransfer})
}
