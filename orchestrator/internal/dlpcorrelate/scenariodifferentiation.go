package dlpcorrelate

import (
	"fmt"

	"github.com/audspect/bas/internal/reporting"
)

// DifferentiationVerdict classifies a set of independently-evaluated
// scenario cases by whether the system correctly tells legitimate cases
// apart from illegitimate ones. Unlike ChannelConsistency (which asks
// whether N channels agree with each other) or CorrelationChain (an
// ordered sequence), each case here has its OWN expected direction --
// agreement between cases is not the question.
type DifferentiationVerdict string

const (
	// DifferentiatesCorrectly: every case with informative evidence
	// matched its own expected direction.
	DifferentiatesCorrectly DifferentiationVerdict = "differentiates_correctly"
	// OverBlocking: at least one legitimate case (ExpectedToSucceed) was
	// blocked -- a false positive, operational friction, not a safety
	// success.
	OverBlocking DifferentiationVerdict = "over_blocking"
	// UnderBlocking: at least one illegitimate case got through -- the
	// real-risk finding.
	UnderBlocking DifferentiationVerdict = "under_blocking"
	// MixedDifferentiationFailure: both OverBlocking and UnderBlocking
	// conditions are present at once. Deliberately a distinct verdict --
	// never silently collapsed into just one of the two.
	MixedDifferentiationFailure DifferentiationVerdict = "mixed_differentiation_failure"
	// DifferentiationInsufficientEvidence: no case produced a Match or
	// Mismatch at all. Never defaulted to DifferentiatesCorrectly.
	DifferentiationInsufficientEvidence DifferentiationVerdict = "insufficient_evidence"
)

// ScenarioCase is one independently-evaluated case's already-computed
// enforcement comparison, plus the caller's own ExpectedToSucceed flag
// encoding the scenario's design intent (what SHOULD happen) -- never
// inferred from the observation itself.
type ScenarioCase struct {
	Label             string
	ExpectedToSucceed bool
	Comparison        reporting.ComparisonResult
	Reason            string
}

// ScenarioDifferentiationResult is the aggregate verdict over N
// independent scenario cases.
type ScenarioDifferentiationResult struct {
	Cases   []ScenarioCase
	Verdict DifferentiationVerdict
	Reason  string
}

// EvaluateScenarioDifferentiation classifies cases into one of the 5
// DifferentiationVerdict values. Only Match/Mismatch comparisons are
// informative; MissingEvidence/NotApplicable/Unknown entries are kept in
// Cases but never move the verdict.
func EvaluateScenarioDifferentiation(cases []ScenarioCase) (ScenarioDifferentiationResult, error) {
	if len(cases) == 0 {
		return ScenarioDifferentiationResult{}, fmt.Errorf("no scenario cases provided -- nothing to assess differentiation over")
	}

	matchCount, overBlockCount, underBlockCount := 0, 0, 0
	for _, c := range cases {
		switch c.Comparison {
		case reporting.Match:
			matchCount++
		case reporting.Mismatch:
			if c.ExpectedToSucceed {
				overBlockCount++
			} else {
				underBlockCount++
			}
		}
	}

	var verdict DifferentiationVerdict
	var reason string
	switch {
	case overBlockCount > 0 && underBlockCount > 0:
		verdict = MixedDifferentiationFailure
		reason = fmt.Sprintf("%d legitimate case(s) over-blocked and %d illegitimate case(s) under-blocked -- both failure directions present", overBlockCount, underBlockCount)
	case overBlockCount > 0:
		verdict = OverBlocking
		reason = fmt.Sprintf("%d legitimate case(s) were blocked -- false positive(s), operational friction", overBlockCount)
	case underBlockCount > 0:
		verdict = UnderBlocking
		reason = fmt.Sprintf("%d illegitimate case(s) got through -- false negative(s), a real data-loss risk", underBlockCount)
	case matchCount > 0:
		verdict = DifferentiatesCorrectly
		reason = fmt.Sprintf("all %d case(s) with informative evidence matched their own expected direction", matchCount)
	default:
		verdict = DifferentiationInsufficientEvidence
		reason = "no case produced a Match or Mismatch comparison -- cannot assess differentiation"
	}

	return ScenarioDifferentiationResult{
		Cases:   append([]ScenarioCase{}, cases...),
		Verdict: verdict,
		Reason:  reason,
	}, nil
}

// Campaign03EmailPolicyAndExceptionFailure is dlp.txt §3C's Campaign 03:
// "Email policy and exception failure" -- send synthetic sensitive
// content through normal delivery, a justified override, and
// unauthorized sharing; verify the system differentiates correctly
// rather than uniformly blocking or uniformly allowing. normalDelivery
// and justifiedOverride are both ExpectedToSucceed=true (ordinary
// business use and an authorized exception both ought to succeed);
// unauthorizedSharing is ExpectedToSucceed=false.
//
// dlp.txt's own text also asks to "verify actual mail disposition and
// policy audit evidence" -- this is closed by reusing the existing
// reporting.ComparisonResult and reporting.DLPEvidence.Override evidence
// already produced by the live dlpVerifier pipeline; no new evidence
// source is built here. This function never calls that evaluator
// itself -- the caller already ran it.
func Campaign03EmailPolicyAndExceptionFailure(normalDelivery, justifiedOverride, unauthorizedSharing ScenarioCase) (ScenarioDifferentiationResult, error) {
	return EvaluateScenarioDifferentiation([]ScenarioCase{normalDelivery, justifiedOverride, unauthorizedSharing})
}
