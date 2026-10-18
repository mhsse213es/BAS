package dlppolicy

import (
	"fmt"
	"strings"
	"time"
)

// DLPPolicyRuleRef is one member rule's full standing within a
// precedence evaluation: its priority, its own action if it wins,
// and whether it is currently eligible to be considered at all.
// Eligible is reported as a plain fact here -- enabled, published,
// and in-scope for this evaluation context -- never independently
// re-derived from DLPPolicyScopeDeclaration matching logic.
type DLPPolicyRuleRef struct {
	RuleID         string
	Priority       *int
	ExpectedAction string
	Eligible       bool
}

// DLPPolicyEvaluationContext is the hypothetical data-access attempt
// precedence is evaluated against -- a synthetic identity/location/
// data-type combination, never a real user or real sensitive content.
type DLPPolicyEvaluationContext struct {
	UserOrGroup string
	Location    string
	DataType    string
	Note        string
}

// DLPPolicyPrecedenceExpectation is one declared "across these
// candidate rules, for this context, this one should win and do
// this" claim.
type DLPPolicyPrecedenceExpectation struct {
	ScopeID                 ScopeID                    `json:"scopeId"`
	Context                 DLPPolicyEvaluationContext `json:"context"`
	CandidateRules          []DLPPolicyRuleRef         `json:"candidateRules"`
	ExpectedWinningRuleID   string                     `json:"expectedWinningRuleId"`
	ExpectedEffectiveAction string                     `json:"expectedEffectiveAction"`
	OverrideJustification   string                     `json:"overrideJustification,omitempty"`
	ControlProduct          string                     `json:"controlProduct"`
	Note                    string                     `json:"note,omitempty"`
}

// DLPPolicyPrecedenceEvidence is one normalized record of which rule
// actually won, and what action it took, for a scope/context.
type DLPPolicyPrecedenceEvidence struct {
	ScopeID                 ScopeID                    `json:"scopeId"`
	Context                 DLPPolicyEvaluationContext `json:"context"`
	ObservedWinningRuleID   string                     `json:"observedWinningRuleId"`
	ObservedEffectiveAction string                     `json:"observedEffectiveAction"`
	Timestamp               time.Time                  `json:"timestamp"`
	Source                  EvidenceSource             `json:"source"`
	Provenance              Provenance                 `json:"provenance"`
}

// DLPPolicyPrecedenceEvidenceProvider supplies precedence-resolution
// evidence for a scope, evaluation context, and time window.
type DLPPolicyPrecedenceEvidenceProvider interface {
	DLPPolicyPrecedenceEvidenceFor(scope ScopeID, context DLPPolicyEvaluationContext, window TimeWindow) ([]DLPPolicyPrecedenceEvidence, error)
}

// FixtureDLPPolicyPrecedenceProvider wraps an in-memory slice of
// hand-built DLPPolicyPrecedenceEvidence values -- no real vendor
// policy-simulation API is called in this slice.
type FixtureDLPPolicyPrecedenceProvider struct {
	events []DLPPolicyPrecedenceEvidence
}

func NewFixtureDLPPolicyPrecedenceProvider(events []DLPPolicyPrecedenceEvidence) *FixtureDLPPolicyPrecedenceProvider {
	return &FixtureDLPPolicyPrecedenceProvider{events: events}
}

func (p *FixtureDLPPolicyPrecedenceProvider) DLPPolicyPrecedenceEvidenceFor(scope ScopeID, context DLPPolicyEvaluationContext, window TimeWindow) ([]DLPPolicyPrecedenceEvidence, error) {
	var out []DLPPolicyPrecedenceEvidence
	for _, e := range p.events {
		if e.ScopeID != scope || e.Context != context {
			continue
		}
		if e.Timestamp.Before(window.Start) || e.Timestamp.After(window.End) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// resolveExpectedWinner computes, from a candidate set's own declared
// priorities and eligibility, which rule the expectation's own data
// implies should win, and whether the set is genuinely ambiguous (two
// or more eligible candidates tied at the lowest priority value) or
// indeterminate (no eligible candidate, or an eligible candidate with
// no declared priority at all). This never reasons about a REAL
// vendor's behavior -- it only checks that the expectation's own
// candidate set is internally self-consistent.
func resolveExpectedWinner(candidates []DLPPolicyRuleRef) (winnerID string, ambiguous bool, indeterminate bool) {
	var eligible []DLPPolicyRuleRef
	for _, c := range candidates {
		if c.Eligible {
			eligible = append(eligible, c)
		}
	}
	if len(eligible) == 0 {
		return "", false, true
	}
	for _, c := range eligible {
		if c.Priority == nil {
			return "", false, true
		}
	}

	min := *eligible[0].Priority
	for _, c := range eligible[1:] {
		if *c.Priority < min {
			min = *c.Priority
		}
	}

	var atMin []DLPPolicyRuleRef
	for _, c := range eligible {
		if *c.Priority == min {
			atMin = append(atMin, c)
		}
	}
	if len(atMin) == 1 {
		return atMin[0].RuleID, false, false
	}
	return "", true, false
}

// VerifyDLPPolicyPrecedenceExpectation checks one declared precedence
// expectation against evidence. Unlike VerifyDLPPolicyRuleExpectation,
// it has no asOf parameter -- precedence has no time-based expiry
// concept of its own; only window bounds evidence relevance.
func VerifyDLPPolicyPrecedenceExpectation(exp DLPPolicyPrecedenceExpectation, provider DLPPolicyPrecedenceEvidenceProvider, window TimeWindow) VerdictDetail {
	expectedCandidate, found := findRuleRef(exp.CandidateRules, exp.ExpectedWinningRuleID)
	if !found {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: "expected winning rule is not among the declared candidates"}
	}
	if !expectedCandidate.Eligible {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: "expected winner is marked ineligible (disabled/unpublished/out of scope); an ineligible rule cannot win"}
	}

	winnerID, ambiguous, indeterminate := resolveExpectedWinner(exp.CandidateRules)
	if indeterminate {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: "one or more eligible candidates have no declared priority (or none are eligible); precedence cannot be determined"}
	}
	if !ambiguous && strings.TrimSpace(exp.OverrideJustification) == "" && winnerID != exp.ExpectedWinningRuleID {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: "declared expected winner contradicts the candidate rules' own priorities; set OverrideJustification if this is an intentional override, or correct the expectation"}
	}

	records, err := provider.DLPPolicyPrecedenceEvidenceFor(exp.ScopeID, exp.Context, window)
	if err != nil {
		return withTieNote(ambiguous, VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("precedence evidence collection failed: %v", err)})
	}
	if len(records) == 0 {
		return withTieNote(ambiguous, VerdictDetail{Verdict: VerdictInconclusive, Reason: "no precedence evidence found for this context in the window"})
	}
	latest := latestPrecedenceEvidenceByTimestamp(records)

	if _, ok := findRuleRef(exp.CandidateRules, latest.ObservedWinningRuleID); !ok {
		return withTieNote(ambiguous, VerdictDetail{Verdict: VerdictInconclusive, Reason: "the vendor reported a winning rule that was not among the declared candidates; the candidate list may be incomplete"})
	}
	if latest.ObservedWinningRuleID != exp.ExpectedWinningRuleID {
		return withTieNote(ambiguous, VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: fmt.Sprintf("expected rule %q to take precedence for this context, %q won instead", exp.ExpectedWinningRuleID, latest.ObservedWinningRuleID)})
	}
	if latest.ObservedEffectiveAction != exp.ExpectedEffectiveAction {
		return withTieNote(ambiguous, VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: "the expected rule won, but its own effective action did not match"})
	}
	return withTieNote(ambiguous, VerdictDetail{Verdict: VerdictConfirmedSuccess})
}

func findRuleRef(candidates []DLPPolicyRuleRef, ruleID string) (DLPPolicyRuleRef, bool) {
	for _, c := range candidates {
		if c.RuleID == ruleID {
			return c, true
		}
	}
	return DLPPolicyRuleRef{}, false
}

func latestPrecedenceEvidenceByTimestamp(records []DLPPolicyPrecedenceEvidence) DLPPolicyPrecedenceEvidence {
	latest := records[0]
	for _, r := range records[1:] {
		if r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}
	return latest
}

// withTieNote appends an informational suffix to v.Reason when
// ambiguous is true -- a genuine priority tie means the expected
// winner reflects an assumed, not derivable, tie-break, regardless of
// which verdict is ultimately reached.
func withTieNote(ambiguous bool, v VerdictDetail) VerdictDetail {
	if !ambiguous {
		return v
	}
	note := "candidate rules declare a genuine priority tie; the expected winner reflects an assumed, not derivable, tie-break"
	if v.Reason == "" {
		v.Reason = fmt.Sprintf("(note: %s)", note)
	} else {
		v.Reason = fmt.Sprintf("%s (note: %s)", v.Reason, note)
	}
	return v
}
