package webgwefficacy

import (
	"fmt"
	"time"
)

// PolicyBaselineExpectation is a declared "this policy rule's
// configuration, and whether any time-boxed exception on it, should
// look like this" claim -- a claim about configuration STATE over
// time, never a per-request decision.
type PolicyBaselineExpectation struct {
	PolicyRuleID       string     `json:"policyRuleId"`
	ExpectedConfigHash string     `json:"expectedConfigHash"`
	ExceptionExpiresAt *time.Time `json:"exceptionExpiresAt,omitempty"`
	ControlProduct     string     `json:"controlProduct"`
	Note               string     `json:"note,omitempty"`
}

// PolicyConfigEvidence is one normalized record of a policy rule's
// actually-observed configuration state.
type PolicyConfigEvidence struct {
	PolicyRuleID       string         `json:"policyRuleId"`
	ObservedConfigHash string         `json:"observedConfigHash"`
	StillActive        bool           `json:"stillActive"`
	Timestamp          time.Time      `json:"timestamp"`
	Source             EvidenceSource `json:"source"`
}

// PolicyConfigEvidenceProvider supplies policy-configuration evidence
// for a policy rule ID and time window.
type PolicyConfigEvidenceProvider interface {
	PolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]PolicyConfigEvidence, error)
}

// FixturePolicyConfigProvider wraps an in-memory slice of hand-built
// PolicyConfigEvidence values -- no real configuration-management API
// is called in this phase.
type FixturePolicyConfigProvider struct {
	events []PolicyConfigEvidence
}

func NewFixturePolicyConfigProvider(events []PolicyConfigEvidence) *FixturePolicyConfigProvider {
	return &FixturePolicyConfigProvider{events: events}
}

func (p *FixturePolicyConfigProvider) PolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]PolicyConfigEvidence, error) {
	var out []PolicyConfigEvidence
	for _, e := range p.events {
		if e.PolicyRuleID != policyRuleID {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyPolicyBaselineExpectation checks one declared policy-baseline
// expectation against evidence, as of asOf.
//
// A rule whose latest evidence reports StillActive false is Fail,
// independent of the exception-expiry check below and regardless of
// whether ObservedConfigHash still matches ExpectedConfigHash --
// configHashFor only hashes a rule's action/filters/traffic, never
// its enabled flag, so a rule disabled in the gateway's own console
// with everything else untouched would otherwise produce an
// identical hash and a false Pass. A disabled rule enforces nothing,
// and a matching hash does not change that.
//
// An expired exception (ExceptionExpiresAt before asOf) that is still
// active in the evidence is configuration drift, flagged as Fail
// regardless of whether the underlying config hash otherwise matches
// -- a stale exception left live past its expiry is itself the
// finding, not something a hash comparison would catch. By the time
// this check runs, StillActive is already known true (the check
// above returned otherwise), so this condition no longer needs to
// test it itself.
//
// asOf is an explicit parameter, never time.Now() read internally, so
// this function stays deterministic and testable.
func VerifyPolicyBaselineExpectation(
	exp PolicyBaselineExpectation,
	provider PolicyConfigEvidenceProvider,
	window TimeWindow,
	asOf time.Time,
) VerdictDetail {
	records, err := provider.PolicyConfigEvidenceFor(exp.PolicyRuleID, window)
	if err != nil {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("policy configuration evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no policy configuration evidence found for this rule in the window",
		}
	}
	latest := latestByTimestamp(records, func(e PolicyConfigEvidence) time.Time { return e.Timestamp })
	if !latest.StillActive {
		return VerdictDetail{
			Verdict: VerdictFail,
			Reason:  fmt.Sprintf("policy rule %q is disabled in the gateway's own configuration -- a matching config hash does not mean it is enforcing", exp.PolicyRuleID),
		}
	}
	if exp.ExceptionExpiresAt != nil && asOf.After(*exp.ExceptionExpiresAt) {
		return VerdictDetail{
			Verdict: VerdictFail,
			Reason:  fmt.Sprintf("exception on policy rule %q expired at %s but is still active in the gateway's own configuration", exp.PolicyRuleID, exp.ExceptionExpiresAt.Format(time.RFC3339)),
		}
	}
	if latest.ObservedConfigHash != exp.ExpectedConfigHash {
		return VerdictDetail{
			Verdict: VerdictFail,
			Reason:  fmt.Sprintf("observed configuration hash %q did not match expected %q", latest.ObservedConfigHash, exp.ExpectedConfigHash),
		}
	}
	return VerdictDetail{Verdict: VerdictPass}
}
