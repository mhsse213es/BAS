package emailgwefficacy

import (
	"fmt"
	"time"
)

// EmailPolicyBaselineExpectation is a declared "this email-security
// policy rule's configuration, and any time-boxed exception on it,
// should look like this" claim -- a claim about gateway-level
// CONFIGURATION STATE over time (email.txt §1.H: "policy precedence,
// stale policies, exceptions, control failures, fail-open behavior"),
// never about one message's delivery fate. Mirrors webgwefficacy's own
// PolicyBaselineExpectation/VerifyPolicyBaselineExpectation precedent
// exactly -- same reasoning, re-implemented independently in this
// package (never imported: see this package's own architecture spec's
// locked decision on zero cross-import with webgwefficacy), using
// THIS package's own EmailGWVerdict vocabulary rather than
// webgwefficacy's Pass/Fail/Unsupported wording.
//
// Distinct from InboxRuleExpectation/OAuthConsentGrantExpectation/
// DelegatedMailboxAccessExpectation (mailboxcompromise.go): those are
// claims about a specific MAILBOX's observed state (was a rule/grant/
// delegation detected); this is a claim about a POLICY RULE's own
// configuration as the gateway reports it, independent of any
// individual mailbox or message.
type EmailPolicyBaselineExpectation struct {
	PolicyRuleID       string     `json:"policyRuleId"`
	ExpectedConfigHash string     `json:"expectedConfigHash"`
	ExceptionExpiresAt *time.Time `json:"exceptionExpiresAt,omitempty"`
	ControlProduct     string     `json:"controlProduct"`
	Note               string     `json:"note,omitempty"`
}

// EmailPolicyConfigEvidence is one normalized record of a policy
// rule's actually-observed configuration state.
type EmailPolicyConfigEvidence struct {
	PolicyRuleID       string         `json:"policyRuleId"`
	ObservedConfigHash string         `json:"observedConfigHash"`
	StillActive        bool           `json:"stillActive"`
	Timestamp          time.Time      `json:"timestamp"`
	Source             EvidenceSource `json:"source"`
	Provenance         Provenance     `json:"provenance"`
}

// EmailPolicyConfigEvidenceProvider supplies policy-configuration
// evidence for a policy rule ID and time window. A returned error
// means collection failed -- distinct from a successful search that
// found nothing (nil error, empty slice).
type EmailPolicyConfigEvidenceProvider interface {
	EmailPolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]EmailPolicyConfigEvidence, error)
}

// FixtureEmailPolicyConfigProvider wraps an in-memory slice of
// hand-built EmailPolicyConfigEvidence values -- no real tenant
// configuration-management API is called in this phase.
type FixtureEmailPolicyConfigProvider struct {
	events []EmailPolicyConfigEvidence
}

func NewFixtureEmailPolicyConfigProvider(events []EmailPolicyConfigEvidence) *FixtureEmailPolicyConfigProvider {
	return &FixtureEmailPolicyConfigProvider{events: events}
}

func (p *FixtureEmailPolicyConfigProvider) EmailPolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]EmailPolicyConfigEvidence, error) {
	var out []EmailPolicyConfigEvidence
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

// VerifyEmailPolicyBaselineExpectation checks one declared policy-
// baseline expectation against evidence, as of asOf. Returns a single
// VerdictDetail, not a full EfficacyResult -- the check is inherently
// single-dimensional (is the policy's own configuration state what it
// should be), the same reasoning VerifyInboxRuleExpectation uses for
// its own single-VerdictDetail return.
//
// A rule whose latest evidence reports StillActive false is
// ConfirmedFailure, independent of the exception-expiry check below
// and regardless of whether ObservedConfigHash still matches
// ExpectedConfigHash -- a disabled rule enforces nothing, and a
// matching hash does not change that.
//
// An expired exception (ExceptionExpiresAt before asOf) that is still
// active in the evidence is configuration drift, flagged as
// ConfirmedFailure regardless of whether the underlying config hash
// otherwise matches -- a stale exception left live past its expiry is
// itself the finding, not something a hash comparison would catch.
//
// asOf is an explicit parameter, never time.Now() read internally, so
// this function stays deterministic and testable.
func VerifyEmailPolicyBaselineExpectation(
	exp EmailPolicyBaselineExpectation,
	provider EmailPolicyConfigEvidenceProvider,
	window TimeWindow,
	asOf time.Time,
) VerdictDetail {
	records, err := provider.EmailPolicyConfigEvidenceFor(exp.PolicyRuleID, window)
	if err != nil {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("policy configuration evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no policy configuration evidence found for this rule in the window; absence of evidence is not proof of either outcome",
		}
	}
	latest := latestByTimestamp(records, func(e EmailPolicyConfigEvidence) time.Time { return e.Timestamp })
	if !latest.StillActive {
		return VerdictDetail{
			Verdict: VerdictConfirmedFailure,
			Reason:  fmt.Sprintf("policy rule %q is disabled in the gateway's own configuration -- a matching config hash does not mean it is enforcing", exp.PolicyRuleID),
		}
	}
	if exp.ExceptionExpiresAt != nil && asOf.After(*exp.ExceptionExpiresAt) {
		return VerdictDetail{
			Verdict: VerdictConfirmedFailure,
			Reason:  fmt.Sprintf("exception on policy rule %q expired at %s but is still active in the gateway's own configuration", exp.PolicyRuleID, exp.ExceptionExpiresAt.Format(time.RFC3339)),
		}
	}
	if latest.ObservedConfigHash != exp.ExpectedConfigHash {
		return VerdictDetail{
			Verdict: VerdictConfirmedFailure,
			Reason:  fmt.Sprintf("observed configuration hash %q did not match expected %q", latest.ObservedConfigHash, exp.ExpectedConfigHash),
		}
	}
	return VerdictDetail{Verdict: VerdictConfirmedSuccess}
}

// antiPhishImpersonationPolicyRuleID/ConfigHash are the synthetic
// fixed identifiers this scenario always uses -- a real rule ID/hash
// from an authorized lab tenant, never a production or customer value.
const (
	antiPhishImpersonationPolicyRuleID = "lab-anti-phish-impersonation-finance-scope"
	antiPhishImpersonationPolicyHash   = "sha256:lab-baseline-config-v1"
)

// AntiPhishImpersonationPolicyBaselineExpectation builds the policy-
// baseline/config-drift scenario: a documented impersonation-
// protection policy, scoped to a finance-department test group, with
// a time-boxed exception (e.g. a temporary allowlist entry created
// during a migration). valid=true is the known-good case: asOf is
// still before the exception's own expiry, and the observed
// configuration matches the documented baseline -- expected
// ConfirmedSuccess. valid=false is the known-bad case: the exception
// has expired but the gateway's own configuration still shows it
// active (stale exception never revoked) -- the specific risk
// email.txt §1.H names under "stale policies"/"exceptions".
func AntiPhishImpersonationPolicyBaselineExpectation(valid bool) EmailPolicyBaselineExpectation {
	exp := EmailPolicyBaselineExpectation{
		PolicyRuleID:       antiPhishImpersonationPolicyRuleID,
		ExpectedConfigHash: antiPhishImpersonationPolicyHash,
		ControlProduct:     "m365-defender-o365",
	}
	now := time.Now()
	if valid {
		future := now.Add(30 * 24 * time.Hour)
		exp.ExceptionExpiresAt = &future
		exp.Note = "documented impersonation-protection policy exception, still within its own time-boxed validity window"
	} else {
		past := now.Add(-30 * 24 * time.Hour)
		exp.ExceptionExpiresAt = &past
		exp.Note = "documented impersonation-protection policy exception, expired 30 days ago but never revoked in the gateway's own configuration -- a stale exception"
	}
	return exp
}
