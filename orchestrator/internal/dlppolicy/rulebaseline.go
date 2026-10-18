package dlppolicy

import (
	"fmt"
	"strings"
	"time"
)

// DLPPolicyRuleExpectation is one declared "this rule's own
// configuration should look like this" claim -- a claim about a
// single rule's configuration state in a single declared scope,
// never about a real exfiltration attempt's fate.
type DLPPolicyRuleExpectation struct {
	RuleID              string
	ScopeID             ScopeID
	Scope               DLPPolicyScopeDeclaration
	ExpectedMode        DLPPolicyMode
	ExpectedEnabled     bool
	ExpectedPublished   bool
	RuleExpiresAt       *time.Time
	ExceptionExpiresAt  *time.Time
	MaxPropagationDelay time.Duration
	ControlProduct      string
	Note                string
}

// DLPPolicyRuleEvidence is one normalized record of a rule's
// actually-observed configuration state in one scope.
type DLPPolicyRuleEvidence struct {
	RuleID          string
	ScopeID         ScopeID
	ObservedScope   DLPPolicyScopeDeclaration
	ObservedMode    DLPPolicyMode
	Enabled         bool
	Published       bool
	ExceptionActive bool
	ConfigChangedAt time.Time
	LastSyncedAt    time.Time
	Timestamp       time.Time
	Source          EvidenceSource
	Provenance      Provenance
}

// DLPPolicyRuleEvidenceProvider supplies policy-configuration
// evidence for a rule ID, scope, and time window. A returned error
// means collection failed -- distinct from a successful search that
// found nothing (nil error, empty slice).
type DLPPolicyRuleEvidenceProvider interface {
	DLPPolicyRuleEvidenceFor(ruleID string, scope ScopeID, window TimeWindow) ([]DLPPolicyRuleEvidence, error)
}

// FixtureDLPPolicyRuleProvider wraps an in-memory slice of hand-built
// DLPPolicyRuleEvidence values -- no real vendor configuration-
// management API is called in this slice.
type FixtureDLPPolicyRuleProvider struct {
	events []DLPPolicyRuleEvidence
}

func NewFixtureDLPPolicyRuleProvider(events []DLPPolicyRuleEvidence) *FixtureDLPPolicyRuleProvider {
	return &FixtureDLPPolicyRuleProvider{events: events}
}

func (p *FixtureDLPPolicyRuleProvider) DLPPolicyRuleEvidenceFor(ruleID string, scope ScopeID, window TimeWindow) ([]DLPPolicyRuleEvidence, error) {
	var out []DLPPolicyRuleEvidence
	for _, e := range p.events {
		if e.RuleID != ruleID || e.ScopeID != scope {
			continue
		}
		if e.Timestamp.Before(window.Start) || e.Timestamp.After(window.End) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyDLPPolicyRuleExpectation checks one declared rule-level
// expectation against evidence, as of asOf. asOf is an explicit
// parameter, never time.Now() read internally, so this function stays
// deterministic and testable -- same discipline as
// emailgwefficacy.VerifyEmailPolicyBaselineExpectation.
func VerifyDLPPolicyRuleExpectation(exp DLPPolicyRuleExpectation, provider DLPPolicyRuleEvidenceProvider, window TimeWindow, asOf time.Time) VerdictDetail {
	records, err := provider.DLPPolicyRuleEvidenceFor(exp.RuleID, exp.ScopeID, window)
	if err != nil {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("policy configuration evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: "no policy configuration evidence found for this rule/scope in the window"}
	}
	latest := latestRuleEvidenceByTimestamp(records)

	if exp.ExpectedEnabled && !latest.Enabled {
		return VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: "rule is disabled"}
	}
	if exp.ExpectedPublished && !latest.Published {
		return VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: "rule not published/deployed to this scope"}
	}
	if exp.RuleExpiresAt != nil && asOf.After(*exp.RuleExpiresAt) {
		return VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: "rule expired but still active"}
	}
	if exp.ExceptionExpiresAt != nil && asOf.After(*exp.ExceptionExpiresAt) && latest.ExceptionActive {
		return VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: "exception expired but still active"}
	}
	if latest.ObservedMode != exp.ExpectedMode {
		return VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: fmt.Sprintf("expected mode %q, observed %q", exp.ExpectedMode, latest.ObservedMode)}
	}
	if mismatch := scopeMismatch(exp.Scope, latest.ObservedScope); mismatch != "" {
		return VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: mismatch}
	}
	if exp.ExceptionExpiresAt == nil && latest.ExceptionActive {
		return VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: "exception active but not declared/expected on this rule in this scope"}
	}
	if exp.MaxPropagationDelay > 0 {
		lag := latest.ConfigChangedAt.Sub(latest.LastSyncedAt)
		if lag > exp.MaxPropagationDelay {
			return VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: "stale endpoint configuration, propagation delay exceeded"}
		}
	}
	return VerdictDetail{Verdict: VerdictConfirmedSuccess}
}

func latestRuleEvidenceByTimestamp(records []DLPPolicyRuleEvidence) DLPPolicyRuleEvidence {
	latest := records[0]
	for _, r := range records[1:] {
		if r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}
	return latest
}

// scopeMismatch compares every field of a DLPPolicyScopeDeclaration as
// a set (order-independent; nil and an empty slice compare equal) and
// returns an empty string when all fields match, or a reason naming
// every mismatched field otherwise.
func scopeMismatch(expected, observed DLPPolicyScopeDeclaration) string {
	var mismatched []string
	check := func(name string, exp, obs []string) {
		if !setsEqual(exp, obs) {
			mismatched = append(mismatched, name)
		}
	}
	check("IncludedLocations", expected.IncludedLocations, observed.IncludedLocations)
	check("ExcludedLocations", expected.ExcludedLocations, observed.ExcludedLocations)
	check("IncludedUsers", expected.IncludedUsers, observed.IncludedUsers)
	check("ExcludedUsers", expected.ExcludedUsers, observed.ExcludedUsers)
	check("IncludedDevices", expected.IncludedDevices, observed.IncludedDevices)
	check("ExcludedDevices", expected.ExcludedDevices, observed.ExcludedDevices)
	check("IncludedGroups", expected.IncludedGroups, observed.IncludedGroups)
	check("ExcludedGroups", expected.ExcludedGroups, observed.ExcludedGroups)
	if len(mismatched) == 0 {
		return ""
	}
	return fmt.Sprintf("scope mismatch in field(s): %s", strings.Join(mismatched, ", "))
}

func setsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; !ok {
			return false
		}
	}
	return true
}
