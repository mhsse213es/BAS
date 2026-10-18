package dlppolicy

import "time"

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
