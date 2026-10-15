package emailgwefficacy

import (
	"fmt"
	"time"
)

// InboxRuleExpectation is area F's first capability (emailGW.txt
// §1.F's "suspicious inbox rules, forwarding changes" bullet, the
// tenant-level sub-capability the Phase 3 implementation spec's own
// Scope Refinement already flagged as new -- outlook-rules-bec.yaml
// covers only the endpoint leg). Unlike MailExpectation, this is a
// declared claim about a mailbox's CONFIGURATION STATE (was a
// suspicious rule created and detected), never about one message's
// delivery fate -- mirrors webgwefficacy's PolicyBaselineExpectation/
// DNSQueryExpectation precedent of giving a genuinely
// different-shaped check its own small type family rather than
// stretching MailExpectation to mean something it doesn't.
type InboxRuleExpectation struct {
	Mailbox          string `json:"mailbox"`
	RuleDescription  string `json:"ruleDescription"` // e.g. "auto-forward to external domain"
	ExpectedDetected bool   `json:"expectedDetected"`
	ControlProduct   string `json:"controlProduct"`
	Note             string `json:"note,omitempty"`
}

// InboxRuleEvidence is one normalized record of whether a suspicious
// mailbox rule was actually detected, however it was obtained.
type InboxRuleEvidence struct {
	Mailbox         string         `json:"mailbox"`
	RuleDetected    bool           `json:"ruleDetected"`
	DetectionSource string         `json:"detectionSource,omitempty"` // e.g. "Defender alert", "audit log"
	Timestamp       time.Time      `json:"timestamp"`
	Source          EvidenceSource `json:"source"`
	Provenance      Provenance     `json:"provenance"`
}

// InboxRuleEvidenceProvider supplies inbox-rule detection evidence
// for a mailbox and time window. A returned error means collection
// failed -- distinct from a successful search that found nothing
// (nil error, empty slice).
type InboxRuleEvidenceProvider interface {
	InboxRuleEvidenceFor(mailbox string, window TimeWindow) ([]InboxRuleEvidence, error)
}

// FixtureInboxRuleProvider wraps an in-memory slice of hand-built
// InboxRuleEvidence values -- no real tenant audit-log/alert API is
// called in this phase.
type FixtureInboxRuleProvider struct {
	events []InboxRuleEvidence
}

func NewFixtureInboxRuleProvider(events []InboxRuleEvidence) *FixtureInboxRuleProvider {
	return &FixtureInboxRuleProvider{events: events}
}

func (p *FixtureInboxRuleProvider) InboxRuleEvidenceFor(mailbox string, window TimeWindow) ([]InboxRuleEvidence, error) {
	var out []InboxRuleEvidence
	for _, e := range p.events {
		if e.Mailbox != mailbox {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyInboxRuleExpectation checks one declared expectation against
// inbox-rule detection evidence. Returns a single VerdictDetail, not
// a full EfficacyResult -- the check is inherently single-dimensional
// (was the rule detected or not), the same reasoning
// webgwefficacy.VerifyDNSQueryExpectation used for its own
// single-VerdictDetail return. A collection error or an empty result
// both yield Inconclusive, never an assumed verdict -- absence of
// evidence is not proof the rule went undetected, or that it was
// detected.
func VerifyInboxRuleExpectation(exp InboxRuleExpectation, provider InboxRuleEvidenceProvider, window TimeWindow) VerdictDetail {
	records, err := provider.InboxRuleEvidenceFor(exp.Mailbox, window)
	if err != nil {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  fmt.Sprintf("inbox-rule evidence collection failed: %v", err),
		}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no inbox-rule evidence found for this mailbox in the window; absence of evidence is not proof of either outcome",
		}
	}

	latest := latestByTimestamp(records, func(e InboxRuleEvidence) time.Time { return e.Timestamp })
	if latest.RuleDetected == exp.ExpectedDetected {
		return VerdictDetail{Verdict: VerdictConfirmedSuccess}
	}
	return VerdictDetail{
		Verdict: VerdictConfirmedFailure,
		Reason: fmt.Sprintf("rule detection %t did not match expected %t for mailbox %q",
			latest.RuleDetected, exp.ExpectedDetected, exp.Mailbox),
	}
}

// SuspiciousAutoForwardExpectation builds area F's first scenario: a
// synthetic auto-forward-to-external-domain rule created in a test
// mailbox, which tenant security should detect and alert on.
// detected=true is the known-good case (the rule is created and the
// tenant's security telemetry detects it); detected=false is the
// known-bad case (the same rule created but undetected).
func SuspiciousAutoForwardExpectation(detected bool) InboxRuleExpectation {
	return InboxRuleExpectation{
		Mailbox:          "helpdesk-test@example-lab.test",
		RuleDescription:  "auto-forward to an external, synthetic test domain",
		ExpectedDetected: detected,
		ControlProduct:   "m365-defender-o365",
		Note:             "synthetic inbox rule created in an authorized lab mailbox -- never a real customer or production mailbox",
	}
}
