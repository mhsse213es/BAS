package emailgwefficacy

import (
	"fmt"
	"time"
)

// This file is area F's second and third capability additions
// (email.txt §1.E/§1.H: "OAuth consent abuse, application
// permissions... delegated access" / "mailbox persistence"), the two
// sub-capabilities this package's own architecture spec explicitly
// names as unbuilt alongside InboxRuleExpectation's own "suspicious
// inbox rules/forwarding" leg (inboxrule.go): "Mailbox
// delegation/OAuth-consent... remain unbuilt." Both are declared
// claims about a specific MAILBOX/IDENTITY's observed state --
// mirrors InboxRuleExpectation's own shape (expectation / evidence /
// provider / fixture / single-VerdictDetail verify) exactly, since
// each is still inherently single-dimensional: was the suspicious
// grant/delegation actually detected.

// OAuthConsentGrantExpectation is a declared claim about whether a
// specific, synthetic OAuth application consent grant -- over-
// permissioned relative to the test user's actual role -- was
// detected by the tenant's consent-governance/risk telemetry.
type OAuthConsentGrantExpectation struct {
	UserPrincipal    string   `json:"userPrincipal"`
	AppDisplayName   string   `json:"appDisplayName"`
	RequestedScopes  []string `json:"requestedScopes"`
	ExpectedDetected bool     `json:"expectedDetected"`
	ControlProduct   string   `json:"controlProduct"`
	Note             string   `json:"note,omitempty"`
}

// OAuthConsentGrantEvidence is one normalized record of whether a
// suspicious OAuth consent grant was actually detected, however it
// was obtained (e.g. Microsoft Graph's own risky-application/consent
// audit signals).
type OAuthConsentGrantEvidence struct {
	UserPrincipal   string         `json:"userPrincipal"`
	AppDisplayName  string         `json:"appDisplayName"`
	GrantDetected   bool           `json:"grantDetected"`
	DetectionSource string         `json:"detectionSource,omitempty"` // e.g. "Entra ID risk detection", "audit log"
	Timestamp       time.Time      `json:"timestamp"`
	Source          EvidenceSource `json:"source"`
	Provenance      Provenance     `json:"provenance"`
}

// OAuthConsentGrantEvidenceProvider supplies OAuth-consent-grant
// detection evidence for a user principal and time window. A returned
// error means collection failed -- distinct from a successful search
// that found nothing (nil error, empty slice).
type OAuthConsentGrantEvidenceProvider interface {
	OAuthConsentGrantEvidenceFor(userPrincipal string, window TimeWindow) ([]OAuthConsentGrantEvidence, error)
}

// FixtureOAuthConsentGrantProvider wraps an in-memory slice of
// hand-built OAuthConsentGrantEvidence values -- no real tenant
// consent-governance/audit API is called in this phase.
type FixtureOAuthConsentGrantProvider struct {
	events []OAuthConsentGrantEvidence
}

func NewFixtureOAuthConsentGrantProvider(events []OAuthConsentGrantEvidence) *FixtureOAuthConsentGrantProvider {
	return &FixtureOAuthConsentGrantProvider{events: events}
}

func (p *FixtureOAuthConsentGrantProvider) OAuthConsentGrantEvidenceFor(userPrincipal string, window TimeWindow) ([]OAuthConsentGrantEvidence, error) {
	var out []OAuthConsentGrantEvidence
	for _, e := range p.events {
		if e.UserPrincipal != userPrincipal {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyOAuthConsentGrantExpectation checks one declared expectation
// against OAuth-consent-grant detection evidence. A collection error
// or an empty result both yield Inconclusive, never an assumed
// verdict -- absence of evidence is not proof the grant went
// undetected, or that it was detected.
func VerifyOAuthConsentGrantExpectation(exp OAuthConsentGrantExpectation, provider OAuthConsentGrantEvidenceProvider, window TimeWindow) VerdictDetail {
	records, err := provider.OAuthConsentGrantEvidenceFor(exp.UserPrincipal, window)
	if err != nil {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  fmt.Sprintf("OAuth consent-grant evidence collection failed: %v", err),
		}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no OAuth consent-grant evidence found for this user in the window; absence of evidence is not proof of either outcome",
		}
	}
	latest := latestByTimestamp(records, func(e OAuthConsentGrantEvidence) time.Time { return e.Timestamp })
	if latest.GrantDetected == exp.ExpectedDetected {
		return VerdictDetail{Verdict: VerdictConfirmedSuccess}
	}
	return VerdictDetail{
		Verdict: VerdictConfirmedFailure,
		Reason: fmt.Sprintf("consent-grant detection %t did not match expected %t for user %q",
			latest.GrantDetected, exp.ExpectedDetected, exp.UserPrincipal),
	}
}

// SuspiciousOAuthConsentGrantExpectation builds the scenario: a
// synthetic, over-permissioned third-party app (requesting
// Mail.Read/Mail.Send against a test user with no legitimate business
// need for either) consents against a lab user, which tenant
// consent-governance/risk telemetry should detect and flag.
// detected=true is the known-good case (the grant is created and
// detected); detected=false is the known-bad case (the same grant
// created but undetected).
func SuspiciousOAuthConsentGrantExpectation(detected bool) OAuthConsentGrantExpectation {
	return OAuthConsentGrantExpectation{
		UserPrincipal:    "helpdesk-test@example-lab.test",
		AppDisplayName:   "lab-test-over-permissioned-app",
		RequestedScopes:  []string{"Mail.Read", "Mail.Send"},
		ExpectedDetected: detected,
		ControlProduct:   "m365-defender-o365",
		Note:             "synthetic, over-permissioned OAuth app consent granted in an authorized lab tenant -- never a real customer or production grant",
	}
}

// DelegatedMailboxAccessExpectation is a declared claim about whether
// a specific, synthetic delegated-access grant on a test mailbox
// (e.g. Full Access or Send As, delegated to an identity with no
// legitimate business need for it) was detected by tenant security
// telemetry.
type DelegatedMailboxAccessExpectation struct {
	Mailbox          string `json:"mailbox"`
	DelegateIdentity string `json:"delegateIdentity"`
	AccessType       string `json:"accessType"` // e.g. "FullAccess", "SendAs"
	ExpectedDetected bool   `json:"expectedDetected"`
	ControlProduct   string `json:"controlProduct"`
	Note             string `json:"note,omitempty"`
}

// DelegatedMailboxAccessEvidence is one normalized record of whether
// a suspicious delegated-access grant was actually detected.
type DelegatedMailboxAccessEvidence struct {
	Mailbox         string         `json:"mailbox"`
	GrantDetected   bool           `json:"grantDetected"`
	DetectionSource string         `json:"detectionSource,omitempty"`
	Timestamp       time.Time      `json:"timestamp"`
	Source          EvidenceSource `json:"source"`
	Provenance      Provenance     `json:"provenance"`
}

// DelegatedMailboxAccessEvidenceProvider supplies delegated-access
// detection evidence for a mailbox and time window.
type DelegatedMailboxAccessEvidenceProvider interface {
	DelegatedMailboxAccessEvidenceFor(mailbox string, window TimeWindow) ([]DelegatedMailboxAccessEvidence, error)
}

// FixtureDelegatedMailboxAccessProvider wraps an in-memory slice of
// hand-built DelegatedMailboxAccessEvidence values -- no real tenant
// audit-log/alert API is called in this phase.
type FixtureDelegatedMailboxAccessProvider struct {
	events []DelegatedMailboxAccessEvidence
}

func NewFixtureDelegatedMailboxAccessProvider(events []DelegatedMailboxAccessEvidence) *FixtureDelegatedMailboxAccessProvider {
	return &FixtureDelegatedMailboxAccessProvider{events: events}
}

func (p *FixtureDelegatedMailboxAccessProvider) DelegatedMailboxAccessEvidenceFor(mailbox string, window TimeWindow) ([]DelegatedMailboxAccessEvidence, error) {
	var out []DelegatedMailboxAccessEvidence
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

// VerifyDelegatedMailboxAccessExpectation checks one declared
// expectation against delegated-access detection evidence. A
// collection error or an empty result both yield Inconclusive, never
// an assumed verdict.
func VerifyDelegatedMailboxAccessExpectation(exp DelegatedMailboxAccessExpectation, provider DelegatedMailboxAccessEvidenceProvider, window TimeWindow) VerdictDetail {
	records, err := provider.DelegatedMailboxAccessEvidenceFor(exp.Mailbox, window)
	if err != nil {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  fmt.Sprintf("delegated-access evidence collection failed: %v", err),
		}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no delegated-access evidence found for this mailbox in the window; absence of evidence is not proof of either outcome",
		}
	}
	latest := latestByTimestamp(records, func(e DelegatedMailboxAccessEvidence) time.Time { return e.Timestamp })
	if latest.GrantDetected == exp.ExpectedDetected {
		return VerdictDetail{Verdict: VerdictConfirmedSuccess}
	}
	return VerdictDetail{
		Verdict: VerdictConfirmedFailure,
		Reason: fmt.Sprintf("delegated-access detection %t did not match expected %t for mailbox %q",
			latest.GrantDetected, exp.ExpectedDetected, exp.Mailbox),
	}
}

// SuspiciousDelegatedMailboxAccessExpectation builds the scenario: a
// synthetic Full Access delegation grant on a lab mailbox, delegated
// to an identity with no legitimate business need for it, which
// tenant security telemetry should detect and flag. detected=true is
// the known-good case; detected=false is the known-bad case.
func SuspiciousDelegatedMailboxAccessExpectation(detected bool) DelegatedMailboxAccessExpectation {
	return DelegatedMailboxAccessExpectation{
		Mailbox:          "helpdesk-test@example-lab.test",
		DelegateIdentity: "lab-test-unexpected-delegate@example-lab.test",
		AccessType:       "FullAccess",
		ExpectedDetected: detected,
		ControlProduct:   "m365-defender-o365",
		Note:             "synthetic Full Access delegation granted in an authorized lab tenant, to an identity with no legitimate business need for it -- never a real customer or production grant",
	}
}
