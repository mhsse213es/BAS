package emailgwefficacy

// Real message injection, wiring exercise.SpoofableSMTPInjector into
// this package's own scenario builders -- the sender-side half of
// observation-model item 3 (OriginDeliveryObservation), previously
// built (2026-10-15, docs/superpowers/specs/2026-10-15-emailgw-
// mastery-phase3-first-real-vertical-design.md §2) and never actually
// called from anywhere in this package until now.
//
// Not every scenario is wired: an expectation with an empty
// EnvelopeFrom (checked, never silently skipped) is a deliberate
// signal that this scenario's known-good or known-bad direction needs
// a capability this package doesn't have yet. As of this file:
//   - SPFAlignmentExpectation(true)/DMARCPolicyExpectation(true) need
//     a lab domain whose published SPF record actually authorizes
//     Audspect's own sending IP -- infrastructure, not code.
//   - DKIMAlignmentExpectation(true) needs real DKIM signing;
//     SpoofableSMTPInjector has no signing capability.
//   - EICARAttachmentExpectation (either direction) needs a MIME
//     attachment; SpoofableSMTPInjector only builds a single-part
//     HTML body.
//   - OutboundDLPExpectation (either direction) is an authenticated-
//     internal-sender scenario (mail leaving the org), not an
//     externally-spoofable one -- a structurally different mechanism
//     (e.g. Microsoft Graph sendMail under Mail.Send) would be
//     needed, not this injector.
//   - AuthenticationExceptionScopeExpectation(true) needs to send
//     from infrastructure the exception's own verification condition
//     actually trusts (e.g. a real trusted-relay IP).
//
// Each scenario builder's own Note documents its specific reason;
// this is the summary.

import (
	"context"
	"fmt"

	"github.com/audspect/bas/internal/exercise"
)

// InjectableMessage is the content a scenario's own test message
// needs, beyond the sender-identity fields MailExpectation already
// carries (EnvelopeFrom/HeaderFrom) -- intentionally minimal, mirrors
// exercise.TestMessage.
type InjectableMessage struct {
	Subject  string
	BodyHTML string
}

// InjectionTarget is the gateway-under-test's own delivery target --
// the same for every scenario in one assessment, supplied once by the
// caller. MailExpectation only declares WHAT identity to send as,
// never WHERE the customer's gateway is -- that would duplicate the
// same infrastructure detail into every scenario builder for no
// benefit.
type InjectionTarget struct {
	HELODomain string
	TargetMX   string
	RelayHost  string
}

// scenarioTestContent is the generic, synthetic message content for
// every MessageClass this package currently has EnvelopeFrom wired
// for. Returns ok=false for any other MessageClass -- a caller must
// never silently send empty content for a scenario this function
// doesn't know about.
var scenarioTestContent = map[string]InjectableMessage{
	"spf-fail":                      {Subject: "Urgent: wire approval needed", BodyHTML: "<p>Please approve the attached wire transfer before end of day.</p>"},
	"dkim-fail":                     {Subject: "Urgent: wire approval needed", BodyHTML: "<p>Please approve the attached wire transfer before end of day.</p>"},
	"dmarc-misaligned":              {Subject: "Invoice payment update", BodyHTML: "<p>Our banking details have changed, please update your records before the next payment.</p>"},
	"url-known-bad-reputation":      {Subject: "Your password is expiring soon", BodyHTML: `<p>Please <a href="http://lookalike-login-lab.test/reset">verify your account</a> before it expires.</p>`},
	"url-benign-reputation":         {Subject: "Team meeting notes", BodyHTML: `<p>See the shared notes at <a href="http://known-good-url-lab.test/notes">this link</a>.</p>`},
	"credential-harvesting-url":     {Subject: "Your mailbox storage is full", BodyHTML: `<p>Sign in at <a href="http://lookalike-login-lab.test/login">this portal</a> to restore access.</p>`},
	"executive-impersonation":       {Subject: "Quick favor, are you available?", BodyHTML: "<p>I need you to handle a confidential wire transfer today, let me know when you're free.</p>"},
	"supplier-payment-diversion":    {Subject: "Updated banking details for invoice #4471", BodyHTML: "<p>Please update our banking details before processing the next payment.</p>"},
	"auth-exception-scope-probe":    {Subject: "Internal notice", BodyHTML: "<p>This message claims the exception's trusted identity without meeting its real verification condition.</p>"},
	"post-delivery-threat-response": {Subject: "Shared document ready for review", BodyHTML: `<p>Review the shared document at <a href="http://threat-response-lab.test/doc">this link</a>.</p>`},
}

// ScenarioTestContent returns the InjectableMessage content for exp's
// own MessageClass, and whether one exists -- a lookup, not a
// fallback: a MessageClass with no entry here must never be sent with
// invented or empty content.
func ScenarioTestContent(exp MailExpectation) (InjectableMessage, bool) {
	content, ok := scenarioTestContent[exp.MessageClass]
	return content, ok
}

// InjectScenarioMessage sends exp's own test message for real,
// through target, via exercise.SpoofableSMTPInjector, and returns the
// sender-side half of OriginDeliveryObservation. It never inspects or
// infers the receiving system's outcome -- that remains strictly a
// MailEvidenceProvider's job, per OriginDeliveryObservation's own
// two-independent-legs discipline (types.go).
//
// Returns an error, never a silent no-op, when exp.EnvelopeFrom is
// empty -- the deliberate "not wired for real injection" signal this
// file's own package comment documents.
func InjectScenarioMessage(ctx context.Context, target InjectionTarget, exp MailExpectation, content InjectableMessage) (OriginDeliveryObservation, error) {
	if exp.EnvelopeFrom == "" {
		return OriginDeliveryObservation{}, fmt.Errorf("InjectScenarioMessage: %s has no EnvelopeFrom set -- not wired for real injection, see %s's own Note", exp.MessageClass, exp.MessageClass)
	}

	injector := &exercise.SpoofableSMTPInjector{
		EnvelopeFrom: exp.EnvelopeFrom,
		HeaderFrom:   exp.HeaderFrom,
		HELODomain:   target.HELODomain,
		TargetMX:     target.TargetMX,
		RelayHost:    target.RelayHost,
	}
	leg, err := injector.SendTestMessage(ctx, exercise.TestMessage{
		To:       exp.Recipient,
		Subject:  content.Subject,
		BodyHTML: content.BodyHTML,
	})
	if err != nil {
		return OriginDeliveryObservation{}, fmt.Errorf("InjectScenarioMessage: %w", err)
	}

	return OriginDeliveryObservation{
		SenderPayloadHash: leg.SenderPayloadHash,
		Timestamp:         leg.Timestamp,
	}, nil
}
