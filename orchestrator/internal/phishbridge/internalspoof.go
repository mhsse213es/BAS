package phishbridge

import (
	"context"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

// InternalSenderSpoofExpectation builds the MailExpectation for
// PH-AUTH-007 (internal sender spoofing): a message whose
// envelope/header claims an internal identity but is delivered over
// an externally-originated HELO/relay connection -- the real-world
// mechanism internal-sender-spoofing protections (anti-spoofing
// policies keyed on HELO/connecting-IP vs. claimed domain) actually
// catch. This is a genuine capability closure, not a parallel engine:
// MailExpectation is a plain, exported emailgwefficacy struct, and
// InjectScenarioMessage/VerifyMailExpectation are both already
// generic, exported entry points that never consult
// emailgwefficacy's own private scenarioTestContent map -- a caller
// outside that package can supply its own InjectableMessage content
// directly, which is exactly what DispatchInternalSenderSpoof below
// does. Zero lines of emailgwefficacy itself change.
//
// Distinct from PH-AUTH-001 (external domain spoofing, caught by
// SPF/DKIM/DMARC alignment on the message's OWN claimed domain) and
// PH-AUTH-005/PH-BEC-001 (display-name impersonation, a freemail
// envelope with a forged internal-looking display name): this
// scenario's envelope domain IS the real internal-looking domain --
// what it fakes is the connection's own origin (HELO identity),
// which SPF/DKIM/DMARC alignment checks don't evaluate at all.
func InternalSenderSpoofExpectation(caught bool) emailgwefficacy.MailExpectation {
	return emailgwefficacy.InternalSenderSpoofExpectation(caught)
}

// internalSenderSpoofContent is this scenario's own test message --
// phishbridge's own content, never added to emailgwefficacy's private
// scenarioTestContent map, because InjectScenarioMessage takes content
// as a parameter and never looks that map up itself.
var internalSenderSpoofContent = emailgwefficacy.InjectableMessage{
	Subject:  "IT Support: password reset required",
	BodyHTML: "<p>Please reset your password immediately using the internal portal.</p>",
}

// DispatchInternalSenderSpoof sends PH-AUTH-007's real test message
// via emailgwefficacy.InjectScenarioMessage. target.HELODomain is what
// simulates the spoofing: a HELO identity claiming to be (or routed
// through) the internal mail infrastructure, while exp.EnvelopeFrom
// is the internal-looking address the message claims to be from.
func DispatchInternalSenderSpoof(ctx context.Context, target emailgwefficacy.InjectionTarget, exp emailgwefficacy.MailExpectation) (emailgwefficacy.OriginDeliveryObservation, error) {
	return emailgwefficacy.InjectScenarioMessage(ctx, target, exp, internalSenderSpoofContent)
}

// Registers PH-AUTH-007's test message for the EmailGW executor. The message
// has no attachment, so nothing can fail to build here.
func init() {
	emailgwefficacy.RegisterScenarioTestContent("internal-sender-helo-spoof", internalSenderSpoofContent)
}
