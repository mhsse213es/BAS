package phishbridge

import (
	"context"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

// DirectPathExpectation and RelayPathExpectation encode the IDENTICAL
// spoofed-sender attack message (same SenderProfile, MessageClass,
// EnvelopeFrom) -- the only thing PH-EVA-002 needs to prove is that
// the SAME attack reaches two differently-configured endpoints
// differently. Recipient differs between the two so each path's own
// evidence (keyed by MessageRef) never collides with the other's in a
// fixture provider.
//
// This is the second, differently-configured real gateway the
// earlier overlap note said didn't exist: DispatchRelayPathBypassMessage
// performs a REAL, independent SMTP round trip to whichever
// target.TargetMX the caller points it at, so a test proves two
// genuinely separate deliveries (to two separate local SMTP test
// servers), not one dispatch re-labeled twice. The verified
// ENFORCEMENT OUTCOME per path still comes from fixture evidence --
// the same tier every other CoverageAdapterTested scenario in this
// catalog uses for enforcement claims absent a live vendor tenant --
// but the dispatch mechanics themselves are real and genuinely
// independent per path. caught=true is the known-good case for that
// path (the path's own configured policy catches it); caught=false is
// the known-bad case.
func DirectPathExpectation(caught bool) emailgwefficacy.MailExpectation {
	exp := emailgwefficacy.MailExpectation{
		SenderProfile:  "relay-path-bypass",
		Recipient:      "direct-path-test@example-lab.test",
		MessageClass:   "relay-path-bypass",
		ControlProduct: "m365-defender-o365",
		Note:           "delivered directly to the perimeter gateway's own configured inbound path (full anti-spoofing policy applied)",
		EnvelopeFrom:   "payments@relay-path-bypass-lab.test",
	}
	if caught {
		exp.ExpectedAction = emailgwefficacy.ExpectedQuarantine
	} else {
		exp.ExpectedAction = emailgwefficacy.ExpectedDeliver
	}
	return exp
}

// RelayPathExpectation is DirectPathExpectation's own sibling for the
// alternate, differently-configured relay path -- same attack, same
// sender, a different Recipient only so its evidence stays distinct.
func RelayPathExpectation(caught bool) emailgwefficacy.MailExpectation {
	exp := DirectPathExpectation(caught)
	exp.Recipient = "relay-path-test@example-lab.test"
	exp.Note = "delivered via a differently-configured internal relay path that does not re-apply the perimeter gateway's own inbound anti-spoofing policy"
	return exp
}

var relayPathBypassContent = emailgwefficacy.InjectableMessage{
	Subject:  "Updated payment instructions",
	BodyHTML: "<p>Please use the new account details below for all future payments.</p>",
}

// DispatchRelayPathBypassMessage sends PH-EVA-002's real test message
// via emailgwefficacy.InjectScenarioMessage. Called once per path
// (direct, then relay), each time pointed at a different real SMTP
// target -- the caller, not this function, supplies the second,
// differently-configured endpoint.
func DispatchRelayPathBypassMessage(ctx context.Context, target emailgwefficacy.InjectionTarget, exp emailgwefficacy.MailExpectation) (emailgwefficacy.OriginDeliveryObservation, error) {
	return emailgwefficacy.InjectScenarioMessage(ctx, target, exp, relayPathBypassContent)
}
