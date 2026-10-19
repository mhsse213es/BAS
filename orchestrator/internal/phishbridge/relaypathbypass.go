package phishbridge

import (
	"context"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

// DirectPathExpectation and RelayPathExpectation are PH-EVA-002's two legs.
// The definitions live in emailgwefficacy so the EmailGW dispatch table and
// this bridge share one expectation. The two legs carry the identical attack
// message and differ only in recipient, so each leg's evidence stays distinct.
// PH-EVA-002 is graded on the direct leg; the relay leg is reported as the
// bypass finding (see the API executor), never as a verdict of its own.
func DirectPathExpectation(caught bool) emailgwefficacy.MailExpectation {
	return emailgwefficacy.RelayPathBypassDirectExpectation(caught)
}

// RelayPathExpectation is DirectPathExpectation's sibling for the relay path.
func RelayPathExpectation(caught bool) emailgwefficacy.MailExpectation {
	return emailgwefficacy.RelayPathBypassRelayExpectation(caught)
}

var relayPathBypassContent = emailgwefficacy.InjectableMessage{
	Subject:  "Updated payment instructions",
	BodyHTML: "<p>Please use the new account details below for all future payments.</p>",
}

// Registers PH-EVA-002's test message for the EmailGW executor. Both legs share
// one message class, so one registration covers both.
func init() {
	emailgwefficacy.RegisterScenarioTestContent("relay-path-bypass", relayPathBypassContent)
}

// DispatchRelayPathBypassMessage sends PH-EVA-002's real test message via
// emailgwefficacy.InjectScenarioMessage. Called once per leg (direct, then
// relay), each time pointed at a different real SMTP target.
func DispatchRelayPathBypassMessage(ctx context.Context, target emailgwefficacy.InjectionTarget, exp emailgwefficacy.MailExpectation) (emailgwefficacy.OriginDeliveryObservation, error) {
	return emailgwefficacy.InjectScenarioMessage(ctx, target, exp, relayPathBypassContent)
}
