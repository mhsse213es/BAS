package phishbridge

import (
	"context"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

// ReplyChainHijackExpectation builds PH-BEC-006's MailExpectation: a
// message framed as a reply within an existing conversation thread
// (Subject starting with "Re:", body quoting the prior message),
// envelope-from an account presented as already compromised (paired
// conceptually with PH-AUTH-010's own compromise-detection evidence,
// never duplicating it here).
//
// Honest scope limit, named rather than hidden: this tests whether
// the SAME domain-reputation/sender-authentication control already
// proven for PH-AUTH-010/PH-BEC-002 catches a reply-framed message --
// it does NOT test genuine thread-history-aware content anomaly
// detection (comparing this reply against the real prior thread's own
// content/participants), because no such capability exists anywhere
// in this codebase to evaluate against. Building real RFC 5322
// In-Reply-To/References threading headers would need a new field on
// exercise.TestMessage/buildSpoofableMIME, which this package does
// not add -- exercise is one of the locked, wrapped engines this
// initiative never modifies. caught=true is the known-good case;
// caught=false is the known-bad case.
func ReplyChainHijackExpectation(caught bool) emailgwefficacy.MailExpectation {
	return emailgwefficacy.ReplyChainHijackExpectation(caught)
}

// replyChainHijackContent is this scenario's own test message content.
// The Subject's "Re:" prefix and the quoted-reply body are the
// reply-chain narrative's own markers -- real RFC 5322 In-Reply-To/
// References headers are not set, see ReplyChainHijackExpectation's
// own doc comment for why.
var replyChainHijackContent = emailgwefficacy.InjectableMessage{
	Subject: "Re: Q3 budget review",
	BodyHTML: "<p>Following up on our earlier thread -- can you resend the updated figures to the account below before end of day?</p>" +
		"<blockquote>On the original thread: \"Attaching the Q3 budget draft for your review, let me know if anything looks off.\"</blockquote>",
}

// DispatchReplyChainHijack sends PH-BEC-006's real test message via
// emailgwefficacy.InjectScenarioMessage.
func DispatchReplyChainHijack(ctx context.Context, target emailgwefficacy.InjectionTarget, exp emailgwefficacy.MailExpectation) (emailgwefficacy.OriginDeliveryObservation, error) {
	return emailgwefficacy.InjectScenarioMessage(ctx, target, exp, replyChainHijackContent)
}

// Registers PH-BEC-006's reply-chain message for the EmailGW executor. The
// message has no attachment, so nothing can fail to build here.
func init() {
	emailgwefficacy.RegisterScenarioTestContent("reply-chain-hijack", replyChainHijackContent)
}
