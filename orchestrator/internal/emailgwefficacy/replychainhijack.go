package emailgwefficacy

// ReplyChainHijackExpectation builds the reply-chain-hijack MailExpectation
// (PH-BEC-006's email leg): a message framed as a reply within an existing thread.
// caught=true is the known-good case (the gateway quarantines it); caught=false is the known-bad case.
func ReplyChainHijackExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "reply-chain-hijack",
		Recipient:      "finance-test@example-lab.test",
		MessageClass:   "reply-chain-hijack",
		ControlProduct: "m365-defender-o365",
		Note:           "message framed as a reply within an existing thread (Subject starting with Re:, quoted prior content), envelope-from an account presented as compromised -- tests the same domain-reputation/compromise-detection control PH-AUTH-010 proves, under a reply-chain narrative; does not test genuine thread-history-aware content anomaly detection, which no capability in this codebase provides",
		EnvelopeFrom:   "accounts@reply-chain-hijack-lab.test",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}
