package emailgwefficacy

// InternalSenderSpoofExpectation builds the internal-sender-spoof MailExpectation
// (PH-AUTH-007's email leg): a synthetic internal-looking sender delivered over
// an externally-originated HELO/relay connection. caught=true is the known-good
// case (the gateway quarantines the spoofed sender); caught=false is the known-bad case.
func InternalSenderSpoofExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "internal-sender-helo-spoof",
		Recipient:      "helpdesk-test@example-lab.test",
		MessageClass:   "internal-sender-helo-spoof",
		ControlProduct: "m365-defender-o365",
		Note:           "synthetic internal-looking envelope/header-from claim delivered over an externally-originated HELO/relay connection -- tests internal-sender-spoofing (anti-spoofing policy on HELO/connecting-IP vs. claimed domain), distinct from external domain spoofing (SPF/DKIM/DMARC alignment) and from display-name impersonation",
		EnvelopeFrom:   "it-helpdesk@internal-corp-lab.test",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}
