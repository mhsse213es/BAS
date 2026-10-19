package emailgwefficacy

// RelayPathBypassDirectExpectation is PH-EVA-002's direct-path leg: the spoofed
// sender delivered to the perimeter gateway's own inbound path, which applies
// the full anti-spoofing policy. caught=true is that path's known-good case.
func RelayPathBypassDirectExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "relay-path-bypass",
		Recipient:      "direct-path-test@example-lab.test",
		MessageClass:   "relay-path-bypass",
		ControlProduct: "m365-defender-o365",
		Note:           "delivered directly to the perimeter gateway's own configured inbound path (full anti-spoofing policy applied)",
		EnvelopeFrom:   "payments@relay-path-bypass-lab.test",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}

// RelayPathBypassRelayExpectation is PH-EVA-002's relay-path leg: the same
// attack through a differently-configured internal relay that does not
// re-apply the perimeter's inbound anti-spoofing policy. Only the recipient
// and note differ, so this leg's evidence stays distinct from the direct leg's.
func RelayPathBypassRelayExpectation(caught bool) MailExpectation {
	exp := RelayPathBypassDirectExpectation(caught)
	exp.Recipient = "relay-path-test@example-lab.test"
	exp.Note = "delivered via a differently-configured internal relay path that does not re-apply the perimeter gateway's own inbound anti-spoofing policy"
	return exp
}
