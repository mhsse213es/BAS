package emailgwefficacy

// Phase 3a scenario builders (docs/superpowers/specs/2026-10-15-
// emailgw-mastery-phase3-first-real-vertical-design.md §1). Pure data,
// no I/O -- each pairs a known-good case with a known-bad case, per
// emailGW.txt's own quality bar (a harness that can't prove both a
// pass and a fail is not yet trustworthy). Every SenderProfile/
// Recipient here is a fabricated, synthetic identity -- never a real
// customer, partner, or brand domain (§2.3 condition #4).

// SPFAlignmentExpectation builds the area-A SPF scenario. pass=true is
// the known-good case (an aligned sender, expected to be delivered);
// pass=false is the known-bad case (a spoofed envelope-from with no
// matching SPF record, expected to be quarantined).
func SPFAlignmentExpectation(pass bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "spoofed-exec-display-name",
		Recipient:      "finance-test@example-lab.test",
		ControlProduct: "m365-defender-o365",
	}
	if pass {
		exp.MessageClass = "spf-pass"
		exp.ExpectedAction = ExpectedDeliver
		exp.Note = "synthetic sender with an SPF record that aligns with the envelope-from domain"
	} else {
		exp.MessageClass = "spf-fail"
		exp.ExpectedAction = ExpectedQuarantine
		exp.Note = "synthetic sender spoofing an envelope-from domain with no matching SPF record"
	}
	return exp
}

// DKIMAlignmentExpectation builds the area-A DKIM scenario. pass=true
// is a validly signed message (known-good, expected delivery);
// pass=false is an unsigned (or invalidly signed) message claiming
// the same sender identity (known-bad, expected quarantine).
func DKIMAlignmentExpectation(pass bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "spoofed-exec-display-name",
		Recipient:      "finance-test@example-lab.test",
		ControlProduct: "m365-defender-o365",
	}
	if pass {
		exp.MessageClass = "dkim-pass"
		exp.ExpectedAction = ExpectedDeliver
		exp.Note = "message signed with a DKIM key published in the sending domain's DNS"
	} else {
		exp.MessageClass = "dkim-fail"
		exp.ExpectedAction = ExpectedQuarantine
		exp.Note = "unsigned message claiming a sender identity whose domain publishes a DKIM record"
	}
	return exp
}

// DMARCPolicyExpectation builds the area-A DMARC-alignment scenario.
// aligned=true is a message whose From-header domain aligns with its
// SPF/DKIM-authenticated domain (known-good, expected delivery);
// aligned=false is a message with a misaligned From-header domain
// against a sending domain publishing a DMARC p=reject/quarantine
// policy (known-bad, expected rejection).
func DMARCPolicyExpectation(aligned bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "spoofed-exec-display-name",
		Recipient:      "finance-test@example-lab.test",
		ControlProduct: "m365-defender-o365",
	}
	if aligned {
		exp.MessageClass = "dmarc-aligned"
		exp.ExpectedAction = ExpectedDeliver
		exp.Note = "From-header domain aligns with the SPF/DKIM-authenticated domain"
	} else {
		exp.MessageClass = "dmarc-misaligned"
		exp.ExpectedAction = ExpectedReject
		exp.Note = "From-header domain misaligned against a sending domain publishing DMARC p=reject"
	}
	return exp
}

// CredentialHarvestingURLExpectation builds the area-B phishing
// scenario: a message containing a synthetic, non-functional
// lookalike-login URL. The URL is never a real, working
// credential-capture page -- only a declared, inert test fixture
// (§2.3 condition #4). caught=true is the known-good case (the
// gateway's URL/content inspection catches it); caught=false is the
// known-bad case (the same URL delivered uninspected).
func CredentialHarvestingURLExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "known-bad-lookalike-login",
		Recipient:      "helpdesk-test@example-lab.test",
		MessageClass:   "credential-harvesting-url",
		ControlProduct: "m365-defender-o365",
		Note:           "synthetic, non-functional lookalike login URL hosted in the authorized lab -- never a real credential-capture page",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}
