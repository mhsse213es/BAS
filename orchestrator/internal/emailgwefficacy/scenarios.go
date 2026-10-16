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

// EICARAttachmentExpectation builds the area-C attachment/content-
// inspection scenario: a message carrying the industry-standard
// EICAR test string as its attachment -- never a real malware
// sample, per emailGW.txt §1.C's own named constraint. caught=true is
// the known-good case (the gateway's attachment inspection catches
// it); caught=false is the known-bad case (the same attachment
// delivered uninspected).
func EICARAttachmentExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "known-bad-malware-attachment",
		Recipient:      "helpdesk-test@example-lab.test",
		MessageClass:   "eicar-attachment",
		ControlProduct: "m365-defender-o365",
		Note:           "industry-standard EICAR test string as the attachment -- never a real malware sample",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}

// URLRewriteExpectation builds the area-D URL/post-delivery-
// protection scenario: whether a URL was rewritten for click-time
// inspection. knownBad=true is a malicious/unknown-reputation URL
// (known-bad case, expected to be rewritten); knownBad=false is a
// benign URL (known-good/false-positive case, expected to be
// delivered unrewritten). Distinct from CredentialHarvestingURLExpectation,
// which tests whether a social-engineering lure is caught at all, not
// whether a URL was technically rewritten.
func URLRewriteExpectation(knownBad bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "known-bad-url-reputation",
		Recipient:      "helpdesk-test@example-lab.test",
		ControlProduct: "m365-defender-o365",
	}
	if knownBad {
		exp.MessageClass = "url-known-bad-reputation"
		exp.ExpectedAction = ExpectedRewrite
		exp.Note = "synthetic URL with an unknown/bad reputation, hosted in the authorized lab -- expected to be rewritten for click-time inspection"
	} else {
		exp.MessageClass = "url-benign-reputation"
		exp.ExpectedAction = ExpectedDeliver
		exp.Note = "synthetic benign URL -- no rewriting needed, the false-positive/legitimate-mail case"
	}
	return exp
}

// OutboundDLPExpectation builds the area-E outbound-security/DLP
// scenario: an outbound message to an external recipient, carrying a
// synthetic data marker -- never real sensitive data, matching
// internal/cloudsink's own synthetic-marker discipline for DLP
// scenarios. sensitive=true is the known-bad case (a synthetic
// sensitive-data marker, expected to be quarantined before it leaves
// the organization); sensitive=false is the known-good/false-positive
// case (ordinary outbound mail, expected to be delivered).
func OutboundDLPExpectation(sensitive bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "internal-finance-user",
		Recipient:      "external-partner-test@external-lab.test",
		ControlProduct: "m365-defender-o365",
	}
	if sensitive {
		exp.MessageClass = "outbound-dlp-sensitive-marker"
		exp.ExpectedAction = ExpectedQuarantine
		exp.Note = "synthetic sensitive-data marker in the message body -- never real sensitive data; expected to be blocked before leaving the organization"
	} else {
		exp.MessageClass = "outbound-ordinary-mail"
		exp.ExpectedAction = ExpectedDeliver
		exp.Note = "ordinary outbound mail with no sensitive-data marker -- the false-positive/legitimate-mail case"
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

// ExecutiveImpersonationExpectation builds the EG-002 area-B scenario:
// a message sent from a freemail address that itself can legitimately
// PASS SPF/DKIM/DMARC for its own domain, with its display name
// forged to impersonate a company executive. This exercises the
// gateway's impersonation-protection policy specifically --
// deliberately independent of, and never conflated with,
// SPFAlignmentExpectation/DKIMAlignmentExpectation/DMARCPolicyExpectation,
// which test sender-authentication alignment on the message's OWN
// domain, a different control entirely. caught=true is the known-good
// case (impersonation protection catches the forged display name);
// caught=false is the known-bad case (the same message delivered
// uninspected).
func ExecutiveImpersonationExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "freemail-exec-display-name-impersonation",
		Recipient:      "finance-test@example-lab.test",
		MessageClass:   "executive-impersonation",
		ControlProduct: "m365-defender-o365",
		Note:           "synthetic freemail sender, itself SPF/DKIM/DMARC-aligned, with a display name forged to impersonate a company executive -- tests impersonation-protection policy, not sender authentication",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}

// SupplierPaymentDiversionExpectation builds the EG-005 area-B
// scenario: a message from a lookalike or newly-registered vendor
// domain (not the real supplier's own domain, and not impersonating
// an internal executive) requesting a change to bank/payment details
// against an existing invoice. This exercises domain-reputation and
// newly-observed-domain heuristics -- distinct from
// ExecutiveImpersonationExpectation (an internal persona, forged via
// a freemail display name) and from the SPF/DKIM/DMARC scenarios
// (which test the message's OWN domain authentication, not its
// similarity to a known, trusted vendor domain). caught=true is the
// known-good case (domain-reputation/heuristic protection catches it);
// caught=false is the known-bad case (the same message delivered
// uninspected).
func SupplierPaymentDiversionExpectation(caught bool) MailExpectation {
	exp := MailExpectation{
		SenderProfile:  "lookalike-vendor-domain-payment-redirect",
		Recipient:      "accounts-payable-test@example-lab.test",
		MessageClass:   "supplier-payment-diversion",
		ControlProduct: "m365-defender-o365",
		Note:           "synthetic lookalike/newly-registered vendor domain (not the real supplier's own domain) requesting a bank-detail change against an existing invoice -- tests domain-reputation/newly-observed-domain heuristics, not sender authentication or internal-persona impersonation",
	}
	if caught {
		exp.ExpectedAction = ExpectedQuarantine
	} else {
		exp.ExpectedAction = ExpectedDeliver
	}
	return exp
}

// AuthenticationExceptionScopeExpectation builds the EG-009 area-A
// scenario: a documented mail-flow exception that bypasses normal
// authentication/spam inspection for messages genuinely verified as
// originating from a specific trusted source (e.g. a connector keyed
// on source IP, used for a known partner or internal relay).
//
// scoped=true is the known-good case: a message that genuinely
// originates from the exception's real, verified trusted source (not
// merely claiming to) -- expected to bypass inspection and deliver,
// proving the documented exception does not break the legitimate mail
// flow it exists for.
//
// scoped=false is the known-bad case: a message that spoofs ONLY the
// exception's spoofable trigger condition (e.g. envelope-from
// claiming the excepted domain) without meeting its real verification
// condition -- expected to be caught by normal enforcement, exactly
// like any other unauthenticated spoof. A ConfirmedFailure on this
// branch is the specific risk EG-009 names: the exception's
// scope-check keyed on a spoofable attribute alone, creating an
// unintended trust path.
//
// Reuses MailExpectation/EnforcementEvidence/VerifyMailExpectation
// unchanged, the same Phase-4-established reasoning C/D/E used for
// EICAR/URL-rewrite/outbound-DLP: this is still "one message, one
// expected delivery action," so no new type family is needed here,
// unlike area F's inboxrule.go (a mailbox CONFIGURATION STATE, not a
// message) -- confirmed before writing this scenario, not assumed.
func AuthenticationExceptionScopeExpectation(scoped bool) MailExpectation {
	exp := MailExpectation{
		Recipient:      "finance-test@example-lab.test",
		ControlProduct: "m365-defender-o365",
	}
	if scoped {
		exp.SenderProfile = "trusted-relay-exception-genuine-use"
		exp.MessageClass = "auth-exception-genuine-use"
		exp.ExpectedAction = ExpectedDeliver
		exp.Note = "message genuinely originates from the exception's real, verified trusted source -- expected to bypass normal inspection and deliver, proving the documented exception does not break the legitimate mail flow it exists for"
	} else {
		exp.SenderProfile = "spoofed-exception-trigger-outside-real-scope"
		exp.MessageClass = "auth-exception-scope-probe"
		exp.ExpectedAction = ExpectedQuarantine
		exp.Note = "message spoofs only the exception's spoofable trigger condition without meeting its real verification condition -- expected to be caught by normal enforcement; a ConfirmedFailure here means the exception's scope-check keys on a spoofable attribute alone, an unintended trust path"
	}
	return exp
}
