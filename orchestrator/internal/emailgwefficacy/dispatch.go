package emailgwefficacy

// ExpectationByID resolves one of EmailGWScenarioRegistry's own
// expectation IDs back to the concrete MailExpectation that produces
// it -- the one lookup a real run dispatcher needs and the registry
// itself never provided (ExpectationIDs there are classification
// labels only, consumed by ClassifyScenarioMaturity against already-
// collected ScenarioExecutionRecords, never resolved back to a
// callable builder). This is that missing production lookup; until
// now it only existed ad hoc, duplicated, inside
// maturity_live_test.go's own test tables.
//
// EG-007 is deliberately absent: it is not a MailExpectation at all
// (SuspiciousAutoForwardExpectation, a mailbox-rule check with its own
// InboxRuleEvidenceProvider family, not SMTP injection) -- looking it
// up here must fail, not silently return an empty, wrong value.
//
// EG-008.known-good/EG-008.known-bad resolve to the identical
// MailExpectation, and so do EG-010.detection/EG-010.response: unlike
// every other scenario, PostDeliveryThreatResponseExpectation takes
// no bool, because its "good" or "bad" outcome is decided by
// Defender's own post-delivery verdict, not by which message Audspect
// chose to send. Running any one of those four IDs performs the exact
// same real injection as the other three.
var expectationByID = map[string]MailExpectation{
	"EG-001.spf.known-good":   SPFAlignmentExpectation(true),
	"EG-001.spf.known-bad":    SPFAlignmentExpectation(false),
	"EG-001.dkim.known-good":  DKIMAlignmentExpectation(true),
	"EG-001.dkim.known-bad":   DKIMAlignmentExpectation(false),
	"EG-001.dmarc.known-good": DMARCPolicyExpectation(true),
	"EG-001.dmarc.known-bad":  DMARCPolicyExpectation(false),

	"EG-002.known-good": ExecutiveImpersonationExpectation(true),
	"EG-002.known-bad":  ExecutiveImpersonationExpectation(false),

	"EG-003.credential-url.known-good": CredentialHarvestingURLExpectation(true),
	"EG-003.credential-url.known-bad":  CredentialHarvestingURLExpectation(false),
	"EG-003.url-rewrite.known-good":    URLRewriteExpectation(false), // knownBad=false is URLRewriteExpectation's own known-good/false-positive case
	"EG-003.url-rewrite.known-bad":     URLRewriteExpectation(true),

	"EG-004.known-good": EICARAttachmentExpectation(true),
	"EG-004.known-bad":  EICARAttachmentExpectation(false),

	"EG-005.known-good": SupplierPaymentDiversionExpectation(true),
	"EG-005.known-bad":  SupplierPaymentDiversionExpectation(false),

	"EG-006.known-good": OutboundDLPExpectation(false), // sensitive=false is OutboundDLPExpectation's own known-good/legitimate-mail case
	"EG-006.known-bad":  OutboundDLPExpectation(true),

	"EG-008.known-good": PostDeliveryThreatResponseExpectation(),
	"EG-008.known-bad":  PostDeliveryThreatResponseExpectation(),

	"EG-009.known-good": AuthenticationExceptionScopeExpectation(true),
	"EG-009.known-bad":  AuthenticationExceptionScopeExpectation(false),

	"EG-010.detection": PostDeliveryThreatResponseExpectation(),
	"EG-010.response":  PostDeliveryThreatResponseExpectation(),
}

// ExpectationByID returns the MailExpectation expectationID resolves
// to, and whether one exists. A false result covers both an unknown ID
// and EG-007's own deliberate absence (see this file's package
// comment) -- the caller cannot tell those apart from the bool alone,
// and does not need to: either way, there is nothing to inject.
func ExpectationByID(expectationID string) (MailExpectation, bool) {
	exp, ok := expectationByID[expectationID]
	return exp, ok
}
