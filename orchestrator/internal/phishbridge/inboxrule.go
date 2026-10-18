package phishbridge

import (
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// FromSingleDimensionDetectionVerdict translates any of
// emailgwefficacy's single-dimensional, mailbox/identity-
// CONFIGURATION-STATE VerdictDetail checks (VerifyInboxRuleExpectation
// for PH-AUTH-009, VerifyDelegatedMailboxAccessExpectation for
// PH-AUTH-010, and VerifyOAuthConsentGrantExpectation should a future
// scenario need it) into phishval's Detection dimension. These checks
// are never about one message's delivery fate, hence their own
// evidence shape distinct from MailExpectation/EfficacyResult --
// deliberately generic rather than one near-duplicate function per
// VerdictDetail-returning check, since the translation logic itself
// is identical regardless of which underlying configuration state was
// checked; source names which one for the Observation's own record.
//
// VerdictConfirmedFailure here is a genuine observed negative (the
// evidence provider actually returned a record showing the opposite
// of what was expected), not an absence of evidence -- every one of
// these Verify* functions already routes a truly empty/erroring
// search to VerdictInconclusive itself, so by the time this function
// sees ConfirmedFailure, SearchedComplete is honestly true.
func FromSingleDimensionDetectionVerdict(v emailgwefficacy.VerdictDetail, source string) phishval.Observation {
	switch v.Verdict {
	case emailgwefficacy.VerdictConfirmedSuccess:
		return phishval.Observation{Detection: &phishval.DetectionObservation{
			Outcome: phishval.DetectionDetected, Source: source,
			Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh,
			SearchedComplete: true, Detail: "configuration-state detection matched the declared expectation",
		}}
	case emailgwefficacy.VerdictConfirmedFailure:
		return phishval.Observation{Detection: &phishval.DetectionObservation{
			Outcome: phishval.DetectionNotDetectedWithinWindow, Source: source,
			Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh,
			SearchedComplete: true, Detail: v.Reason,
		}}
	default: // VerdictInconclusive
		return phishval.Observation{Detection: &phishval.DetectionObservation{
			Outcome: phishval.DetectionInconclusive, Source: source,
			Evidence: phishval.EvidenceMissing, Confidence: phishval.ConfidenceInsufficient,
			Detail: v.Reason,
		}}
	}
}
