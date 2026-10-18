package phishbridge

import (
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// FromInboxRuleVerdict translates
// emailgwefficacy.VerifyInboxRuleExpectation's single-dimensional
// VerdictDetail -- a mailbox-CONFIGURATION-STATE claim (was a
// suspicious auto-forward rule detected), never a message-delivery
// claim, hence its own evidence shape distinct from MailExpectation/
// EfficacyResult -- into phishval's Detection dimension for
// PH-AUTH-009. The real scenario builder
// (emailgwefficacy.SuspiciousAutoForwardExpectation) already existed;
// this was only ever a missing translation, like
// FromExerciseInteractionEvidence was for PH-ID-001.
//
// VerdictConfirmedFailure here is a genuine observed negative (a
// RuleDetected: false record was actually found), not an absence of
// evidence -- VerifyInboxRuleExpectation itself already routes a
// truly empty/erroring search to VerdictInconclusive, so by the time
// this function sees ConfirmedFailure, SearchedComplete is honestly
// true.
func FromInboxRuleVerdict(v emailgwefficacy.VerdictDetail) phishval.Observation {
	switch v.Verdict {
	case emailgwefficacy.VerdictConfirmedSuccess:
		return phishval.Observation{Detection: &phishval.DetectionObservation{
			Outcome: phishval.DetectionDetected, Source: "emailgwefficacy-inboxrule",
			Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh,
			SearchedComplete: true, Detail: "suspicious auto-forward rule detection matched the declared expectation",
		}}
	case emailgwefficacy.VerdictConfirmedFailure:
		return phishval.Observation{Detection: &phishval.DetectionObservation{
			Outcome: phishval.DetectionNotDetectedWithinWindow, Source: "emailgwefficacy-inboxrule",
			Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh,
			SearchedComplete: true, Detail: v.Reason,
		}}
	default: // VerdictInconclusive
		return phishval.Observation{Detection: &phishval.DetectionObservation{
			Outcome: phishval.DetectionInconclusive, Source: "emailgwefficacy-inboxrule",
			Evidence: phishval.EvidenceMissing, Confidence: phishval.ConfidenceInsufficient,
			Detail: v.Reason,
		}}
	}
}
