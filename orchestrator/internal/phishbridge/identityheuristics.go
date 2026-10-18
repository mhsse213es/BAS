package phishbridge

import (
	"time"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

// FromMFAFatigueHeuristic translates
// phishidentity.DetectMFAFatigueHeuristic's own verdict into
// phishval's Detection dimension. Deliberately uses
// phishval.EvidenceInferred/phishval.ConfidenceLow, never
// EvidenceVerifiedTelemetry/ConfidenceHigh -- this heuristic is NOT a
// Microsoft-documented detection (no riskDetections.riskEventType
// value exists for MFA fatigue), and a report built on this
// Observation must never present it as a vendor-verified signal. The
// Source string itself carries the same EXPERIMENTAL label so it
// survives into any rendered report, not just this package's own doc
// comments.
func FromMFAFatigueHeuristic(verdict phishidentity.MFAFatigueHeuristicVerdict, detail string) phishval.Observation {
	const source = "phishidentity-mfafatigue-heuristic (EXPERIMENTAL, not a Microsoft-documented detection)"
	switch verdict {
	case phishidentity.MFAFatigueSuspected:
		return phishval.Observation{Detection: &phishval.DetectionObservation{
			Outcome: phishval.DetectionDetected, Source: source,
			Evidence: phishval.EvidenceInferred, Confidence: phishval.ConfidenceLow,
			SearchedComplete: true, Detail: detail,
		}}
	case phishidentity.MFAFatigueNotObserved:
		return phishval.Observation{Detection: &phishval.DetectionObservation{
			Outcome: phishval.DetectionNotDetectedWithinWindow, Source: source,
			Evidence: phishval.EvidenceInferred, Confidence: phishval.ConfidenceLow,
			SearchedComplete: true, Detail: detail,
		}}
	default: // MFAFatigueUnknown
		return phishval.Observation{Detection: &phishval.DetectionObservation{
			Outcome: phishval.DetectionInconclusive, Source: source,
			Evidence: phishval.EvidenceMissing, Confidence: phishval.ConfidenceInsufficient,
			Detail: detail,
		}}
	}
}

// FromSessionTheftResponseHeuristic translates
// phishidentity.DetectSessionTheftResponseHeuristic's own verdict into
// phishval's Response dimension (the same dimension PH-IR-002's own
// admin-triggered RevokeSignInSessions uses, ResponseContained,
// since both ultimately claim "session access was cut off"). Uses
// EvidenceInferred/ConfidenceLow for the same reason
// FromMFAFatigueHeuristic does -- no Microsoft-documented field links
// a risky sign-in to a subsequent revocation, so this is never
// presented as a verified causal signal.
func FromSessionTheftResponseHeuristic(verdict phishidentity.SessionTheftHeuristicVerdict, detail string) phishval.Observation {
	const source = "phishidentity-sessiontheft-heuristic (EXPERIMENTAL, not a Microsoft-documented causal signal)"
	switch verdict {
	case phishidentity.SessionTheftRevokedAfterRiskyEvent:
		return phishval.Observation{Response: &phishval.ResponseObservation{
			Outcome: phishval.ResponseContained, Timestamp: time.Now(), Source: source,
			Evidence: phishval.EvidenceInferred, Confidence: phishval.ConfidenceLow,
			Detail: detail,
		}}
	case phishidentity.SessionTheftNotRevoked:
		return phishval.Observation{Response: &phishval.ResponseObservation{
			Outcome: phishval.ResponseFailed, Timestamp: time.Now(), Source: source,
			Evidence: phishval.EvidenceInferred, Confidence: phishval.ConfidenceLow,
			Detail: detail,
		}}
	default: // SessionTheftUnknown
		return phishval.Observation{} // NotTested: never fabricates Contained or Failed from an inconclusive heuristic
	}
}
