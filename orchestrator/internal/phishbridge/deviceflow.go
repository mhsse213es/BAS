package phishbridge

import (
	"time"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

// FromDeviceCodeEnforcement translates
// phishidentity.EvaluateDeviceCodeEnforcement's own real, per-sign-in
// enforcement outcome into phishval's Enforcement dimension for
// PH-ID-003. Deliberately built only from SignInsByAuthenticationProtocol's
// real per-attempt evidence -- never from
// phishidentity.ConditionalAccessPolicies' own configuration list, per
// the user's own instruction to keep configuration and enforcement
// evidence distinct and never infer one from the other. A caller that
// also wants to report "and a policy named X exists" does so as a
// separate fact alongside this Observation, never folded into it.
func FromDeviceCodeEnforcement(outcome phishidentity.DeviceCodeEnforcement, detail string) phishval.Observation {
	switch outcome {
	case phishidentity.DeviceCodeBlocked:
		return phishval.Observation{Enforcement: &phishval.EnforcementObservation{
			Outcome: phishval.EnforcementBlocked, Timestamp: time.Now(), Source: "phishidentity-signinlogs",
			Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh, Detail: detail,
		}}
	case phishidentity.DeviceCodeAllowed:
		return phishval.Observation{Enforcement: &phishval.EnforcementObservation{
			Outcome: phishval.EnforcementAllowed, Timestamp: time.Now(), Source: "phishidentity-signinlogs",
			Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh, Detail: detail,
		}}
	default: // DeviceCodeUnknown
		return phishval.Observation{Enforcement: &phishval.EnforcementObservation{
			Outcome: phishval.EnforcementUnknown, Timestamp: time.Now(), Source: "phishidentity-signinlogs",
			Evidence: phishval.EvidenceMissing, Confidence: phishval.ConfidenceInsufficient, Detail: detail,
		}}
	}
}
