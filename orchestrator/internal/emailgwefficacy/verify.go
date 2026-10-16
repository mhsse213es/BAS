package emailgwefficacy

import (
	"fmt"
	"time"
)

// unsupportedResponseReason is this phase's constant reason for every
// ResponseVerdict -- no response-evidence integration (quarantine/
// recall/account-containment completion tracking against a real
// product) exists yet; this is a structural "capability does not
// exist," distinct from a run whose evidence happened to be missing
// (Inconclusive), matching webgwefficacy's own Phase 1 precedent for
// its then-unbuilt Response dimension.
const unsupportedResponseReason = "no response-evidence integration exists in this phase"

// VerifyMailExpectation checks one declared expectation against
// enforcement and detection evidence, scoring Prevention and
// DetectionVerdict independently from two disjoint evidence calls --
// by construction, nothing returned by DetectionEvidenceFor can ever
// change Prevention's verdict, and nothing returned by
// EnforcementEvidenceFor can ever change DetectionVerdict's. This is
// the structural implementation of emailGW.txt §3's own instruction:
// "Never report missing SIEM telemetry as proof that the gateway
// failed to block a message. Never claim a finding is false merely
// because one downstream product did not generate an alert."
func VerifyMailExpectation(
	exp MailExpectation,
	observation OriginDeliveryObservation,
	provider MailEvidenceProvider,
	window TimeWindow,
) EfficacyResult {
	result := EfficacyResult{
		Expectation: exp,
		Observation: observation,
		ResponseVerdict: VerdictDetail{
			Verdict: VerdictNotTested,
			Reason:  unsupportedResponseReason,
		},
	}
	msg := exp.Ref()

	result.Prevention = verifyPrevention(exp, provider, msg, window, &result.Enforcement)
	result.DetectionVerdict = verifyDetection(provider, msg, window, &result.Detection)

	return result
}

// verifyPrevention computes the Prevention dimension from enforcement
// evidence alone. A collection error or an empty result both yield
// Inconclusive, never an assumed ConfirmedSuccess or
// ConfirmedFailure -- emailGW.txt §2's own instruction that neither a
// blocked nor a delivered message is automatically proof of anything
// until the actual control behavior is established.
func verifyPrevention(exp MailExpectation, provider MailEvidenceProvider, msg MessageRef, window TimeWindow, enforcementOut *[]EnforcementEvidence) VerdictDetail {
	records, err := provider.EnforcementEvidenceFor(msg, window)
	if err != nil {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  fmt.Sprintf("enforcement evidence collection failed: %v", err),
		}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no enforcement evidence found for this message in the window; absence of evidence is not proof of either a healthy or a failed control",
		}
	}

	*enforcementOut = records
	latest := latestByTimestamp(records, func(e EnforcementEvidence) time.Time { return e.Timestamp })

	if latest.Action == string(exp.ExpectedAction) {
		return VerdictDetail{Verdict: VerdictConfirmedSuccess}
	}
	return VerdictDetail{
		Verdict: VerdictConfirmedFailure,
		Reason:  fmt.Sprintf("gateway action %q did not match expected %q", latest.Action, exp.ExpectedAction),
	}
}

// verifyDetection computes the DetectionVerdict dimension from
// detection evidence alone. A collection error or an empty result
// both yield Inconclusive -- never ConfirmedFailure -- per
// emailGW.txt §3's own instruction quoted on VerifyMailExpectation.
// Only an explicit record asserting AlertGenerated == false (the
// provider was checked and the answer is "no alert fired") can
// produce ConfirmedFailure for this dimension; a provider returning
// zero records at all means the check could not be made, which is a
// different, weaker claim.
func verifyDetection(provider MailEvidenceProvider, msg MessageRef, window TimeWindow, detectionOut *[]DetectionEvidence) VerdictDetail {
	records, err := provider.DetectionEvidenceFor(msg, window)
	if err != nil {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  fmt.Sprintf("detection evidence collection failed: %v", err),
		}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no detection evidence found for this message in the window; missing telemetry is never read as a confirmed detection failure",
		}
	}

	*detectionOut = records
	latest := latestByTimestamp(records, func(e DetectionEvidence) time.Time { return e.Timestamp })

	if latest.AlertGenerated {
		return VerdictDetail{Verdict: VerdictConfirmedSuccess}
	}
	return VerdictDetail{
		Verdict: VerdictConfirmedFailure,
		Reason:  "detection provider confirmed no alert was generated for this message",
	}
}
