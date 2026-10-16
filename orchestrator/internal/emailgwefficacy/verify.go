package emailgwefficacy

import (
	"fmt"
	"time"
)

// VerifyMailExpectation checks one declared expectation against
// enforcement, detection, and response evidence, scoring Prevention,
// DetectionVerdict, and ResponseVerdict independently from three
// disjoint evidence calls -- by construction, nothing returned by
// DetectionEvidenceFor or ResponseEvidenceFor can ever change
// Prevention's verdict, and so on for each pair. This is the
// structural implementation of emailGW.txt §3's own instruction:
// "Never report missing SIEM telemetry as proof that the gateway
// failed to block a message. Never claim a finding is false merely
// because one downstream product did not generate an alert." The same
// discipline applies to Response: a message whose remediation hasn't
// resolved yet, or whose provider errored, must never be read as a
// confirmed remediation failure.
func VerifyMailExpectation(
	exp MailExpectation,
	observation OriginDeliveryObservation,
	provider MailEvidenceProvider,
	window TimeWindow,
) EfficacyResult {
	result := EfficacyResult{
		Expectation: exp,
		Observation: observation,
	}
	msg := exp.Ref()

	result.Prevention = verifyPrevention(exp, provider, msg, window, &result.Enforcement)
	result.DetectionVerdict = verifyDetection(provider, msg, window, &result.Detection)
	result.ResponseVerdict = verifyResponse(provider, msg, window, &result.Response)

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

// verifyResponse computes the ResponseVerdict dimension from response
// evidence alone. A collection error or an empty result both yield
// Inconclusive, never ConfirmedFailure -- a remediation that hasn't
// resolved yet (still in a non-terminal state at a real provider) is
// expected to surface as no evidence yet, the same "absence is not
// proof" discipline verifyPrevention and verifyDetection apply to
// their own dimensions. Only an explicit record asserting
// Completed == false (the provider reached a terminal, non-success
// state and reported it) can produce ConfirmedFailure.
func verifyResponse(provider MailEvidenceProvider, msg MessageRef, window TimeWindow, responseOut *[]ResponseEvidence) VerdictDetail {
	records, err := provider.ResponseEvidenceFor(msg, window)
	if err != nil {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  fmt.Sprintf("response evidence collection failed: %v", err),
		}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no response evidence found for this message in the window; a remediation action that hasn't resolved yet is never read as a confirmed failure",
		}
	}

	*responseOut = records
	latest := latestByTimestamp(records, func(e ResponseEvidence) time.Time { return e.Timestamp })

	if latest.Completed {
		return VerdictDetail{Verdict: VerdictConfirmedSuccess}
	}
	return VerdictDetail{
		Verdict: VerdictConfirmedFailure,
		Reason:  fmt.Sprintf("required response action %q did not complete", latest.ActionRequired),
	}
}
