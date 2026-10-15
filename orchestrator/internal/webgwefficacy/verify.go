package webgwefficacy

import (
	"fmt"
	"sort"
)

// unsupportedResponseReason is this phase's constant reason for every
// Response verdict -- no response-evidence integration (SOC/
// ticketing/EDR action correlation) exists at all yet; this is a
// structural "capability does not exist," distinct from a run whose
// evidence happened to be missing (Inconclusive).
const unsupportedResponseReason = "no response-evidence integration exists in this phase"

// VerifyHTTPExpectation checks one declared expectation against
// gateway evidence, scoring prevention, detection, and response
// independently. Mirrors networkefficacy.VerifyControlExpectation's
// precedent (every failure mode resolves to a verdict with a reason;
// this function never returns an error) with three independently
// computed dimensions instead of one.
func VerifyHTTPExpectation(
	exp HTTPExpectation,
	observation HTTPObservation,
	provider GatewayEvidenceProvider,
	window TimeWindow,
) EfficacyResult {
	result := EfficacyResult{
		Expectation: exp,
		Observation: observation,
		Response:    VerdictDetail{Verdict: VerdictUnsupported, Reason: unsupportedResponseReason},
	}
	req := HTTPRequestRef{URL: exp.RequestURL, User: exp.User}

	records, err := provider.GatewayEvidenceFor(req, window)
	if err != nil {
		reason := fmt.Sprintf("gateway evidence collection failed: %v", err)
		result.Prevention = VerdictDetail{Verdict: VerdictInconclusive, Reason: reason}
		result.Detection = VerdictDetail{Verdict: VerdictInconclusive, Reason: reason}
		return result
	}
	if len(records) == 0 {
		result.Prevention = VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no gateway evidence found for this request in the window; absence of evidence is not proof the expected action occurred",
		}
		result.Detection = VerdictDetail{
			Verdict: VerdictFail,
			Reason:  "no gateway log or alert found; expected the gateway to record this request",
		}
		return result
	}

	result.Evidence = records
	latest := latestGatewayEvidence(records)

	if latest.Action == string(exp.ExpectedAction) {
		result.Prevention = VerdictDetail{Verdict: VerdictPass}
	} else {
		result.Prevention = VerdictDetail{
			Verdict: VerdictFail,
			Reason:  fmt.Sprintf("gateway action %q did not match expected %q", latest.Action, exp.ExpectedAction),
		}
	}

	result.Detection = VerdictDetail{Verdict: VerdictPass}

	return result
}

// latestGatewayEvidence returns the record with the latest Timestamp
// -- a later event reflects the gateway's final decision for a
// request more faithfully than an earlier one (retries, duplicate log
// lines, a policy change mid-test).
func latestGatewayEvidence(records []GatewayEvidence) GatewayEvidence {
	sorted := make([]GatewayEvidence, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })
	return sorted[len(sorted)-1]
}
