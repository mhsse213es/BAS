package wafmodsec

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafval"
)

// Review Focus: a rate-limit claim is only meaningful across the WHOLE
// burst, not any single response -- the limiter firing partway through is
// itself the evidence of enforcement, even though most responses in a real
// burst still reach origin before the limit trips.
func TestBuildBurstCollectionResults_SomeBlocked_ResolvesBlocked(t *testing.T) {
	responses := []modsecwaf.RawResponse{
		{StatusCode: 200, Body: []byte(echoBody)},
		{StatusCode: 200, Body: []byte(echoBody)},
		{StatusCode: 200, Body: []byte(echoBody)},
		{StatusCode: 503, Body: []byte(`<html><body>503 Service Temporarily Unavailable</body></html>`)},
		{StatusCode: 503, Body: []byte(`<html><body>503 Service Temporarily Unavailable</body></html>`)},
	}
	key := wafval.CorrelationKey{TestExecutionID: "t1", RequestID: "r1"}
	results := BuildBurstCollectionResults(responses, key, time.Now())

	verdict := wafval.EvaluateClaim(wafval.Expectation{Claim: wafval.ClaimPrevention}, results, key)
	if verdict.Verdict != wafval.VerdictBlocked {
		t.Errorf("Verdict = %q, want %q (reason: %s)", verdict.Verdict, wafval.VerdictBlocked, verdict.Reason)
	}
	if verdict.Completeness != wafval.CompletenessComplete {
		t.Errorf("Completeness = %q, want %q", verdict.Completeness, wafval.CompletenessComplete)
	}
}

// Review Focus: if NOTHING in the burst was ever blocked, that is the real,
// honest finding that no rate limit is actually enforced -- must not be
// silently reported as "Blocked" just because a limit was declared.
func TestBuildBurstCollectionResults_NoneBlocked_ResolvesAllowed(t *testing.T) {
	responses := []modsecwaf.RawResponse{
		{StatusCode: 200, Body: []byte(echoBody)},
		{StatusCode: 200, Body: []byte(echoBody)},
		{StatusCode: 200, Body: []byte(echoBody)},
	}
	key := wafval.CorrelationKey{TestExecutionID: "t2", RequestID: "r2"}
	results := BuildBurstCollectionResults(responses, key, time.Now())

	// VerdictMissed requires a resolved Detection axis (DetectionNotMatched
	// under verified-complete coverage) -- this bridge never parses the
	// ModSecurity audit log, so every Observation carries DetectionUnknown,
	// same disclosed limitation as BuildCollectionResults. Allowed-through
	// evidence with an unresolved Detection axis is Inconclusive, not Missed.
	verdict := wafval.EvaluateClaim(wafval.Expectation{Claim: wafval.ClaimPrevention}, results, key)
	if verdict.Verdict != wafval.VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q (reason: %s)", verdict.Verdict, wafval.VerdictInconclusive, verdict.Reason)
	}
}
