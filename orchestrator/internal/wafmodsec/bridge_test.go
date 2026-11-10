package wafmodsec

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafval"
)

const echoBody = `{"path":"/search","method":"GET","query":{"q":"laptop stand"}}`
const modsecBlockBody = `<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center><hr><center>nginx</center></body></html>`

func TestBuildCollectionResults_Blocked_WAFEnforcedAndOriginNeverReceived(t *testing.T) {
	resp := modsecwaf.RawResponse{StatusCode: 403, Body: []byte(modsecBlockBody)}
	key := wafval.CorrelationKey{TestExecutionID: "t1", RequestID: "r1"}
	results := BuildCollectionResults(resp, key, time.Now())

	verdict := wafval.EvaluateClaim(wafval.Expectation{Claim: wafval.ClaimPrevention}, results, key)
	if verdict.Verdict != wafval.VerdictBlocked {
		t.Errorf("Verdict = %q, want %q (reason: %s)", verdict.Verdict, wafval.VerdictBlocked, verdict.Reason)
	}
	if verdict.Completeness != wafval.CompletenessComplete {
		t.Errorf("Completeness = %q, want %q", verdict.Completeness, wafval.CompletenessComplete)
	}
}

func TestBuildCollectionResults_Allowed_WAFAllowedAndOriginReceived(t *testing.T) {
	resp := modsecwaf.RawResponse{StatusCode: 200, Body: []byte(echoBody)}
	key := wafval.CorrelationKey{TestExecutionID: "t2", RequestID: "r2"}
	results := BuildCollectionResults(resp, key, time.Now())

	verdict := wafval.EvaluateClaim(wafval.Expectation{Claim: wafval.ClaimFalsePositive}, results, key)
	if verdict.Verdict != wafval.VerdictAllowed {
		t.Errorf("Verdict = %q, want %q (reason: %s)", verdict.Verdict, wafval.VerdictAllowed, verdict.Reason)
	}
	if verdict.Completeness != wafval.CompletenessComplete {
		t.Errorf("Completeness = %q, want %q", verdict.Completeness, wafval.CompletenessComplete)
	}
}

func TestBuildCollectionResults_IncorrectlyBlocked_BenignRequestBlocked(t *testing.T) {
	resp := modsecwaf.RawResponse{StatusCode: 403, Body: []byte(modsecBlockBody)}
	key := wafval.CorrelationKey{TestExecutionID: "t3", RequestID: "r3"}
	results := BuildCollectionResults(resp, key, time.Now())

	verdict := wafval.EvaluateClaim(wafval.Expectation{Claim: wafval.ClaimFalsePositive}, results, key)
	if verdict.Verdict != wafval.VerdictIncorrectlyBlocked {
		t.Errorf("Verdict = %q, want %q (reason: %s)", verdict.Verdict, wafval.VerdictIncorrectlyBlocked, verdict.Reason)
	}
}
