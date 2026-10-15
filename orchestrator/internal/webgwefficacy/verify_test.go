package webgwefficacy

import (
	"errors"
	"testing"
	"time"
)

// erroringProvider always returns err, and optionally also non-empty
// records -- used to prove VerifyHTTPExpectation checks the error
// before ever looking at the records slice's length.
type erroringProvider struct {
	err     error
	records []GatewayEvidence
}

func (p erroringProvider) GatewayEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]GatewayEvidence, error) {
	return p.records, p.err
}

func TestVerifyHTTPExpectation_ProviderError_PreventionAndDetectionInconclusive(t *testing.T) {
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := erroringProvider{err: errors.New("gateway API unreachable")}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{})

	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q", result.Prevention.Verdict, VerdictInconclusive)
	}
	if result.Detection.Verdict != VerdictInconclusive {
		t.Errorf("Detection.Verdict = %q, want %q", result.Detection.Verdict, VerdictInconclusive)
	}
	if result.Response.Verdict != VerdictUnsupported {
		t.Errorf("Response.Verdict = %q, want %q", result.Response.Verdict, VerdictUnsupported)
	}
}

func TestVerifyHTTPExpectation_ProviderErrorWithRecords_RecordsIgnored(t *testing.T) {
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := erroringProvider{
		err:     errors.New("gateway API unreachable"),
		records: []GatewayEvidence{{RequestURL: "https://malware.example/payload", Action: "block", Timestamp: time.Now()}},
	}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{})

	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q -- a provider error must be checked before its records are ever inspected", result.Prevention.Verdict, VerdictInconclusive)
	}
	if len(result.Evidence) != 0 {
		t.Errorf("Evidence = %+v, want empty -- records returned alongside an error must be ignored", result.Evidence)
	}
}

func TestVerifyHTTPExpectation_NoEvidence_PreventionInconclusiveDetectionFail(t *testing.T) {
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider(nil)
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)})

	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q -- missing telemetry is never proof of a successful bypass", result.Prevention.Verdict, VerdictInconclusive)
	}
	if result.Detection.Verdict != VerdictFail {
		t.Errorf("Detection.Verdict = %q, want %q -- no log/alert at all is a genuine detection failure", result.Detection.Verdict, VerdictFail)
	}
}

func TestVerifyHTTPExpectation_ActionMatches_PreventionPass(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q", result.Prevention.Verdict, VerdictPass)
	}
	if result.Detection.Verdict != VerdictPass {
		t.Errorf("Detection.Verdict = %q, want %q -- evidence existing at all is this phase's detection signal", result.Detection.Verdict, VerdictPass)
	}
}

func TestVerifyHTTPExpectation_AllowActionMatches_PreventionPass(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{RequestURL: "https://intranet.example/portal", ExpectedAction: ExpectedAllow}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://intranet.example/portal", Action: "allow", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q -- the allow case must be proven end-to-end, same as the block case", result.Prevention.Verdict, VerdictPass)
	}
	if result.Detection.Verdict != VerdictPass {
		t.Errorf("Detection.Verdict = %q, want %q -- evidence existing at all is this phase's detection signal", result.Detection.Verdict, VerdictPass)
	}
}

func TestVerifyHTTPExpectation_ActionMismatch_PreventionFail(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "allow", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Prevention.Verdict != VerdictFail {
		t.Errorf("Prevention.Verdict = %q, want %q -- the gateway allowed a request expected to be blocked", result.Prevention.Verdict, VerdictFail)
	}
	if result.Detection.Verdict != VerdictPass {
		t.Errorf("Detection.Verdict = %q, want %q -- the gateway still logged the request, even though it took the wrong action", result.Detection.Verdict, VerdictPass)
	}
}

func TestVerifyHTTPExpectation_ActionCaseMismatch_TreatedAsMismatchNotNormalized(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "Block", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Prevention.Verdict != VerdictFail {
		t.Errorf("Prevention.Verdict = %q, want %q -- this phase does exact-case matching; normalizing vendor casing is a live adapter's job (Phase 2), not this package's", result.Prevention.Verdict, VerdictFail)
	}
}

func TestVerifyHTTPExpectation_ResponseAlwaysUnsupportedInThisPhase(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Response.Verdict != VerdictUnsupported {
		t.Errorf("Response.Verdict = %q, want %q -- no response-evidence integration exists until a later phase", result.Response.Verdict, VerdictUnsupported)
	}
	if result.Response.Reason == "" {
		t.Error("Response.Reason is empty, want a stated reason since Verdict != Pass")
	}
}

func TestVerifyHTTPExpectation_MultipleMatchingRecords_MostRecentWins(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "allow", Timestamp: older, Source: SourceFixture},
		{RequestURL: "https://malware.example/payload", Action: "block", Timestamp: newer, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)})

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q -- the most recent record (block) must win over the stale earlier one (allow)", result.Prevention.Verdict, VerdictPass)
	}
}

func TestVerifyHTTPExpectation_ZeroValueExpectation_DoesNotPanic(t *testing.T) {
	provider := NewFixtureGatewayProvider(nil)
	result := VerifyHTTPExpectation(HTTPExpectation{}, HTTPObservation{}, provider, TimeWindow{})

	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q for a zero-value expectation with no matching evidence", result.Prevention.Verdict, VerdictInconclusive)
	}
}
