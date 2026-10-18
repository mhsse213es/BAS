package dlpresilience

import (
	"testing"
	"time"
)

var resilienceTestBase = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
var resilienceTestWindow = TimeWindow{Start: resilienceTestBase.Add(-time.Hour), End: resilienceTestBase.Add(time.Hour)}

func resilienceEv(expectationID string, observedMode FailureMode, ts time.Time) ServiceUnavailabilityEvidence {
	return ServiceUnavailabilityEvidence{
		ExpectationID: expectationID, ObservedMode: observedMode,
		Timestamp: ts, Source: SourceFixture,
	}
}

func verifyResilience(exp ServiceUnavailabilityExpectation, evs ...ServiceUnavailabilityEvidence) ResilienceVerdict {
	return VerifyServiceUnavailabilityExpectation(exp, NewFixtureServiceUnavailabilityProvider(evs), resilienceTestWindow)
}

func TestFixtureServiceUnavailabilityProvider_FiltersByExpectationAndWindow(t *testing.T) {
	evs := []ServiceUnavailabilityEvidence{
		resilienceEv("exp-A", FailClosed, resilienceTestBase),
		resilienceEv("exp-B", FailClosed, resilienceTestBase),
		resilienceEv("exp-A", FailClosed, resilienceTestBase.Add(-24*time.Hour)),
	}
	p := NewFixtureServiceUnavailabilityProvider(evs)
	got, err := p.ServiceUnavailabilityEvidenceFor("exp-A", resilienceTestWindow)
	if err != nil {
		t.Fatalf("ServiceUnavailabilityEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
}

type countingProvider struct{ onCall func() }

func (p *countingProvider) ServiceUnavailabilityEvidenceFor(expectationID string, window TimeWindow) ([]ServiceUnavailabilityEvidence, error) {
	p.onCall()
	return nil, nil
}

func TestVerify_UnsetExpectedMode_ReturnsInconclusiveWithoutCallingProvider(t *testing.T) {
	exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "classification"}
	called := false
	provider := &countingProvider{onCall: func() { called = true }}
	got := VerifyServiceUnavailabilityExpectation(exp, provider, resilienceTestWindow)
	if got.Outcome != OutcomeInconclusive {
		t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeInconclusive)
	}
	if called {
		t.Error("provider must never be called when ExpectedMode is unset")
	}
}

func TestVerify_NoEvidence_ReturnsInconclusive(t *testing.T) {
	exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "classification", ExpectedMode: FailClosed}
	got := verifyResilience(exp)
	if got.Outcome != OutcomeInconclusive {
		t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeInconclusive)
	}
}

func TestVerify_ObservedModeEmpty_ReturnsInconclusive(t *testing.T) {
	exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "classification", ExpectedMode: FailClosed}
	got := verifyResilience(exp, resilienceEv("exp-A", "", resilienceTestBase))
	if got.Outcome != OutcomeInconclusive {
		t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeInconclusive)
	}
}

func TestVerify_IndeterminateOK_MatchesFailOpen(t *testing.T) {
	exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "policy", ExpectedMode: IndeterminateOK}
	got := verifyResilience(exp, resilienceEv("exp-A", FailOpen, resilienceTestBase))
	if got.Outcome != OutcomeModeMatched {
		t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeModeMatched)
	}
}

func TestVerify_IndeterminateOK_MatchesFailClosed(t *testing.T) {
	exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "policy", ExpectedMode: IndeterminateOK}
	got := verifyResilience(exp, resilienceEv("exp-A", FailClosed, resilienceTestBase))
	if got.Outcome != OutcomeModeMatched {
		t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeModeMatched)
	}
}

func TestVerify_IndeterminateOK_MatchesDefer(t *testing.T) {
	exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "policy", ExpectedMode: IndeterminateOK}
	got := verifyResilience(exp, resilienceEv("exp-A", Defer, resilienceTestBase))
	if got.Outcome != OutcomeModeMatched {
		t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeModeMatched)
	}
}

func TestVerify_ExactModeMatch_ReturnsMatched(t *testing.T) {
	exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "classification", ExpectedMode: FailClosed}
	got := verifyResilience(exp, resilienceEv("exp-A", FailClosed, resilienceTestBase))
	if got.Outcome != OutcomeModeMatched {
		t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeModeMatched)
	}
}

func TestVerify_ModeMismatch_ReturnsMismatchedNamingBoth(t *testing.T) {
	exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "classification", ExpectedMode: FailClosed}
	got := verifyResilience(exp, resilienceEv("exp-A", FailOpen, resilienceTestBase))
	if got.Outcome != OutcomeModeMismatched {
		t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeModeMismatched)
	}
	if got.Reason == "" {
		t.Fatal("want a Reason naming both the expected and observed mode")
	}
}

func TestVerify_MultipleRecords_PicksLatestByTimestampNotOrder(t *testing.T) {
	exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "classification", ExpectedMode: FailClosed}
	older := resilienceEv("exp-A", FailClosed, resilienceTestBase.Add(-30*time.Minute)) // match-shaped
	newer := resilienceEv("exp-A", FailOpen, resilienceTestBase)                        // mismatch-shaped
	got := verifyResilience(exp, older, newer)
	if got.Outcome != OutcomeModeMismatched {
		t.Fatalf("Outcome = %q, want %q -- must select the record with the latest Timestamp", got.Outcome, OutcomeModeMismatched)
	}
}
