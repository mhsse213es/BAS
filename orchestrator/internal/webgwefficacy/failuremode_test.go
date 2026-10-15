package webgwefficacy

import (
	"errors"
	"testing"
	"time"
)

type erroringFailureModeProvider struct {
	err     error
	records []FailureModeEvidence
}

func (p erroringFailureModeProvider) FailureModeEvidenceFor(scenarioLabel string, window TimeWindow) ([]FailureModeEvidence, error) {
	return p.records, p.err
}

func TestFixtureFailureModeProvider_FiltersByScenarioAndWindow(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: "gateway-outage-datacenter-failover", ObservedBehavior: ExpectedFailClosed, Timestamp: now, Source: SourceFixture},
		{ScenarioLabel: "other-scenario", ObservedBehavior: ExpectedFailClosed, Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.FailureModeEvidenceFor("gateway-outage-datacenter-failover", TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("FailureModeEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want exactly one matching record", got)
	}
}

func TestVerifyFailureModeExpectation_FailClosedKnownGood_Pass(t *testing.T) {
	now := time.Now()
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailClosed, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyFailureModeExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- known-good baseline: the gateway failed closed as expected", result.Verdict, VerdictPass)
	}
}

// TestVerifyFailureModeExpectation_UnexpectedFailOpen_Fail is the
// negative case this capability exists to catch: a gateway declared
// expected to fail closed instead failed open during an outage --
// Phase 3's required fail-open exit-criterion scenario.
func TestVerifyFailureModeExpectation_UnexpectedFailOpen_Fail(t *testing.T) {
	now := time.Now()
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailOpen, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyFailureModeExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- the gateway failed open during an outage when it was expected to fail closed", result.Verdict, VerdictFail)
	}
}

func TestVerifyFailureModeExpectation_NoEvidence_Inconclusive(t *testing.T) {
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := NewFixtureFailureModeProvider(nil)
	result := VerifyFailureModeExpectation(exp, provider, TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyFailureModeExpectation_ProviderError_Inconclusive(t *testing.T) {
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := erroringFailureModeProvider{err: errors.New("outage telemetry unreachable")}
	result := VerifyFailureModeExpectation(exp, provider, TimeWindow{})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyFailureModeExpectation_ProviderErrorWithRecords_RecordsIgnored(t *testing.T) {
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := erroringFailureModeProvider{
		err:     errors.New("outage telemetry unreachable"),
		records: []FailureModeEvidence{{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailClosed, Timestamp: time.Now()}},
	}
	result := VerifyFailureModeExpectation(exp, provider, TimeWindow{})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- a provider error must be checked before its records are ever inspected", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyFailureModeExpectation_MultipleRecords_MostRecentWins(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailOpen, Timestamp: older, Source: SourceFixture},
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailClosed, Timestamp: newer, Source: SourceFixture},
	})
	result := VerifyFailureModeExpectation(exp, provider, TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)})

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- the most recent record (fail-closed) must win over the stale earlier one (fail-open)", result.Verdict, VerdictPass)
	}
}
