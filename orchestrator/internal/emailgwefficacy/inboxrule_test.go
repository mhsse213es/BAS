package emailgwefficacy

import (
	"errors"
	"testing"
	"time"
)

type erroringInboxRuleProvider struct {
	err error
}

func (p erroringInboxRuleProvider) InboxRuleEvidenceFor(mailbox string, window TimeWindow) ([]InboxRuleEvidence, error) {
	return nil, p.err
}

func TestVerifyInboxRuleExpectation_ProviderError_Inconclusive(t *testing.T) {
	exp := SuspiciousAutoForwardExpectation(true)
	result := VerifyInboxRuleExpectation(exp, erroringInboxRuleProvider{err: errors.New("audit log API unreachable")}, scenarioWindow())

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyInboxRuleExpectation_NoEvidence_Inconclusive(t *testing.T) {
	exp := SuspiciousAutoForwardExpectation(true)
	provider := NewFixtureInboxRuleProvider(nil)
	result := VerifyInboxRuleExpectation(exp, provider, scenarioWindow())

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- absence of evidence must never be read as either outcome", result.Verdict, VerdictInconclusive)
	}
}

func TestSuspiciousAutoForwardScenario_KnownGood_DetectedAsExpected(t *testing.T) {
	exp := SuspiciousAutoForwardExpectation(true)
	now := time.Now()
	provider := NewFixtureInboxRuleProvider([]InboxRuleEvidence{
		{Mailbox: exp.Mailbox, RuleDetected: true, DetectionSource: "Defender alert", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyInboxRuleExpectation(exp, provider, scenarioWindow())

	if result.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictConfirmedSuccess)
	}
}

func TestSuspiciousAutoForwardScenario_KnownBad_UndetectedMismatch(t *testing.T) {
	exp := SuspiciousAutoForwardExpectation(true) // expected detected, but evidence says it wasn't
	now := time.Now()
	provider := NewFixtureInboxRuleProvider([]InboxRuleEvidence{
		{Mailbox: exp.Mailbox, RuleDetected: false, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyInboxRuleExpectation(exp, provider, scenarioWindow())

	if result.Verdict != VerdictConfirmedFailure {
		t.Errorf("Verdict = %q, want %q -- the rule was created but tenant security failed to detect it", result.Verdict, VerdictConfirmedFailure)
	}
	if result.Reason == "" {
		t.Error("Reason is empty, want a stated reason since Verdict != ConfirmedSuccess")
	}
}

func TestVerifyInboxRuleExpectation_MultipleRecords_MostRecentWins(t *testing.T) {
	exp := SuspiciousAutoForwardExpectation(true)
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	provider := NewFixtureInboxRuleProvider([]InboxRuleEvidence{
		{Mailbox: exp.Mailbox, RuleDetected: false, Timestamp: older, Source: SourceFixture},
		{Mailbox: exp.Mailbox, RuleDetected: true, Timestamp: newer, Source: SourceFixture},
	})
	window := TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)}
	result := VerifyInboxRuleExpectation(exp, provider, window)

	if result.Verdict != VerdictConfirmedSuccess {
		t.Errorf("Verdict = %q, want %q -- the most recent record (detected) must win over the stale earlier one (not detected)", result.Verdict, VerdictConfirmedSuccess)
	}
}

func TestFixtureInboxRuleProvider_FiltersByMailboxAndWindow(t *testing.T) {
	now := time.Now()
	provider := NewFixtureInboxRuleProvider([]InboxRuleEvidence{
		{Mailbox: "target@example-lab.test", RuleDetected: true, Timestamp: now},
		{Mailbox: "other@example-lab.test", RuleDetected: true, Timestamp: now},
		{Mailbox: "target@example-lab.test", RuleDetected: true, Timestamp: now.Add(-24 * time.Hour)},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	records, err := provider.InboxRuleEvidenceFor("target@example-lab.test", window)
	if err != nil {
		t.Fatalf("InboxRuleEvidenceFor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %+v, want 1 (wrong-mailbox and out-of-window records excluded)", records)
	}
}

func TestSuspiciousAutoForwardExpectation_NeverNamesARealDomain(t *testing.T) {
	exp := SuspiciousAutoForwardExpectation(true)
	if exp.Mailbox == "" {
		t.Fatal("Mailbox is empty")
	}
	const suffix = ".test"
	if len(exp.Mailbox) < len(suffix) || exp.Mailbox[len(exp.Mailbox)-len(suffix):] != suffix {
		t.Errorf("Mailbox %q is not in the synthetic .test namespace", exp.Mailbox)
	}
}
