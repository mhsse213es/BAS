package emailgwefficacy

import (
	"errors"
	"testing"
	"time"
)

func TestCorrelateWithTicketing_ResponseNotConfirmed_ReturnsUnchanged(t *testing.T) {
	result := EfficacyResult{ResponseVerdict: VerdictDetail{Verdict: VerdictInconclusive, Reason: "no evidence"}}
	got := CorrelateWithTicketing(result, NewFixtureTicketProvider(nil), scenarioWindow())

	if got.ResponseVerdict.Verdict != VerdictInconclusive || got.ResponseVerdict.Reason != "no evidence" {
		t.Errorf("ResponseVerdict = %+v, want unchanged", got.ResponseVerdict)
	}
}

func TestCorrelateWithTicketing_ConfirmedSuccessButNoTicketRecord_DowngradesToInconclusive(t *testing.T) {
	exp := PostDeliveryThreatResponseExpectation()
	result := EfficacyResult{Expectation: exp, ResponseVerdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}}
	got := CorrelateWithTicketing(result, NewFixtureTicketProvider(nil), scenarioWindow())

	if got.ResponseVerdict.Verdict != VerdictInconclusive {
		t.Errorf("ResponseVerdict.Verdict = %q, want %q -- a completed remediation is not sufficient proof of incident escalation", got.ResponseVerdict.Verdict, VerdictInconclusive)
	}
}

func TestCorrelateWithTicketing_ConfirmedSuccessButIncidentNotCreated_DowngradesToInconclusive(t *testing.T) {
	exp := PostDeliveryThreatResponseExpectation()
	result := EfficacyResult{Expectation: exp, ResponseVerdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}}
	now := time.Now()
	provider := NewFixtureTicketProvider([]TicketEvidence{
		{Message: exp.Ref(), IncidentCreated: false, Timestamp: now, Source: SourceFixture},
	})
	got := CorrelateWithTicketing(result, provider, scenarioWindow())

	if got.ResponseVerdict.Verdict != VerdictInconclusive {
		t.Errorf("ResponseVerdict.Verdict = %q, want %q", got.ResponseVerdict.Verdict, VerdictInconclusive)
	}
}

func TestCorrelateWithTicketing_ConfirmedSuccessWithIncidentCreated_StaysConfirmedSuccess(t *testing.T) {
	exp := PostDeliveryThreatResponseExpectation()
	result := EfficacyResult{Expectation: exp, ResponseVerdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}}
	now := time.Now()
	provider := NewFixtureTicketProvider([]TicketEvidence{
		{Message: exp.Ref(), IncidentCreated: true, System: "ServiceNow", Severity: "high", Timestamp: now, Source: SourceFixture},
	})
	got := CorrelateWithTicketing(result, provider, scenarioWindow())

	if got.ResponseVerdict.Verdict != VerdictConfirmedSuccess {
		t.Errorf("ResponseVerdict.Verdict = %q, want %q", got.ResponseVerdict.Verdict, VerdictConfirmedSuccess)
	}
	if len(got.TicketEvidence) != 1 {
		t.Errorf("TicketEvidence = %+v, want the one corroborating record attached", got.TicketEvidence)
	}
}

func TestCorrelateWithTicketing_MultipleRecords_MostRecentWins(t *testing.T) {
	exp := PostDeliveryThreatResponseExpectation()
	result := EfficacyResult{Expectation: exp, ResponseVerdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}}
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	provider := NewFixtureTicketProvider([]TicketEvidence{
		{Message: exp.Ref(), IncidentCreated: false, Timestamp: older, Source: SourceFixture},
		{Message: exp.Ref(), IncidentCreated: true, Timestamp: newer, Source: SourceFixture},
	})
	window := TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)}
	got := CorrelateWithTicketing(result, provider, window)

	if got.ResponseVerdict.Verdict != VerdictConfirmedSuccess {
		t.Errorf("ResponseVerdict.Verdict = %q, want %q -- the most recent record (incident created) must win", got.ResponseVerdict.Verdict, VerdictConfirmedSuccess)
	}
}

func TestCorrelateWithTicketing_ProviderError_Inconclusive(t *testing.T) {
	exp := PostDeliveryThreatResponseExpectation()
	result := EfficacyResult{Expectation: exp, ResponseVerdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}}
	got := CorrelateWithTicketing(result, erroringTicketProvider{err: errors.New("ITSM API unreachable")}, scenarioWindow())

	if got.ResponseVerdict.Verdict != VerdictInconclusive {
		t.Errorf("ResponseVerdict.Verdict = %q, want %q", got.ResponseVerdict.Verdict, VerdictInconclusive)
	}
}

type erroringTicketProvider struct{ err error }

func (p erroringTicketProvider) TicketEvidenceFor(msg MessageRef, window TimeWindow) ([]TicketEvidence, error) {
	return nil, p.err
}

func TestFixtureTicketProvider_FiltersByMessageAndWindow(t *testing.T) {
	target := MessageRef{SenderProfile: "a", Recipient: "b", MessageClass: "c"}
	other := MessageRef{SenderProfile: "x", Recipient: "y", MessageClass: "z"}
	now := time.Now()
	provider := NewFixtureTicketProvider([]TicketEvidence{
		{Message: target, IncidentCreated: true, Timestamp: now},
		{Message: other, IncidentCreated: true, Timestamp: now},
		{Message: target, IncidentCreated: true, Timestamp: now.Add(-24 * time.Hour)},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	records, err := provider.TicketEvidenceFor(target, window)
	if err != nil {
		t.Fatalf("TicketEvidenceFor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %+v, want 1 (wrong-message and out-of-window records excluded)", records)
	}
}
