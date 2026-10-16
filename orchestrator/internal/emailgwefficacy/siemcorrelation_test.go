package emailgwefficacy

import (
	"errors"
	"testing"
	"time"
)

func TestCorrelateWithSIEM_DetectionNotConfirmed_ReturnsUnchanged(t *testing.T) {
	result := EfficacyResult{DetectionVerdict: VerdictDetail{Verdict: VerdictInconclusive, Reason: "no evidence"}}
	got := CorrelateWithSIEM(result, NewFixtureSIEMProvider(nil), scenarioWindow())

	if got.DetectionVerdict.Verdict != VerdictInconclusive || got.DetectionVerdict.Reason != "no evidence" {
		t.Errorf("DetectionVerdict = %+v, want unchanged", got.DetectionVerdict)
	}
}

func TestCorrelateWithSIEM_ConfirmedSuccessButNoSIEMRecord_DowngradesToInconclusive(t *testing.T) {
	exp := ExecutiveImpersonationExpectation(true)
	result := EfficacyResult{
		Expectation:      exp,
		DetectionVerdict: VerdictDetail{Verdict: VerdictConfirmedSuccess},
	}
	got := CorrelateWithSIEM(result, NewFixtureSIEMProvider(nil), scenarioWindow())

	if got.DetectionVerdict.Verdict != VerdictInconclusive {
		t.Errorf("DetectionVerdict.Verdict = %q, want %q -- Defender's own alert is not sufficient proof it reached the SOC", got.DetectionVerdict.Verdict, VerdictInconclusive)
	}
	if got.DetectionVerdict.Reason == "" {
		t.Error("want a stated reason")
	}
}

func TestCorrelateWithSIEM_ConfirmedSuccessWithMatchingSIEMRecord_StaysConfirmedSuccess(t *testing.T) {
	exp := ExecutiveImpersonationExpectation(true)
	result := EfficacyResult{
		Expectation:      exp,
		DetectionVerdict: VerdictDetail{Verdict: VerdictConfirmedSuccess},
	}
	now := time.Now()
	provider := NewFixtureSIEMProvider([]SIEMEvidence{
		{Message: exp.Ref(), EventType: "alert-ingested", Timestamp: now, Source: SourceFixture},
	})
	got := CorrelateWithSIEM(result, provider, scenarioWindow())

	if got.DetectionVerdict.Verdict != VerdictConfirmedSuccess {
		t.Errorf("DetectionVerdict.Verdict = %q, want %q", got.DetectionVerdict.Verdict, VerdictConfirmedSuccess)
	}
	if len(got.SIEMEvidence) != 1 {
		t.Errorf("SIEMEvidence = %+v, want the one corroborating record attached", got.SIEMEvidence)
	}
}

func TestCorrelateWithSIEM_ProviderError_Inconclusive(t *testing.T) {
	exp := ExecutiveImpersonationExpectation(true)
	result := EfficacyResult{Expectation: exp, DetectionVerdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}}
	got := CorrelateWithSIEM(result, erroringSIEMProvider{err: errors.New("SIEM API unreachable")}, scenarioWindow())

	if got.DetectionVerdict.Verdict != VerdictInconclusive {
		t.Errorf("DetectionVerdict.Verdict = %q, want %q", got.DetectionVerdict.Verdict, VerdictInconclusive)
	}
}

type erroringSIEMProvider struct{ err error }

func (p erroringSIEMProvider) SIEMEvidenceFor(msg MessageRef, window TimeWindow) ([]SIEMEvidence, error) {
	return nil, p.err
}

func TestFixtureSIEMProvider_FiltersByMessageAndWindow(t *testing.T) {
	target := MessageRef{SenderProfile: "a", Recipient: "b", MessageClass: "c"}
	other := MessageRef{SenderProfile: "x", Recipient: "y", MessageClass: "z"}
	now := time.Now()
	provider := NewFixtureSIEMProvider([]SIEMEvidence{
		{Message: target, Timestamp: now},
		{Message: other, Timestamp: now},
		{Message: target, Timestamp: now.Add(-24 * time.Hour)},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	records, err := provider.SIEMEvidenceFor(target, window)
	if err != nil {
		t.Fatalf("SIEMEvidenceFor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %+v, want 1 (wrong-message and out-of-window records excluded)", records)
	}
}
