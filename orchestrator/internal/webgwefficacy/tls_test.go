package webgwefficacy

import (
	"errors"
	"testing"
	"time"
)

type erroringTLSProvider struct{ err error }

func (p erroringTLSProvider) TLSInspectionEvidenceFor(requestURL string, window TimeWindow) ([]TLSInspectionEvidence, error) {
	return nil, p.err
}

func TestFixtureTLSInspectionProvider_FiltersByURLAndWindow(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureTLSInspectionProvider([]TLSInspectionEvidence{
		{RequestURL: "https://intranet.example/portal", WasInspected: true, Timestamp: now, Source: SourceFixture},
		{RequestURL: "https://other.example/page", WasInspected: true, Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.TLSInspectionEvidenceFor("https://intranet.example/portal", TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("TLSInspectionEvidenceFor: %v", err)
	}
	if len(got) != 1 || !got[0].WasInspected {
		t.Fatalf("got %+v, want exactly one inspected record for the matching URL", got)
	}
}

func TestFixtureTLSInspectionProvider_OutsideWindowExcluded(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureTLSInspectionProvider([]TLSInspectionEvidence{
		{RequestURL: "https://intranet.example/portal", WasInspected: true, Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.TLSInspectionEvidenceFor("https://intranet.example/portal", TimeWindow{Start: now.Add(time.Hour), End: now.Add(2 * time.Hour)})
	if err != nil {
		t.Fatalf("TLSInspectionEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want empty -- outside the requested window", got)
	}
}

func TestVerifyTLSInspectionExpectation_InspectedMatchesExpectation_Pass(t *testing.T) {
	now := time.Now()
	exp := TLSInspectionExpectation{RequestURL: "https://intranet.example/portal", ExpectedInspected: true}
	provider := NewFixtureTLSInspectionProvider([]TLSInspectionEvidence{
		{RequestURL: exp.RequestURL, WasInspected: true, CertIssuer: "Cloudflare Gateway CA", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyTLSInspectionExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictPass)
	}
}

func TestVerifyTLSInspectionExpectation_NotInspectedWhenExpected_Fail(t *testing.T) {
	now := time.Now()
	exp := TLSInspectionExpectation{RequestURL: "https://intranet.example/portal", ExpectedInspected: true}
	provider := NewFixtureTLSInspectionProvider([]TLSInspectionEvidence{
		{RequestURL: exp.RequestURL, WasInspected: false, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyTLSInspectionExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- expected inspection but evidence shows bypass", result.Verdict, VerdictFail)
	}
}

func TestVerifyTLSInspectionExpectation_NoEvidence_Inconclusive(t *testing.T) {
	exp := TLSInspectionExpectation{RequestURL: "https://intranet.example/portal", ExpectedInspected: true}
	provider := NewFixtureTLSInspectionProvider(nil)
	result := VerifyTLSInspectionExpectation(exp, provider, TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- a successful request must never be read as proof of inspection", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyTLSInspectionExpectation_ProviderError_Inconclusive(t *testing.T) {
	exp := TLSInspectionExpectation{RequestURL: "https://intranet.example/portal", ExpectedInspected: true}
	provider := erroringTLSProvider{err: errors.New("certificate store unreachable")}
	result := VerifyTLSInspectionExpectation(exp, provider, TimeWindow{})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyTLSInspectionExpectation_MultipleRecords_MostRecentWins(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	exp := TLSInspectionExpectation{RequestURL: "https://intranet.example/portal", ExpectedInspected: true}
	provider := NewFixtureTLSInspectionProvider([]TLSInspectionEvidence{
		{RequestURL: exp.RequestURL, WasInspected: false, Timestamp: older, Source: SourceFixture},
		{RequestURL: exp.RequestURL, WasInspected: true, Timestamp: newer, Source: SourceFixture},
	})
	result := VerifyTLSInspectionExpectation(exp, provider, TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)})

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- the most recent record (inspected) must win over the stale earlier one (bypassed)", result.Verdict, VerdictPass)
	}
}
