package webgwefficacy

import (
	"errors"
	"testing"
	"time"
)

type erroringSIEMProvider struct {
	err     error
	records []SIEMEvidence
}

func (p erroringSIEMProvider) SIEMEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]SIEMEvidence, error) {
	return p.records, p.err
}

func TestFixtureSIEMProvider_ReturnsMatchingEvidence(t *testing.T) {
	now := time.Now()
	provider := NewFixtureSIEMProvider([]SIEMEvidence{
		{RequestURL: "https://malware.example/payload", EventType: "web-gateway-alert", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.SIEMEvidenceFor(HTTPRequestRef{URL: "https://malware.example/payload"}, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("SIEMEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want one matching record", got)
	}
}

func TestCorrelateWithSIEM_DetectionNotPass_ReturnedUnchanged(t *testing.T) {
	now := time.Now()
	original := EfficacyResult{
		Expectation: HTTPExpectation{RequestURL: "https://malware.example/payload"},
		Detection:   VerdictDetail{Verdict: VerdictInconclusive, Reason: "no gateway evidence found"},
	}
	provider := NewFixtureSIEMProvider([]SIEMEvidence{
		{RequestURL: "https://malware.example/payload", EventType: "web-gateway-alert", Timestamp: now, Source: SourceFixture},
	})
	result := CorrelateWithSIEM(original, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Detection.Verdict != VerdictInconclusive || result.Detection.Reason != "no gateway evidence found" {
		t.Errorf("Detection = %+v, want unchanged from the input -- SIEM must never manufacture a detection the gateway never showed", result.Detection)
	}
}

func TestCorrelateWithSIEM_MatchingRecord_DetectionStaysPassWithCorroboration(t *testing.T) {
	now := time.Now()
	original := EfficacyResult{
		Expectation: HTTPExpectation{RequestURL: "https://malware.example/payload"},
		Detection:   VerdictDetail{Verdict: VerdictPass},
	}
	provider := NewFixtureSIEMProvider([]SIEMEvidence{
		{RequestURL: "https://malware.example/payload", EventType: "web-gateway-alert", Timestamp: now, Source: SourceFixture},
	})
	result := CorrelateWithSIEM(original, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Detection.Verdict != VerdictPass {
		t.Errorf("Detection.Verdict = %q, want %q", result.Detection.Verdict, VerdictPass)
	}
	if result.Detection.Reason == "" {
		t.Error("Detection.Reason is empty, want a stated corroboration note")
	}
	if len(result.SIEMEvidence) != 1 {
		t.Errorf("SIEMEvidence = %+v, want the matching record attached", result.SIEMEvidence)
	}
}

func TestCorrelateWithSIEM_NoMatchingRecord_DetectionDowngradedToInconclusive(t *testing.T) {
	now := time.Now()
	original := EfficacyResult{
		Expectation: HTTPExpectation{RequestURL: "https://malware.example/payload"},
		Detection:   VerdictDetail{Verdict: VerdictPass},
	}
	provider := NewFixtureSIEMProvider(nil)
	result := CorrelateWithSIEM(original, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Detection.Verdict != VerdictInconclusive {
		t.Errorf("Detection.Verdict = %q, want %q -- missing SIEM corroboration is not proof the alert was lost, only that it is uncorroborated", result.Detection.Verdict, VerdictInconclusive)
	}
}

func TestCorrelateWithSIEM_ProviderError_DetectionInconclusive(t *testing.T) {
	original := EfficacyResult{
		Expectation: HTTPExpectation{RequestURL: "https://malware.example/payload"},
		Detection:   VerdictDetail{Verdict: VerdictPass},
	}
	provider := erroringSIEMProvider{err: errors.New("SIEM API unreachable")}
	result := CorrelateWithSIEM(original, provider, TimeWindow{})

	if result.Detection.Verdict != VerdictInconclusive {
		t.Errorf("Detection.Verdict = %q, want %q", result.Detection.Verdict, VerdictInconclusive)
	}
}

func TestCorrelateWithSIEM_ProviderErrorWithRecords_RecordsIgnored(t *testing.T) {
	now := time.Now()
	original := EfficacyResult{
		Expectation: HTTPExpectation{RequestURL: "https://malware.example/payload"},
		Detection:   VerdictDetail{Verdict: VerdictPass},
	}
	provider := erroringSIEMProvider{
		err:     errors.New("SIEM API unreachable"),
		records: []SIEMEvidence{{RequestURL: "https://malware.example/payload", EventType: "web-gateway-alert", Timestamp: now}},
	}
	result := CorrelateWithSIEM(original, provider, TimeWindow{})

	if len(result.SIEMEvidence) != 0 {
		t.Errorf("SIEMEvidence = %+v, want empty -- records returned alongside an error must be ignored", result.SIEMEvidence)
	}
}
