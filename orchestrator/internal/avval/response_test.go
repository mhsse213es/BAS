package avval

import "testing"

func TestEvaluateResponse_Remediated_HighConfidence(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Response: ResponseRemediated, EvidenceKind: EvidenceObserved},
		}},
	}
	outcome, conf, _ := EvaluateResponse(results, key("r1"))
	if outcome != ResponseRemediated {
		t.Errorf("outcome = %q, want %q", outcome, ResponseRemediated)
	}
	if conf != ConfidenceHigh {
		t.Errorf("confidence = %q, want %q", conf, ConfidenceHigh)
	}
}

func TestEvaluateResponse_NotApplicable_WhenNothingToRespondTo(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Response: ResponseNotApplicable, EvidenceKind: EvidenceObserved},
		}},
	}
	outcome, _, _ := EvaluateResponse(results, key("r2"))
	if outcome != ResponseNotApplicable {
		t.Errorf("outcome = %q, want %q", outcome, ResponseNotApplicable)
	}
}

func TestEvaluateResponse_ContradictoryAcrossControlSources_Unknown(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Response: ResponseRemediated, EvidenceKind: EvidenceObserved},
		}},
		{ControlSource: ControlSourceEDR, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceEDR, EventID: "e2", Response: ResponseFailed, EvidenceKind: EvidenceObserved},
		}},
	}
	outcome, conf, _ := EvaluateResponse(results, key("r3"))
	if outcome != ResponseUnknown {
		t.Errorf("outcome = %q, want %q", outcome, ResponseUnknown)
	}
	if conf != ConfidenceNone {
		t.Errorf("confidence = %q, want %q", conf, ConfidenceNone)
	}
}

func TestEvaluateResponse_NoEvidence_Unknown(t *testing.T) {
	outcome, conf, _ := EvaluateResponse(nil, key("r4"))
	if outcome != ResponseUnknown || conf != ConfidenceNone {
		t.Errorf("outcome/conf = %q/%q, want %q/%q", outcome, conf, ResponseUnknown, ConfidenceNone)
	}
}
