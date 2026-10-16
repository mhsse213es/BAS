package avval

import "testing"

func TestCorrelate_CrossControlSourceAgreement(t *testing.T) {
	key := CorrelationKey{TestExecutionID: "t1"}
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Prevention: PreventionBlocked},
		}},
		{ControlSource: ControlSourceIndependentSensor, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceIndependentSensor, EventID: "e2", Prevention: PreventionBlocked},
		}},
	}
	view := Correlate(key, results)
	if view.PreventionAx.State != AxisAgree || view.PreventionAx.Prevention != PreventionBlocked {
		t.Errorf("PreventionAx = %+v, want Agree/Blocked", view.PreventionAx)
	}
}

func TestCorrelate_DuplicateEventID_NotIndependentCorroboration(t *testing.T) {
	key := CorrelationKey{TestExecutionID: "t1"}
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "dup", Prevention: PreventionBlocked},
			{ControlSource: ControlSourceAVEngine, EventID: "dup", Prevention: PreventionAllowed}, // same event, re-reported differently
		}},
	}
	view := Correlate(key, results)
	// Only the first instance of "dup" counts, so this control source
	// contributes exactly one value -- Agree on Blocked, not Ambiguous.
	if view.PreventionAx.State != AxisAgree || view.PreventionAx.Prevention != PreventionBlocked {
		t.Errorf("PreventionAx = %+v, want Agree/Blocked (dup event not independent)", view.PreventionAx)
	}
}

func TestCorrelate_SameControlSourceDisagreement_Ambiguous(t *testing.T) {
	key := CorrelationKey{TestExecutionID: "t1"}
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Prevention: PreventionBlocked},
			{ControlSource: ControlSourceAVEngine, EventID: "e2", Prevention: PreventionAllowed},
		}},
	}
	view := Correlate(key, results)
	if view.PreventionAx.State != AxisAmbiguous {
		t.Errorf("PreventionAx.State = %q, want %q", view.PreventionAx.State, AxisAmbiguous)
	}
}

func TestCorrelate_CrossControlSourceContradiction(t *testing.T) {
	key := CorrelationKey{TestExecutionID: "t1"}
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Prevention: PreventionBlocked},
		}},
		{ControlSource: ControlSourceEDR, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceEDR, EventID: "e2", Prevention: PreventionAllowed},
		}},
	}
	view := Correlate(key, results)
	if view.PreventionAx.State != AxisContradictory {
		t.Errorf("PreventionAx.State = %q, want %q", view.PreventionAx.State, AxisContradictory)
	}
}

func TestCorrelate_IncompleteCoverage_NotObservedNotAsserted(t *testing.T) {
	key := CorrelationKey{TestExecutionID: "t1"}
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageSearchIncomplete, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Detection: DetectionNotObservedInWindow},
		}},
	}
	view := Correlate(key, results)
	if view.DetectionAx.State != AxisUnknown {
		t.Errorf("DetectionAx.State = %q, want %q (incomplete coverage must not assert a negative)", view.DetectionAx.State, AxisUnknown)
	}
}

func TestCorrelate_ResponseAxis_NotApplicableAgreed(t *testing.T) {
	key := CorrelationKey{TestExecutionID: "t1"}
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound, Observations: []Observation{
			{ControlSource: ControlSourceAVEngine, EventID: "e1", Response: ResponseNotApplicable},
		}},
	}
	view := Correlate(key, results)
	if view.ResponseAx.State != AxisAgree || view.ResponseAx.Response != ResponseNotApplicable {
		t.Errorf("ResponseAx = %+v, want Agree/NotApplicable", view.ResponseAx)
	}
}
