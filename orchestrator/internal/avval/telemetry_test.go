package avval

import "testing"

func TestEvaluateTelemetryCompleteness_AllFound_Complete(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound},
		{ControlSource: ControlSourceIndependentSensor, Coverage: CoverageSearchedVerifiedNone},
	}
	state, _ := EvaluateTelemetryCompleteness(results)
	if state != TelemetryComplete {
		t.Errorf("state = %q, want %q", state, TelemetryComplete)
	}
}

func TestEvaluateTelemetryCompleteness_OnePresentOneIncomplete_Partial(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageFound},
		{ControlSource: ControlSourceEDR, Coverage: CoverageSearchIncomplete},
	}
	state, _ := EvaluateTelemetryCompleteness(results)
	if state != TelemetryPartial {
		t.Errorf("state = %q, want %q", state, TelemetryPartial)
	}
}

func TestEvaluateTelemetryCompleteness_SourceUnavailable_Unavailable(t *testing.T) {
	results := []CollectionResult{
		{ControlSource: ControlSourceAVEngine, Coverage: CoverageSourceUnavailable},
	}
	state, _ := EvaluateTelemetryCompleteness(results)
	if state != TelemetryUnavailable {
		t.Errorf("state = %q, want %q", state, TelemetryUnavailable)
	}
}

func TestEvaluateTelemetryCompleteness_NoResults_Unavailable(t *testing.T) {
	state, _ := EvaluateTelemetryCompleteness(nil)
	if state != TelemetryUnavailable {
		t.Errorf("state = %q, want %q", state, TelemetryUnavailable)
	}
}
