package killchain

import "testing"

func TestAggregateDetection_AnyDetectionIsDetected(t *testing.T) {
	ev := AggregateDetection([]DetectionObservation{
		{Verdict: ObservationNotDetected, Provider: "sentinel"},
		{Verdict: ObservationDetected, Provider: "sentinel", AlertID: "alert-9"},
	})
	if ev.Value != DetectionDetected || ev.AlertID != "alert-9" || ev.TelemetrySource != "sentinel" {
		t.Fatalf("got %+v, want detected with alert-9 from sentinel", ev)
	}
}

// Detection is positive evidence, so a failed check elsewhere cannot cancel it.
func TestAggregateDetection_ErrorDoesNotCancelDetection(t *testing.T) {
	ev := AggregateDetection([]DetectionObservation{
		{Verdict: ObservationError, Provider: "defender"},
		{Verdict: ObservationDetected, Provider: "sentinel", AlertID: "a1"},
	})
	if ev.Value != DetectionDetected {
		t.Fatalf("value = %s, want detected", ev.Value)
	}
}

func TestAggregateDetection_NoObservationsIsInconclusive(t *testing.T) {
	if ev := AggregateDetection(nil); ev.Value != DetectionInconclusive {
		t.Fatalf("value = %s, want inconclusive", ev.Value)
	}
}

func TestAggregateDetection_ErrorOnlyIsInconclusive(t *testing.T) {
	ev := AggregateDetection([]DetectionObservation{{Verdict: ObservationError, Provider: "sentinel"}})
	if ev.Value != DetectionInconclusive {
		t.Fatalf("value = %s, want inconclusive", ev.Value)
	}
}

// A vendor's NotDetected does not prove telemetry was healthy or that the
// window closed. The adapter must leave both unknown, so the verdict engine
// refuses to score it as not-detected.
func TestAggregateDetection_NotDetectedDoesNotClaimHealthOrCompleteWindow(t *testing.T) {
	ev := AggregateDetection([]DetectionObservation{{Verdict: ObservationNotDetected, Provider: "sentinel"}})
	if ev.Value != DetectionNotDetected {
		t.Fatalf("value = %s, want not_detected", ev.Value)
	}
	if ev.TelemetryHealth == TelemetryHealthy {
		t.Fatalf("telemetry health was asserted with no health evidence")
	}
	if ev.WindowComplete == TriYes {
		t.Fatalf("window completeness was asserted with no evidence")
	}
}

// Healthy telemetry and a complete window are carried through only when the
// caller had evidence for them.
func TestAggregateDetection_CarriesHealthOnlyWhenKnown(t *testing.T) {
	ev := AggregateDetection([]DetectionObservation{{
		Verdict: ObservationNotDetected, Provider: "sentinel",
		TelemetryHealth: TelemetryHealthy, WindowComplete: TriYes,
	}})
	if ev.TelemetryHealth != TelemetryHealthy || ev.WindowComplete != TriYes {
		t.Fatalf("known health/window lost: %+v", ev)
	}
}

// Every not-detected provider must show healthy telemetry and a complete
// window. One healthy provider cannot cover an unknown one.
func TestAggregateDetection_AllNotDetectedMustBeHealthyToKnow(t *testing.T) {
	ev := AggregateDetection([]DetectionObservation{
		{Verdict: ObservationNotDetected, Provider: "sentinel", TelemetryHealth: TelemetryHealthy, WindowComplete: TriYes},
		{Verdict: ObservationNotDetected, Provider: "defender"},
	})
	if ev.TelemetryHealth == TelemetryHealthy {
		t.Fatalf("health asserted though one provider's health is unknown")
	}
	if ev.WindowComplete == TriYes {
		t.Fatalf("window asserted complete though one provider's window is unknown")
	}
}

func TestAggregateDetection_AllNotDetectedHealthyIsKnown(t *testing.T) {
	ev := AggregateDetection([]DetectionObservation{
		{Verdict: ObservationNotDetected, Provider: "sentinel", TelemetryHealth: TelemetryHealthy, WindowComplete: TriYes},
		{Verdict: ObservationNotDetected, Provider: "defender", TelemetryHealth: TelemetryHealthy, WindowComplete: TriYes},
	})
	if ev.TelemetryHealth != TelemetryHealthy || ev.WindowComplete != TriYes {
		t.Fatalf("all providers healthy but evidence lost: %+v", ev)
	}
}
