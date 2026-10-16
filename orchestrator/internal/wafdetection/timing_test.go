package wafdetection

import (
	"testing"
	"time"
)

func TestNewTimingScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewTimingScenario("WAFDETECT-004", 5*time.Minute, "an alert must surface within 5 minutes of the triggering event", "manually authored")
	if err != nil {
		t.Fatalf("NewTimingScenario: %v", err)
	}
	if s.ID != "WAFDETECT-004" {
		t.Errorf("ID = %q, want %q", s.ID, "WAFDETECT-004")
	}
}

func TestNewTimingScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewTimingScenario("", 5*time.Minute, "x", "y")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewTimingScenario_EmptyDescription_Rejected(t *testing.T) {
	_, err := NewTimingScenario("WAFDETECT-004", 5*time.Minute, "", "y")
	if err == nil {
		t.Fatal("want error for empty description, got nil")
	}
}

func TestNewTimingScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewTimingScenario("WAFDETECT-004", 5*time.Minute, "x", "")
	if err == nil {
		t.Fatal("want error for empty provenance, got nil")
	}
}

// Review Focus: a zero/negative SLA must not silently make every latency
// "within SLA".
func TestNewTimingScenario_ZeroSLA_Rejected(t *testing.T) {
	_, err := NewTimingScenario("WAFDETECT-004", 0, "x", "y")
	if err == nil {
		t.Fatal("want error for SLA <= 0, got nil")
	}
}

func TestNewTimingScenario_NegativeSLA_Rejected(t *testing.T) {
	_, err := NewTimingScenario("WAFDETECT-004", -time.Minute, "x", "y")
	if err == nil {
		t.Fatal("want error for SLA <= 0, got nil")
	}
}

func mustTimingScenario(t *testing.T) TimingScenario {
	t.Helper()
	s, err := NewTimingScenario("WAFDETECT-004", 5*time.Minute, "x", "y")
	if err != nil {
		t.Fatalf("NewTimingScenario: %v", err)
	}
	return s
}

func TestEvaluateResponseTiming_ZeroEventTimestamp_ReturnsInconclusive(t *testing.T) {
	scenario := mustTimingScenario(t)
	verdict, _, err := EvaluateResponseTiming(scenario, time.Time{}, time.Now())
	if err != nil {
		t.Fatalf("EvaluateResponseTiming: %v", err)
	}
	if verdict != TimingInconclusive {
		t.Errorf("verdict = %q, want %q", verdict, TimingInconclusive)
	}
}

func TestEvaluateResponseTiming_ZeroAlertTimestamp_ReturnsInconclusive(t *testing.T) {
	scenario := mustTimingScenario(t)
	verdict, _, err := EvaluateResponseTiming(scenario, time.Now(), time.Time{})
	if err != nil {
		t.Fatalf("EvaluateResponseTiming: %v", err)
	}
	if verdict != TimingInconclusive {
		t.Errorf("verdict = %q, want %q", verdict, TimingInconclusive)
	}
}

// Review Focus: a nonsensical ordering must not silently compute a
// negative latency.
func TestEvaluateResponseTiming_AlertBeforeEvent_ReturnsInconclusive(t *testing.T) {
	scenario := mustTimingScenario(t)
	event := time.Now()
	alert := event.Add(-time.Minute)
	verdict, _, err := EvaluateResponseTiming(scenario, event, alert)
	if err != nil {
		t.Fatalf("EvaluateResponseTiming: %v", err)
	}
	if verdict != TimingInconclusive {
		t.Errorf("verdict = %q, want %q", verdict, TimingInconclusive)
	}
}

func TestEvaluateResponseTiming_LatencyAtSLABoundary_ReturnsWithinSLA(t *testing.T) {
	scenario := mustTimingScenario(t)
	event := time.Now()
	alert := event.Add(5 * time.Minute)
	verdict, reason, err := EvaluateResponseTiming(scenario, event, alert)
	if err != nil {
		t.Fatalf("EvaluateResponseTiming: %v", err)
	}
	if verdict != TimingWithinSLA {
		t.Errorf("verdict = %q, want %q", verdict, TimingWithinSLA)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateResponseTiming_LatencyOverSLA_ReturnsSLABreached(t *testing.T) {
	scenario := mustTimingScenario(t)
	event := time.Now()
	alert := event.Add(5*time.Minute + time.Second)
	verdict, _, err := EvaluateResponseTiming(scenario, event, alert)
	if err != nil {
		t.Fatalf("EvaluateResponseTiming: %v", err)
	}
	if verdict != TimingSLABreached {
		t.Errorf("verdict = %q, want %q", verdict, TimingSLABreached)
	}
}
