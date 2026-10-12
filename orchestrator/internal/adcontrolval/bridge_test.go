package adcontrolval

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/admatrix"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/controlval"
)

func TestActionForPrimitive_IsPrimitiveID(t *testing.T) {
	if got := ActionForPrimitive(adprimitive.Primitive{ID: "dcsync"}); got != "dcsync" {
		t.Fatalf("action = %q, want dcsync (verbatim primitive id, no normalization)", got)
	}
}

func TestCorrelationKeyFor_CarriesExactRunTargetActionWindow(t *testing.T) {
	w := controlval.TimeWindow{Start: time.Unix(100, 0), End: time.Unix(200, 0)}
	k := CorrelationKeyFor(adprimitive.Primitive{ID: "kerberoast"}, "run1", "dc01", w)
	if k.RunID != "run1" || k.Target != "dc01" || k.Action != "kerberoast" {
		t.Fatalf("key = %+v, want run1/dc01/kerberoast", k)
	}
	if k.Window != w {
		t.Fatalf("window = %+v, want %+v (carried verbatim)", k.Window, w)
	}
}

func TestToEfficacyState_MapsVerdictAndObservation(t *testing.T) {
	v := controlval.Validation{
		Expectation: controlval.Expectation{Expected: controlval.OutcomeBlocked},
		Observation: &controlval.Observation{Provider: "silverfort", Outcome: controlval.OutcomeBlocked,
			EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
		Verdict: controlval.VerdictPass,
		Reason:  "observed outcome matches expectation",
	}
	s := ToEfficacyState(v)
	if !s.Evaluated || s.Verdict != "PASS" || s.Provider != "silverfort" ||
		s.Observed != "blocked" || s.Expected != "blocked" ||
		s.EvidenceKind != "observed" || s.Confidence != "high" || s.Reason == "" {
		t.Fatalf("mapping wrong: %+v", s)
	}
}

func TestToEfficacyState_NilObservationManufacturesNothing(t *testing.T) {
	// Criterion 3: a nil observation yields Evaluated=true with the verdict, but
	// NO fabricated provider/outcome/evidenceKind/confidence.
	v := controlval.Validation{
		Expectation: controlval.Expectation{Expected: controlval.OutcomeBlocked},
		Verdict:     controlval.VerdictSkipped, Reason: "control response not recorded",
	}
	s := ToEfficacyState(v)
	if !s.Evaluated {
		t.Fatal("a produced validation is Evaluated even with no observation")
	}
	if s.Verdict != "SKIPPED" || s.Expected != "blocked" {
		t.Fatalf("verdict/expected wrong: %+v", s)
	}
	if s.Provider != "" || s.Observed != "" || s.EvidenceKind != "" || s.Confidence != "" {
		t.Fatalf("nil observation must not manufacture evidence, got %+v", s)
	}
}

func TestAttach_LeavesFiveAxesUntouched(t *testing.T) {
	cs := admatrix.CapabilityState{
		PrimitiveID:         "dcsync",
		Modeled:             true,
		ScenarioComposed:    true,
		ExecutionValidation: admatrix.ExecCompleted,
		DetectionValidation: admatrix.DetTelemetryObserved,
	}
	out := Attach(cs, controlval.Validation{Verdict: controlval.VerdictPass})

	if out.Modeled != cs.Modeled {
		t.Error("Attach changed Modeled")
	}
	if out.ScenarioComposed != cs.ScenarioComposed {
		t.Error("Attach changed ScenarioComposed")
	}
	if out.ExecutionValidation != cs.ExecutionValidation {
		t.Error("Attach changed ExecutionValidation")
	}
	if out.DetectionValidation != cs.DetectionValidation {
		t.Error("Attach changed DetectionValidation")
	}
	if out.ContentAvailability != cs.ContentAvailability {
		t.Error("Attach changed ContentAvailability")
	}
	if !out.ControlEfficacy.Evaluated || out.ControlEfficacy.Verdict != "PASS" {
		t.Fatalf("Attach must set only the sixth axis: %+v", out.ControlEfficacy)
	}
}
