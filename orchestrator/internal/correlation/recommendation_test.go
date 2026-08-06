package correlation

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/threatpriority"
	"github.com/audspect/bas/internal/verification"
)

func TestLookupValidation_PreventionCheckedFirst(t *testing.T) {
	now := time.Now()
	prevention := map[string]threatpriority.VerdictEntry{"T1059": {Verdict: "pass", At: now}}
	validation := map[string]threatpriority.VerdictEntry{"T1059": {Verdict: verification.ResultDetected, At: now.Add(-time.Hour)}}

	got := lookupValidation("T1059", prevention, validation)
	if got == nil || got.Source != "prevention" || got.Verdict != "pass" {
		t.Fatalf("got %+v, want prevention/pass (prevention takes precedence)", got)
	}
}

func TestLookupValidation_FallsBackToDetection(t *testing.T) {
	prevention := map[string]threatpriority.VerdictEntry{}
	validation := map[string]threatpriority.VerdictEntry{"T1059": {Verdict: verification.ResultDetected}}

	got := lookupValidation("T1059", prevention, validation)
	if got == nil || got.Source != "detection" || got.Verdict != verification.ResultDetected {
		t.Fatalf("got %+v, want detection/%s", got, verification.ResultDetected)
	}
}

func TestLookupValidation_NeitherPresent_ReturnsNil(t *testing.T) {
	got := lookupValidation("T1059", map[string]threatpriority.VerdictEntry{}, map[string]threatpriority.VerdictEntry{})
	if got != nil {
		t.Fatalf("got %+v, want nil (never validated)", got)
	}
}

func TestLookupValidation_CaseInsensitive(t *testing.T) {
	prevention := map[string]threatpriority.VerdictEntry{"T1059": {Verdict: "pass"}}
	got := lookupValidation("t1059", prevention, map[string]threatpriority.VerdictEntry{})
	if got == nil {
		t.Fatal("expected a match regardless of input case")
	}
}

func TestComputeRecommendation_NeverValidated_HasScenario(t *testing.T) {
	got := computeRecommendation(nil, true)
	if got.Action != "run" || got.Reason != "Never validated" {
		t.Errorf("got %+v, want {run, Never validated}", got)
	}
}

func TestComputeRecommendation_NeverValidated_NoScenario(t *testing.T) {
	got := computeRecommendation(nil, false)
	if got.Action != "no_scenario" {
		t.Errorf("got %+v, want action=no_scenario", got)
	}
}

func TestComputeRecommendation_FailedPrevention_Revalidate(t *testing.T) {
	v := &ValidationStatus{Verdict: "fail", Source: "prevention", At: time.Now().Add(-72 * time.Hour)}
	got := computeRecommendation(v, true)
	if got.Action != "revalidate" {
		t.Errorf("Action = %q, want revalidate", got.Action)
	}
}

func TestComputeRecommendation_NotDetected_Revalidate(t *testing.T) {
	v := &ValidationStatus{Verdict: verification.ResultNotDetected, Source: "detection", At: time.Now()}
	got := computeRecommendation(v, true)
	if got.Action != "revalidate" {
		t.Errorf("Action = %q, want revalidate", got.Action)
	}
}

func TestComputeRecommendation_PassedPrevention_None(t *testing.T) {
	v := &ValidationStatus{Verdict: "pass", Source: "prevention", At: time.Now()}
	got := computeRecommendation(v, true)
	if got.Action != "none" {
		t.Errorf("Action = %q, want none", got.Action)
	}
}

func TestComputeRecommendation_Detected_None(t *testing.T) {
	v := &ValidationStatus{Verdict: verification.ResultDetected, Source: "detection", At: time.Now()}
	got := computeRecommendation(v, true)
	if got.Action != "none" {
		t.Errorf("Action = %q, want none", got.Action)
	}
}
