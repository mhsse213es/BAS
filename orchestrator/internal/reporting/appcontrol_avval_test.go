package reporting

import (
	"testing"

	"github.com/audspect/bas/internal/avval"
)

// Phase 3: a path's prevention outcome and its telemetry visibility become two
// separate avval facts. Sysmon process-creation telemetry is an independent
// sensor's observation, not a security control's detection verdict, so it
// never sets DetectionDetected, and "not visible" never asserts
// DetectionNotObservedInWindow because Sysmon cannot prove a negative.
func TestAppControlToAVVal_PreventionAndVisibilityAreSeparate(t *testing.T) {
	cases := []struct {
		name         string
		row          AppControlPathResult
		wantPrev     avval.PreventionOutcome
		wantExec     avval.ExecutionObservation
		wantCoverage avval.Coverage
	}{
		{"blocked and visible",
			AppControlPathResult{Outcome: AppCtlBlockedAsExpected, Visibility: "visible"},
			avval.PreventionBlocked, avval.ExecutionNotObserved, avval.CoverageFound},
		{"blocked and not visible cannot assert absence of telemetry",
			AppControlPathResult{Outcome: AppCtlBlockedAsExpected, Visibility: "not_visible"},
			avval.PreventionBlocked, avval.ExecutionNotObserved, avval.CoverageSearchIncomplete},
		{"allowed and visible",
			AppControlPathResult{Outcome: AppCtlAllowedUnexpected, Visibility: "visible"},
			avval.PreventionAllowed, avval.ExecutionExecuted, avval.CoverageFound},
		{"allowed and not visible",
			AppControlPathResult{Outcome: AppCtlNotEnforced, Visibility: "not_visible"},
			avval.PreventionAllowed, avval.ExecutionExecuted, avval.CoverageSearchIncomplete},
		{"inconclusive with unknown visibility",
			AppControlPathResult{Outcome: AppCtlInconclusive, Visibility: "unknown"},
			avval.PreventionUnknown, avval.ExecutionUnknown, avval.CoverageSourceUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := AppControlToAVVal(c.row)
			if got.ControlSource != avval.ControlSourceIndependentSensor {
				t.Errorf("ControlSource = %s, want independent_sensor", got.ControlSource)
			}
			if got.Coverage != c.wantCoverage {
				t.Errorf("Coverage = %s, want %s", got.Coverage, c.wantCoverage)
			}
			if len(got.Observations) != 1 {
				t.Fatalf("want exactly one observation, got %d", len(got.Observations))
			}
			o := got.Observations[0]
			if o.Prevention != c.wantPrev {
				t.Errorf("Prevention = %s, want %s", o.Prevention, c.wantPrev)
			}
			if o.Execution != c.wantExec {
				t.Errorf("Execution = %s, want %s", o.Execution, c.wantExec)
			}
			if o.Detection == avval.DetectionDetected || o.Detection == avval.DetectionNotObservedInWindow {
				t.Errorf("telemetry visibility must not set Detection = %s", o.Detection)
			}
			if o.EvidenceKind != avval.EvidenceObserved {
				t.Errorf("EvidenceKind = %s, want observed", o.EvidenceKind)
			}
		})
	}
}
