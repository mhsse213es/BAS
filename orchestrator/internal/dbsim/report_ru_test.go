package dbsim

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/dlpreport"
)

// Ruling R-U (amends R-R): a definite FAIL dimension beats an unverifiable
// dimension unless there is an execution/evidence failure.

func TestRU_DefiniteFailBeatsUnverifiable(t *testing.T) {
	unver := okCorr()
	unver.Telemetry = dlpreport.TelemetryUnverifiable
	// Prevention definitely failed (expected deny, probe succeeded) while the
	// detection dimension is only an evidence gap.
	o := succeeded()
	o.Corr = unver
	g := grade(meta(), o)
	if g.Result != ResultFail {
		t.Fatalf("got %s (%s), want FAIL", g.Result, g.Reason)
	}
	if g.Dims.Prevention != DimFail || g.Dims.Detection != DimUnverifiable {
		t.Fatalf("dims %+v", g.Dims)
	}
}

func TestRU_ExecutionErrorStillBeatsFail(t *testing.T) {
	o := succeeded()
	o.ExecutionError = "dispatch failed"
	if got := ToRunResult(meta(), o); got != ResultError {
		t.Fatalf("got %s", got)
	}
}

func TestRU_UnverifiableAloneIsStillError(t *testing.T) {
	unver := okCorr()
	unver.Telemetry = dlpreport.TelemetryUnverifiable
	o := denied()
	o.Corr = unver
	if got := ToRunResult(meta(), o); got != ResultError {
		t.Fatalf("got %s", got)
	}
}

func TestRU_AbsentWithNoMatchOrEmptyMatchIsFail(t *testing.T) {
	for _, m := range []MatchGrade{MatchNone, ""} {
		c := Correlation{Evaluated: true, Telemetry: dlpreport.TelemetryAbsent, Response: dlpreport.ResponseNotTested, Match: m}
		o := denied()
		o.Corr = c
		if got := ToRunResult(meta(), o); got != ResultFail {
			t.Errorf("match %q: got %s want FAIL", m, got)
		}
	}
}

func TestRU_DelayedWithExactMarkerIsFail(t *testing.T) {
	c := okCorr()
	c.Telemetry, c.Match = dlpreport.TelemetryDelayed, MatchExactMarker
	o := denied()
	o.Corr = c
	if got := ToRunResult(meta(), o); got != ResultFail {
		t.Fatalf("got %s want FAIL (outside SLA window)", got)
	}
}

// End to end: the correlator's output flows through the report layer.
func TestRU_CorrelatorResultFeedsGrade(t *testing.T) {
	good := Result{Match: MatchExact, Telemetry: dlpreport.TelemetryPresent, Response: dlpreport.ResponseNotTested, Alerts: nil}
	o := denied()
	o.Corr = good.ToCorrelation()
	if got := ToRunResult(meta(), o); got != ResultPass {
		t.Fatalf("exact+present: %s", got)
	}
	amb := Result{Match: MatchAmbiguous, Telemetry: dlpreport.TelemetryUnverifiable, Response: dlpreport.ResponseNotTested}
	o.Corr = amb.ToCorrelation()
	if got := ToRunResult(meta(), o); got != ResultError {
		t.Fatalf("ambiguous: %s", got)
	}
	if !strings.Contains(string(MatchAmbiguous), "ambiguous") {
		t.Fatal("unexpected grade vocabulary")
	}
}
