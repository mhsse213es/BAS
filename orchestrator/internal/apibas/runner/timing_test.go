package runner

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/grade"
)

// timingOutcome is the only place a timing PASS can come from. These cases pin the
// invariant that no verdict other than PASS can become PASS, and that a validity failure
// is never overridden.
func TestTimingOutcomeNeverPassesFromNonPassVerdict(t *testing.T) {
	nonPass := map[string]grade.Outcome{
		"error":        grade.Error(grade.ReasonEnvironmentMismatch),
		"inconclusive": grade.Skip(grade.ReasonExcessiveVariance),
		"fail":         {Result: grade.FAIL, Exploitability: grade.Exploited},
	}
	for name, v := range nonPass {
		for _, breach := range []bool{false, true} {
			if got := timingOutcome(v, breach); got.Result == grade.PASS {
				t.Errorf("%s with breach=%v became PASS", name, breach)
			}
		}
	}
}

func TestTimingOutcomeErrorIsNeverOverridden(t *testing.T) {
	v := grade.Error(grade.ReasonEnvironmentMismatch)
	got := timingOutcome(v, true)
	if got.Result != grade.ERROR || got.Reason != grade.ReasonEnvironmentMismatch {
		t.Fatalf("ERROR with a resource breach became %s / %s", got.Result, got.Reason)
	}
}

func TestTimingOutcomePassNeedsNoBreach(t *testing.T) {
	pass := grade.Outcome{Result: grade.PASS, Exploitability: grade.NotExploited}
	if got := timingOutcome(pass, false); got.Result != grade.PASS {
		t.Fatalf("clean PASS became %s", got.Result)
	}
	if got := timingOutcome(pass, true); got.Result != grade.FAIL {
		t.Fatalf("PASS with a work-unit breach became %s, want FAIL", got.Result)
	}
}

// calibrationCheck refuses to grade a scenario whose declared values differ from its
// record, and refuses a scenario with no calibration at all.
func TestCalibrationCheckRefusesUndeclaredCalibration(t *testing.T) {
	reason, _ := calibrationCheck(scenarioWithoutCalibration())
	if reason != grade.ReasonCalibrationMissing {
		t.Fatalf("reason = %q, want CALIBRATION_MISSING", reason)
	}
}

func scenarioWithoutCalibration() contract.Scenario {
	return contract.Scenario{ID: "API-BAS-ABUSE-002", Latency: &contract.LatencyPolicy{CeilingMs: 250, MinRatio: 5, MaxCV: 0.5, Warmup: 3, Trials: 10, Rounds: 3}}
}

func abuse002FromCatalog(t *testing.T) contract.Scenario {
	t.Helper()
	all, err := catalog.All()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range all {
		if s.ID == "API-BAS-ABUSE-002" {
			return s
		}
	}
	t.Fatal("ABUSE-002 not in catalog")
	return contract.Scenario{}
}

// The shipped catalog must match its shipped record exactly, or timing is never graded.
func TestCalibrationCheckAcceptsShippedRecord(t *testing.T) {
	if reason, detail := calibrationCheck(abuse002FromCatalog(t)); reason != "" {
		t.Fatalf("shipped catalog refused: %s (%s)", reason, detail)
	}
}

// A drifted threshold is refused. Nothing widens to absorb it.
func TestCalibrationCheckRefusesDriftedThreshold(t *testing.T) {
	s := abuse002FromCatalog(t)
	s.Latency.CeilingMs = 500
	if reason, _ := calibrationCheck(s); reason != grade.ReasonCalibrationMismatch {
		t.Fatalf("drifted ceiling reason = %q, want CALIBRATION_MISMATCH", reason)
	}
}

func TestCalibrationCheckRefusesUnknownVersion(t *testing.T) {
	s := abuse002FromCatalog(t)
	s.Calibration.Version = 99
	if reason, _ := calibrationCheck(s); reason != grade.ReasonCalibrationMissing {
		t.Fatalf("unknown version reason = %q, want CALIBRATION_MISSING", reason)
	}
}
