package latency

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/grade"
	"time"
)

// calibrationRounds returns two rounds whose baseline median is about 0.15 ms.
func calibrationRounds() []Round {
	base := []time.Duration{150 * time.Microsecond, 150 * time.Microsecond, 150 * time.Microsecond}
	return []Round{{Baseline: base, Attack: ms(1300)}, {Baseline: base, Attack: ms(1300)}}
}

func TestCalibrationInsideBandPasses(t *testing.T) {
	if !CalibrationOK(calibrationRounds(), 0.15, 4) {
		t.Fatal("baseline at the declared value should be inside the band")
	}
}

// A machine whose baseline is four times slower than declared is outside a tolerance of 2.
func TestCalibrationOutsideBandFails(t *testing.T) {
	slow := []time.Duration{600 * time.Microsecond, 600 * time.Microsecond, 600 * time.Microsecond}
	rounds := []Round{{Baseline: slow, Attack: ms(1300)}, {Baseline: slow, Attack: ms(1300)}}
	if CalibrationOK(rounds, 0.15, 2) {
		t.Fatal("baseline four times the declared value should be outside a tolerance of 2")
	}
}

func TestCalibrationWithoutSamplesFails(t *testing.T) {
	if CalibrationOK(nil, 0.15, 4) {
		t.Fatal("no samples should not calibrate")
	}
}

// The guard's reason is a timing ERROR, never a pass or a failure.
func TestEnvironmentMismatchReasonIsNotAResult(t *testing.T) {
	out := grade.Error(grade.ReasonEnvironmentMismatch)
	if out.Result != grade.ERROR || out.Reason != "ENVIRONMENT_MISMATCH" {
		t.Fatalf("got %s / %s, want ERROR / ENVIRONMENT_MISMATCH", out.Result, out.Reason)
	}
}
