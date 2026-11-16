package detecteffectiveness

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

func TestTelemetryProbeVerdict(t *testing.T) {
	probe := models.SimulationResult{Technique: models.AttackTechnique{ID: "T1135"}, Result: models.ResultSkipped, SkipReason: models.SkipReasonTelemetryOnly}
	if v, ok := telemetryProbeVerdict(probe, map[string]bool{"T1135": true}); !ok || v != VerdictDetectedOnly {
		t.Errorf("a detected probe should count as detected-only, got %v %v", v, ok)
	}
	if _, ok := telemetryProbeVerdict(probe, map[string]bool{}); ok {
		t.Error("a probe nobody saw must not be counted as a miss")
	}
	plain := models.SimulationResult{Technique: models.AttackTechnique{ID: "T1135"}, Result: models.ResultSkipped, SkipReason: models.SkipReasonPlatformUnavailable}
	if _, ok := telemetryProbeVerdict(plain, map[string]bool{"T1135": true}); ok {
		t.Error("an ordinary skip is never counted, even if the technique was detected elsewhere")
	}
}
