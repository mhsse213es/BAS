package avefficacy

import (
	"testing"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

// Review Focus: avefficacy must compose correctly with the REAL seed
// catalog from internal/avcatalog, not just hand-built test vectors --
// proving the full chain (real Vector -> real Expectations -> real
// avval.EvaluateClaim -> avefficacy bundling -> scenario aggregation)
// works end to end against both a prevention-shaped vector (AV-FILE-001)
// and a false-positive-shaped vector (AV-FP-001).
func TestEvaluateEfficacyScenario_RealSeedCatalog_MixedOutcome(t *testing.T) {
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectAVAttackCatalog: %v", err)
	}
	scenario, err := NewEfficacyScenario(
		"S-EFF-REAL", "real seed integration", "prove real catalog wiring",
		[]string{"AV-FILE-001", "AV-FP-001"}, "prereq", "evidence", "test",
	)
	if err != nil {
		t.Fatalf("NewEfficacyScenario: %v", err)
	}
	fixtures := map[string]VectorFixture{
		"AV-FILE-001": {PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e1")}},
		// AV-FP-001's primary leg is itself a ClaimFalsePositive claim;
		// a Blocked outcome here is a real, deliberate false positive.
		"AV-FP-001": {PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e2")}},
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline-policy", fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateEfficacyScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q (AV-FP-001's false positive must fail the scenario)", result.Outcome, ScenarioFail)
	}
	var sawFileVerified, sawFPGap bool
	for _, o := range result.VectorOutcomes {
		switch o.VectorID {
		case "AV-FILE-001":
			sawFileVerified = o.Finding == avval.FindingVerifiedProtection
		case "AV-FP-001":
			sawFPGap = o.Finding == avval.FindingConfirmedGap
		}
	}
	if !sawFileVerified {
		t.Error("AV-FILE-001 did not resolve to FindingVerifiedProtection")
	}
	if !sawFPGap {
		t.Error("AV-FP-001 did not resolve to FindingConfirmedGap")
	}
}
