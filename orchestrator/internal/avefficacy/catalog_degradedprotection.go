package avefficacy

import (
	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

// AudspectDegradedProtectionScenario builds the real, catalog-validated
// Degraded Protection scenario (av.txt §3: "controlled test with cloud
// reputation unavailable -- does local protection still operate as
// expected?"), over the single dedicated catalog vector AV-CONFIG-002.
func AudspectDegradedProtectionScenario() (EfficacyScenario, error) {
	return NewEfficacyScenario(
		"AV-DEGRADED-001", "Degraded Protection",
		"establish whether local, offline protection still operates as expected when cloud-reputation lookup is unavailable",
		[]string{"AV-CONFIG-002"},
		"the endpoint's cloud-reputation lookup has been disabled or blocked as this scenario's precondition",
		"product telemetry confirming whether the local engine still blocked the artifact without cloud lookup",
		"manually authored from av.txt §3 'Degraded protection'",
	)
}

// AudspectDegradedProtectionFixtures seeds AV-CONFIG-002 as blocked --
// the expected, reassuring outcome: local protection still works without
// cloud connectivity.
func AudspectDegradedProtectionFixtures() map[string]VectorFixture {
	return map[string]VectorFixture{
		"AV-CONFIG-002": {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-degraded-config-002")}},
	}
}

func loadDegradedProtectionScenario() (EfficacyScenario, ScenarioResult, error) {
	scenario, err := AudspectDegradedProtectionScenario()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline-policy", AudspectDegradedProtectionFixtures(), catalog)
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}
