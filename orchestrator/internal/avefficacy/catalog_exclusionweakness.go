package avefficacy

import (
	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

// AudspectExclusionWeaknessScenario builds the real, catalog-validated
// Exclusion Weakness scenario (av.txt §3: "benign test artifact inside a
// configured exclusion -- does the exclusion create a demonstrable
// protection gap?"), over the single dedicated catalog vector AV-CONFIG-001.
func AudspectExclusionWeaknessScenario() (EfficacyScenario, error) {
	return NewEfficacyScenario(
		"AV-EXCLUSION-001", "Exclusion Weakness",
		"establish whether a configured scan exclusion creates a demonstrable protection gap, by placing a known test artifact inside it",
		[]string{"AV-CONFIG-001"},
		"a specific directory has been added to the AV's scan exclusions as this scenario's precondition",
		"product scan/quarantine telemetry for the exclusion-zone artifact and the unexcluded comparison artifact",
		"manually authored from av.txt §3 'Exclusion weakness'",
	)
}

// AudspectExclusionWeaknessFixtures seeds AV-CONFIG-001 as allowed through
// -- an active exclusion legitimately means the AV never scans that path,
// so a ConfirmedGap result here is the expected, documented behavior of a
// working exclusion, not a product defect. The scenario exists to make
// that gap visible and attributable, never to hide it.
func AudspectExclusionWeaknessFixtures() map[string]VectorFixture {
	return map[string]VectorFixture{
		"AV-CONFIG-001": {PreventionEvidence: []avval.CollectionResult{missedEvidence("e-excl-config-001")}},
	}
}

func loadExclusionWeaknessScenario() (EfficacyScenario, ScenarioResult, error) {
	scenario, err := AudspectExclusionWeaknessScenario()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline-policy", AudspectExclusionWeaknessFixtures(), catalog)
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}
