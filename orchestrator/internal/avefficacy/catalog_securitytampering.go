package avefficacy

import (
	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

// AudspectSecurityTamperingScenario builds the real, catalog-validated
// Security Tampering scenario (av.txt §3: "attempt a permitted, harmless
// security-setting modification -- did the control reject the change, and
// was it recorded?"), over the single dedicated catalog vector
// AV-CONFIG-003. AV-CONFIG-003 itself documents that it must only be
// dispatched against a dedicated test lab, never this build host or a
// production endpoint -- this scenario is fixture-backed only.
func AudspectSecurityTamperingScenario() (EfficacyScenario, error) {
	return NewEfficacyScenario(
		"AV-TAMPER-001", "Security Tampering",
		"establish whether tamper protection rejects an unauthorized attempt to disable real-time monitoring, and whether the attempt was recorded",
		[]string{"AV-CONFIG-003"},
		"endpoint has tamper protection enabled; this scenario's underlying vector must only ever be dispatched against a dedicated, non-production test lab",
		"product tamper-protection telemetry confirming the attempted change was rejected and logged",
		"manually authored from av.txt §3 'Security tampering'",
	)
}

// AudspectSecurityTamperingFixtures seeds AV-CONFIG-003 as blocked -- the
// expected outcome: tamper protection correctly rejects the unauthorized
// configuration-change attempt.
func AudspectSecurityTamperingFixtures() map[string]VectorFixture {
	return map[string]VectorFixture{
		"AV-CONFIG-003": {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-tamper-config-003")}},
	}
}

func loadSecurityTamperingScenario() (EfficacyScenario, ScenarioResult, error) {
	scenario, err := AudspectSecurityTamperingScenario()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline-policy", AudspectSecurityTamperingFixtures(), catalog)
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}
