package avefficacy

import (
	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

// endpointHealthVectorIDs reuse existing seed-catalog vectors (av.txt §3
// "Endpoint health": "stale definitions, disabled sensor or policy drift
// -- is the endpoint genuinely protected, not merely reporting as
// installed?"). This family is a direct application of avval's existing
// Configuration dimension, not a new attack surface, so it deliberately
// adds no new catalog vectors.
var endpointHealthVectorIDs = []string{"AV-FILE-001", "AV-PERSIST-001"}

// AudspectEndpointHealthScenario builds the real, catalog-validated
// Endpoint Health EfficacyScenario.
func AudspectEndpointHealthScenario() (EfficacyScenario, error) {
	return NewEfficacyScenario(
		"AV-HEALTH-001", "Endpoint Health",
		"establish whether the endpoint is genuinely protected -- current signatures, real-time protection active, no policy drift -- not merely reporting as installed",
		endpointHealthVectorIDs,
		"endpoint has signature and/or behavioral AV/NGAV coverage per each contributing vector's own preconditions",
		"product configuration snapshot (real-time protection state, signature age) compared against the required baseline",
		"manually authored from av.txt §3 'Endpoint health', reusing existing catalog vectors' Configuration dimension",
	)
}

// AudspectEndpointHealthFixtures seeds both vectors as cleanly blocked
// (Finding is not this scenario's subject) with Configuration evidence as
// the deliberate variable under test. AV-PERSIST-001 carries a deliberate
// stale-signature policy gap (240h old against a 24h baseline) -- proving
// that a clean prevention result right now does not mean the endpoint is
// genuinely healthy: stale signatures are a real, independently-reported
// failure (av.txt §4's non-offsetting rule applied to Configuration).
func AudspectEndpointHealthFixtures() map[string]VectorFixture {
	healthyConfig := &ConfigurationCheck{
		Snapshot: avval.ConfigurationSnapshot{RealTimeProtectionEnabled: true, SignatureAgeHours: 4, Coverage: avval.CoverageFound},
		Baseline: avval.ConfigurationBaseline{RequireRealTimeProtection: true, MaxSignatureAgeHours: 24},
	}
	staleConfig := &ConfigurationCheck{
		Snapshot: avval.ConfigurationSnapshot{RealTimeProtectionEnabled: true, SignatureAgeHours: 240, Coverage: avval.CoverageFound},
		Baseline: avval.ConfigurationBaseline{RequireRealTimeProtection: true, MaxSignatureAgeHours: 24},
	}
	return map[string]VectorFixture{
		"AV-FILE-001":    {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-health-file-001")}, Configuration: healthyConfig},
		"AV-PERSIST-001": {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-health-persist-001")}, Configuration: staleConfig},
	}
}

func loadEndpointHealthScenario() (EfficacyScenario, ScenarioResult, error) {
	scenario, err := AudspectEndpointHealthScenario()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline-policy", AudspectEndpointHealthFixtures(), catalog)
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}
