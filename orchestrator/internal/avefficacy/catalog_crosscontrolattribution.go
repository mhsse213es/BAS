package avefficacy

import (
	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

// crossControlAttributionVectorIDs reuse existing seed-catalog vectors
// (av.txt §3 "Cross-control attribution": "endpoint simulation with AV,
// EDR, SIEM and firewall telemetry -- which control actually prevented or
// detected the activity?"). AV-NET-001 already documents this exact
// attribution requirement in its own doc comment; this scenario is the
// first to exercise it with real multi-ControlSource evidence.
var crossControlAttributionVectorIDs = []string{"AV-FILE-001", "AV-NET-001"}

// AudspectCrossControlAttributionScenario builds the real,
// catalog-validated Cross-Control Attribution EfficacyScenario.
func AudspectCrossControlAttributionScenario() (EfficacyScenario, error) {
	return NewEfficacyScenario(
		"AV-CROSSATTR-001", "Cross-Control Attribution",
		"establish which control actually prevented each activity, never crediting the AV engine for a block a different control source (e.g. network control) actually performed",
		crossControlAttributionVectorIDs,
		"endpoint has signature-based scanning and network/web-gateway control, each independently instrumented",
		"per-ControlSource collection results for each vector, so the resolved Finding can be traced to the control source(s) that actually supplied evidence",
		"manually authored from av.txt §3 'Cross-control attribution' and av.txt §2.E's attribution requirement, reusing existing catalog vectors",
	)
}

// AudspectCrossControlAttributionFixtures seeds AV-FILE-001 with ordinary
// AV-engine evidence (the AV engine genuinely blocked it) and AV-NET-001
// with evidence from ControlSourceNetworkControl ONLY -- no AV-engine
// observation is supplied at all, so the resolved VerifiedProtection for
// AV-NET-001 is structurally attributable to the network control, never
// fabricated as an AV-engine result it never produced.
func AudspectCrossControlAttributionFixtures() map[string]VectorFixture {
	networkBlocked := []avval.CollectionResult{{
		ControlSource: avval.ControlSourceNetworkControl, Coverage: avval.CoverageFound,
		Observations: []avval.Observation{
			{ControlSource: avval.ControlSourceNetworkControl, EventID: "e-crossattr-net-001", Prevention: avval.PreventionBlocked, EvidenceKind: avval.EvidenceObserved},
		},
	}}
	return map[string]VectorFixture{
		"AV-FILE-001": {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-crossattr-file-001")}},
		"AV-NET-001":  {PreventionEvidence: networkBlocked},
	}
}

func loadCrossControlAttributionScenario() (EfficacyScenario, ScenarioResult, error) {
	scenario, err := AudspectCrossControlAttributionScenario()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline-policy", AudspectCrossControlAttributionFixtures(), catalog)
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}
