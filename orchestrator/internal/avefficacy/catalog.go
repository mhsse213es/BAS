package avefficacy

import (
	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

// avAssessmentVectorIDs is the real seed catalog's concretely dispatchable
// vector set -- the same set internal/avscenario.AudspectAVAssessmentScenario
// builds for real agent dispatch. The efficacy scenario here evaluates
// fixture evidence for that same vector set so the console-facing
// assessment and the dispatchable scenario can never silently diverge.
var avAssessmentVectorIDs = []string{
	"AV-FILE-001", "AV-FILE-002",
	"AV-SCRIPT-001", "AV-SCRIPT-002",
	"AV-BEHAV-002",
	"AV-NET-001",
	"AV-PERSIST-001", "AV-PERSIST-002",
	"AV-FP-001", "AV-FP-002",
}

func blockedEvidence(eventID string) avval.CollectionResult {
	return avval.CollectionResult{ControlSource: avval.ControlSourceAVEngine, Coverage: avval.CoverageFound, Observations: []avval.Observation{
		{ControlSource: avval.ControlSourceAVEngine, EventID: eventID, Prevention: avval.PreventionBlocked, EvidenceKind: avval.EvidenceObserved},
	}}
}

func missedEvidence(eventID string) avval.CollectionResult {
	return avval.CollectionResult{ControlSource: avval.ControlSourceAVEngine, Coverage: avval.CoverageSearchedVerifiedNone, Observations: []avval.Observation{
		{ControlSource: avval.ControlSourceAVEngine, EventID: eventID, Prevention: avval.PreventionAllowed, Detection: avval.DetectionNotObservedInWindow, EvidenceKind: avval.EvidenceObserved},
	}}
}

func allowedEvidence(eventID string) avval.CollectionResult {
	return avval.CollectionResult{ControlSource: avval.ControlSourceAVEngine, Coverage: avval.CoverageFound, Observations: []avval.Observation{
		{ControlSource: avval.ControlSourceAVEngine, EventID: eventID, Prevention: avval.PreventionAllowed, EvidenceKind: avval.EvidenceObserved},
	}}
}

// AudspectAVAssessmentScenario builds the real, catalog-validated AV/NGAV
// assessment EfficacyScenario -- the console-facing counterpart of
// internal/avscenario.AudspectAVAssessmentScenario's dispatchable
// scenario.Scenario, over the same 10 vector IDs.
func AudspectAVAssessmentScenario() (EfficacyScenario, error) {
	return NewEfficacyScenario(
		"AV-ASSESSMENT-001", "AV/NGAV Assessment",
		"establish, with evidence, whether the endpoint's antivirus/NGAV control genuinely prevents the catalog's concretely dispatchable attack vectors without disrupting legitimate workloads",
		avAssessmentVectorIDs,
		"endpoint has signature and/or behavioral AV/NGAV coverage per each contributing vector's own preconditions",
		"product telemetry, OS-level process/file events, and (for false-positive vectors) confirmation the legitimate workload completed undisrupted",
		"manually authored from av.txt §3's scenario families, scoped to avcatalog's current dispatchable vector set",
	)
}

// AudspectAVAssessmentFixtures seeds fixture evidence for 8 of
// AudspectAVAssessmentScenario's 10 contributing vectors. AV-PERSIST-002 is
// a deliberate simulated bypass (ConfirmedGap), mirroring wafassessment's
// own "one deliberate miss among several blocks" seed pattern. AV-FILE-002
// and AV-SCRIPT-002 are deliberately absent -- untested, never silently
// scored as passing. Every outcome here is fixture evidence, never a
// claim about a live endpoint run (see fixtureOnlyDisclosure).
func AudspectAVAssessmentFixtures() map[string]VectorFixture {
	return map[string]VectorFixture{
		"AV-FILE-001":    {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-file-001")}},
		"AV-SCRIPT-001":  {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-script-001")}},
		"AV-BEHAV-002":   {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-behav-002")}},
		"AV-NET-001":     {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-net-001")}},
		"AV-PERSIST-001": {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-persist-001")}},
		"AV-PERSIST-002": {PreventionEvidence: []avval.CollectionResult{missedEvidence("e-persist-002")}},
		"AV-FP-001":      {PreventionEvidence: []avval.CollectionResult{allowedEvidence("e-fp-001")}},
		"AV-FP-002":      {PreventionEvidence: []avval.CollectionResult{allowedEvidence("e-fp-002")}},
	}
}

// loadAVAssessmentScenario builds AudspectAVAssessmentScenario's real seed
// scenario, fixtures, and the real avcatalog, then evaluates them -- the
// one function EvaluateScenarioBySlug calls for the "av-assessment" slug.
func loadAVAssessmentScenario() (EfficacyScenario, ScenarioResult, error) {
	scenario, err := AudspectAVAssessmentScenario()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline-policy", AudspectAVAssessmentFixtures(), catalog)
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}
