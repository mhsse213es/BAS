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

// recoveryRemediationVectorIDs are existing seed-catalog vectors that each
// leave a real, cleanup-able artifact (av.txt §3 "Recovery and
// remediation": "Test artifact detection, quarantine and cleanup -- were
// artifacts removed, and was the endpoint returned to the expected
// state?"). This scenario deliberately reuses them rather than adding new
// vectors -- the Response dimension (already built in avval/avefficacy)
// is exactly what this family measures.
var recoveryRemediationVectorIDs = []string{
	"AV-FILE-001", "AV-FILE-002", "AV-SCRIPT-001", "AV-PERSIST-001", "AV-PERSIST-002",
}

// AudspectRecoveryRemediationScenario builds the real, catalog-validated
// Recovery and Remediation EfficacyScenario.
func AudspectRecoveryRemediationScenario() (EfficacyScenario, error) {
	return NewEfficacyScenario(
		"AV-RECOVERY-001", "Recovery and Remediation",
		"establish, with evidence, whether a detected/quarantined artifact was actually removed and the endpoint was returned to its expected state -- not merely flagged",
		recoveryRemediationVectorIDs,
		"endpoint has signature and/or behavioral AV/NGAV coverage per each contributing vector's own preconditions, with quarantine/remediation enabled",
		"product remediation/quarantine telemetry confirming artifact removal and endpoint state restoration",
		"manually authored from av.txt §3's 'Recovery and remediation' scenario family, reusing existing catalog vectors' real cleanup-able artifacts",
	)
}

// AudspectRecoveryRemediationFixtures seeds every contributing vector as
// correctly blocked (Finding is not this scenario's subject) with
// Response evidence as the deliberate variable under test.
// AV-PERSIST-002 is a deliberate remediation failure: blocked at
// prevention time, but the scheduled task was never actually removed --
// proving the non-offsetting rule applies to Response exactly as it does
// to Finding (a clean prevention result never hides a failed cleanup).
func AudspectRecoveryRemediationFixtures() map[string]VectorFixture {
	remediated := func(eventID string) []avval.CollectionResult {
		return []avval.CollectionResult{{ControlSource: avval.ControlSourceAVEngine, Coverage: avval.CoverageFound, Observations: []avval.Observation{
			{ControlSource: avval.ControlSourceAVEngine, EventID: eventID, Response: avval.ResponseRemediated, EvidenceKind: avval.EvidenceObserved},
		}}}
	}
	failed := func(eventID string) []avval.CollectionResult {
		return []avval.CollectionResult{{ControlSource: avval.ControlSourceAVEngine, Coverage: avval.CoverageFound, Observations: []avval.Observation{
			{ControlSource: avval.ControlSourceAVEngine, EventID: eventID, Response: avval.ResponseFailed, EvidenceKind: avval.EvidenceObserved},
		}}}
	}
	return map[string]VectorFixture{
		"AV-FILE-001":    {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-rec-file-001")}, ResponseEvidence: remediated("r-rec-file-001")},
		"AV-FILE-002":    {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-rec-file-002")}, ResponseEvidence: remediated("r-rec-file-002")},
		"AV-SCRIPT-001":  {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-rec-script-001")}, ResponseEvidence: remediated("r-rec-script-001")},
		"AV-PERSIST-001": {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-rec-persist-001")}, ResponseEvidence: remediated("r-rec-persist-001")},
		"AV-PERSIST-002": {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-rec-persist-002")}, ResponseEvidence: failed("r-rec-persist-002")},
	}
}

func loadRecoveryRemediationScenario() (EfficacyScenario, ScenarioResult, error) {
	scenario, err := AudspectRecoveryRemediationScenario()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline-policy", AudspectRecoveryRemediationFixtures(), catalog)
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}

// AudspectMultiStageExecutionScenario builds the real, catalog-validated
// Multi-stage Execution scenario (av.txt §3: "Document -> script
// interpreter -> suspicious child process"), composing three existing,
// independently-validated catalog vectors in declared order. This composes
// independently-evaluated vectors in sequence -- it does not claim a
// single continuous process tree spanning all three stages in one real
// dispatch (that would require new real execution linking not yet built).
func AudspectMultiStageExecutionScenario() (MultiStageScenario, error) {
	return NewMultiStageScenario(
		"AV-MULTISTAGE-001", "Multi-Stage Execution",
		"establish which stage of a document-to-interpreter-to-child-process chain was stopped, and which stages continued, rather than a single collapsed pass/fail for the whole chain",
		[]StageVector{
			{VectorID: "AV-SCRIPT-001", Label: "initial script interpreter execution"},
			{VectorID: "AV-BEHAV-002", Label: "interpreter spawns a suspicious child process"},
			{VectorID: "AV-PERSIST-002", Label: "follow-on persistence"},
		},
		"endpoint has behavioral/NGAV coverage capable of script-content and parent-child process-chain inspection",
		"product telemetry establishing, per stage, whether execution was observed and whether it was blocked",
		"manually authored from av.txt §3's 'Multi-stage execution' scenario family, composing existing independently-validated catalog vectors",
	)
}

// AudspectMultiStageExecutionFixtures seeds stage 1 (AV-SCRIPT-001) as a
// confirmed gap (allowed through) and stage 2 (AV-BEHAV-002) as blocked --
// demonstrating a layered defense that misses the initial execution but
// catches the suspicious child-process spawn, while still reporting
// stage 1's gap honestly (it is never erased by stage 2's block). Stage 3
// is never evaluated: the chain was interrupted at stage 2.
func AudspectMultiStageExecutionFixtures() map[string]VectorFixture {
	return map[string]VectorFixture{
		"AV-SCRIPT-001": {PreventionEvidence: []avval.CollectionResult{missedEvidence("e-multi-script-001")}},
		"AV-BEHAV-002":  {PreventionEvidence: []avval.CollectionResult{blockedEvidence("e-multi-behav-002")}},
	}
}

func loadMultiStageExecutionScenario() (EfficacyScenario, ScenarioResult, error) {
	scenario, err := AudspectMultiStageExecutionScenario()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateMultiStageScenario(scenario, "baseline-policy", AudspectMultiStageExecutionFixtures(), catalog)
	if err != nil {
		return EfficacyScenario{}, ScenarioResult{}, err
	}
	return scenario.EfficacyScenario, result, nil
}
