package avefficacy

import (
	"testing"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

func TestAudspectAVAssessmentScenario_ValidatesAgainstRealCatalog(t *testing.T) {
	scenario, err := AudspectAVAssessmentScenario()
	if err != nil {
		t.Fatalf("AudspectAVAssessmentScenario: %v", err)
	}
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectAVAttackCatalog: %v", err)
	}
	if err := ValidateAgainstCatalog(scenario, catalog); err != nil {
		t.Errorf("ValidateAgainstCatalog: %v", err)
	}
}

// Review Focus: the real seed scenario must resolve to Fail (the
// deliberate AV-PERSIST-002 bypass), with Fail winning over the two
// deliberately untested vectors -- the exact same precedence
// wafassessment's own seed scenario proves, now against the real AV
// catalog and real avefficacy evaluation chain end to end.
func TestEvaluateScenarioBySlug_AVAssessment_RealFailOutcome(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("av-assessment")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "AV-ASSESSMENT-001" {
		t.Errorf("scenario.ID = %q, want AV-ASSESSMENT-001", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q (AV-PERSIST-002's deliberate bypass must fail the scenario)", result.Outcome, ScenarioFail)
	}
	var sawGap bool
	for _, o := range result.VectorOutcomes {
		if o.VectorID == "AV-PERSIST-002" && o.Finding == avval.FindingConfirmedGap {
			sawGap = true
		}
	}
	if !sawGap {
		t.Error("AV-PERSIST-002 did not resolve to FindingConfirmedGap")
	}
	if len(result.UntestedVectorIDs) != 2 {
		t.Errorf("UntestedVectorIDs = %v, want 2 entries (AV-FILE-002, AV-SCRIPT-002)", result.UntestedVectorIDs)
	}
}

func TestEvaluateScenarioBySlug_UnknownSlug_Error(t *testing.T) {
	if _, _, err := EvaluateScenarioBySlug("does-not-exist"); err == nil {
		t.Fatal("want error for an unknown slug, got nil")
	}
}

// Review Focus: the recovery-remediation scenario's one deliberate
// remediation failure (AV-PERSIST-002) must fail the scenario even though
// its own prevention leg was a clean block -- the non-offsetting rule
// applied to Response, through the real seed catalog end to end.
func TestEvaluateScenarioBySlug_RecoveryRemediation_RealFailOutcome(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("recovery-remediation")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "AV-RECOVERY-001" {
		t.Errorf("scenario.ID = %q, want AV-RECOVERY-001", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
	var sawFailedResponse bool
	for _, o := range result.VectorOutcomes {
		if o.VectorID == "AV-PERSIST-002" {
			if o.Finding != avval.FindingVerifiedProtection {
				t.Errorf("AV-PERSIST-002 Finding = %q, want %q (prevention itself was clean)", o.Finding, avval.FindingVerifiedProtection)
			}
			sawFailedResponse = o.Response == avval.ResponseFailed
		}
	}
	if !sawFailedResponse {
		t.Error("AV-PERSIST-002 did not resolve to Response=Failed")
	}
}

// Review Focus: the multi-stage scenario's real seed must show stage 1
// as a confirmed gap, stage 2 as the blocking stage, and stage 3 as
// never reached -- end to end through the real seed catalog.
func TestEvaluateScenarioBySlug_MultiStageExecution_RealOutcome(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("multi-stage-execution")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "AV-MULTISTAGE-001" {
		t.Errorf("scenario.ID = %q, want AV-MULTISTAGE-001", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q (stage 1's gap)", result.Outcome, ScenarioFail)
	}
	if len(result.VectorOutcomes) != 3 {
		t.Fatalf("len(VectorOutcomes) = %d, want 3", len(result.VectorOutcomes))
	}
	if result.VectorOutcomes[0].Finding != avval.FindingConfirmedGap {
		t.Errorf("stage 1 Finding = %q, want %q", result.VectorOutcomes[0].Finding, avval.FindingConfirmedGap)
	}
	if result.VectorOutcomes[1].Finding != avval.FindingVerifiedProtection {
		t.Errorf("stage 2 Finding = %q, want %q", result.VectorOutcomes[1].Finding, avval.FindingVerifiedProtection)
	}
	if !result.VectorOutcomes[2].StageSkipped {
		t.Error("stage 3 must be marked StageSkipped -- stage 2 interrupted the chain")
	}
}

// Review Focus: an active exclusion is EXPECTED to produce a confirmed
// gap -- the scenario must still report Fail honestly, never suppress
// the expected behavior of a working exclusion.
func TestEvaluateScenarioBySlug_ExclusionWeakness_RealGapOutcome(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("exclusion-weakness")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "AV-EXCLUSION-001" {
		t.Errorf("scenario.ID = %q, want AV-EXCLUSION-001", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
}

func TestEvaluateScenarioBySlug_DegradedProtection_RealPassOutcome(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("degraded-protection")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "AV-DEGRADED-001" {
		t.Errorf("scenario.ID = %q, want AV-DEGRADED-001", scenario.ID)
	}
	if result.Outcome != ScenarioPass {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioPass)
	}
}

func TestEvaluateScenarioBySlug_SecurityTampering_RealPassOutcome(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("security-tampering")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "AV-TAMPER-001" {
		t.Errorf("scenario.ID = %q, want AV-TAMPER-001", scenario.ID)
	}
	if result.Outcome != ScenarioPass {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioPass)
	}
}

// Review Focus: a clean prevention result right now must not hide a real,
// independently-reported stale-signature policy gap -- the non-offsetting
// rule applied to Configuration, through the real seed catalog.
func TestEvaluateScenarioBySlug_EndpointHealth_RealPolicyGapOutcome(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("endpoint-health")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "AV-HEALTH-001" {
		t.Errorf("scenario.ID = %q, want AV-HEALTH-001", scenario.ID)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q (AV-PERSIST-001's stale signatures)", result.Outcome, ScenarioFail)
	}
	var sawPolicyGap bool
	for _, o := range result.VectorOutcomes {
		if o.VectorID == "AV-PERSIST-001" && o.Configuration == avval.ConfigurationPolicyGap {
			sawPolicyGap = true
		}
	}
	if !sawPolicyGap {
		t.Error("AV-PERSIST-001 did not resolve Configuration=PolicyGap")
	}
}

// Review Focus: AV-NET-001's block must resolve VerifiedProtection from
// network-control evidence alone -- no AV-engine observation is supplied,
// so the Finding can never have been fabricated as an AV-engine result.
func TestEvaluateScenarioBySlug_CrossControlAttribution_RealPassOutcome(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("cross-control-attribution")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "AV-CROSSATTR-001" {
		t.Errorf("scenario.ID = %q, want AV-CROSSATTR-001", scenario.ID)
	}
	if result.Outcome != ScenarioPass {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioPass)
	}
	var sawNetBlocked bool
	for _, o := range result.VectorOutcomes {
		if o.VectorID == "AV-NET-001" && o.Finding == avval.FindingVerifiedProtection {
			sawNetBlocked = true
		}
	}
	if !sawNetBlocked {
		t.Error("AV-NET-001 did not resolve FindingVerifiedProtection from network-control-only evidence")
	}
}
