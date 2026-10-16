package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/waforigin"
	"github.com/audspect/bas/internal/wafval"
)

func mustOriginCatalog(t *testing.T) ([]waforigin.BypassScenario, []waforigin.ProtocolBehaviorVector, []waforigin.ConsistencyScenario, []wafcatalog.AttackVector) {
	t.Helper()
	bypass, protocol, consistency, err := waforigin.AudspectWAFOriginCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFOriginCatalog: %v", err)
	}
	attackCatalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	return bypass, protocol, consistency, attackCatalog
}

// Review Focus: a Kind-A bypass-pair weakness (WAFORIGIN-001, routing
// coverage gap) with a trustworthy Blocked baseline and a Missed
// bypass leg must genuinely derive VerdictMissed through the real
// waforigin.EvaluateBypassScenario -- not be asserted.
func TestEvaluateContributingOriginVector_BypassMissed_ReturnsMissed(t *testing.T) {
	bypassScenarios, _, _, attackCatalog := mustOriginCatalog(t)
	fixture := OriginResilienceFixture{
		BaselineEvidence: blocked("WAFORIGIN-001-baseline").Results,
		BypassEvidence:   missed("WAFORIGIN-001-bypass").Results,
	}
	assertion, err := evaluateContributingOriginVector(originCatalogs{
		bypassByID: indexBypass(bypassScenarios), attackByID: indexAttack(attackCatalog),
	}, "WAFORIGIN-001", originResiliencePolicyBasis, fixture)
	if err != nil {
		t.Fatalf("evaluateContributingOriginVector: %v", err)
	}
	if assertion.Verdict != wafval.VerdictMissed {
		t.Errorf("Verdict = %q, want %q", assertion.Verdict, wafval.VerdictMissed)
	}
}

// A Kind-B protocol-claim vector (WAFORIGIN-004) evaluated as a
// prevention claim on its malicious leg must genuinely derive
// VerdictBlocked through the real wafval.EvaluateClaim.
func TestEvaluateContributingOriginVector_ProtocolBlocked_ReturnsBlocked(t *testing.T) {
	_, protocolVectors, _, _ := mustOriginCatalog(t)
	fixture := OriginResilienceFixture{ProtocolEvidence: blocked("WAFORIGIN-004").Results}
	assertion, err := evaluateContributingOriginVector(originCatalogs{
		protocolByID: indexProtocol(protocolVectors),
	}, "WAFORIGIN-004", originResiliencePolicyBasis, fixture)
	if err != nil {
		t.Fatalf("evaluateContributingOriginVector: %v", err)
	}
	if assertion.Verdict != wafval.VerdictBlocked {
		t.Errorf("Verdict = %q, want %q", assertion.Verdict, wafval.VerdictBlocked)
	}
}

// Review Focus: a Kind-C cross-node-consistency scenario
// (WAFORIGIN-005) with two trustworthy nodes disagreeing must
// genuinely derive "drift_detected" through the real
// waforigin.EvaluateConfigurationConsistency, and that drift must
// register as a scenario-level failure -- proving originOutcomeClass,
// not wafval's own failingVerdict, drives this classification (the
// same class of bug the detection-telemetry scenario's design
// deliberately avoids: ConsistencyDrift's string value shares nothing
// with wafval.Verdict's failing values).
func TestEvaluateContributingOriginVector_ConsistencyDrift_ReturnsDrift(t *testing.T) {
	_, _, consistencyScenarios, attackCatalog := mustOriginCatalog(t)
	fixture := OriginResilienceFixture{
		NodeEvidence: []waforigin.NodeEvidence{
			{NodeID: "node-a", Evidence: blocked("WAFORIGIN-005-node-a").Results, Key: wafval.CorrelationKey{TestExecutionID: "node-a", RequestID: "node-a"}},
			{NodeID: "node-b", Evidence: missed("WAFORIGIN-005-node-b").Results, Key: wafval.CorrelationKey{TestExecutionID: "node-b", RequestID: "node-b"}},
		},
	}
	assertion, err := evaluateContributingOriginVector(originCatalogs{
		consistencyByID: indexConsistency(consistencyScenarios), attackByID: indexAttack(attackCatalog),
	}, "WAFORIGIN-005", originResiliencePolicyBasis, fixture)
	if err != nil {
		t.Fatalf("evaluateContributingOriginVector: %v", err)
	}
	if string(assertion.Verdict) != "drift_detected" {
		t.Errorf("Verdict = %q, want %q", assertion.Verdict, "drift_detected")
	}
}

// Review Focus: the non-offsetting rule must hold for origin-resilience
// scenarios too -- a real cross-node drift among otherwise-passing
// vectors, plus a real untested vector, must still resolve
// ScenarioFail.
func TestEvaluateOriginResilienceScenario_DriftAmongPassesPlusUntested_ReturnsFail(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-ORIGIN", "n", "o", []string{"WAFORIGIN-001", "WAFORIGIN-005"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	fixtures := map[string]OriginResilienceFixture{
		"WAFORIGIN-005": {
			NodeEvidence: []waforigin.NodeEvidence{
				{NodeID: "node-a", Evidence: blocked("WAFORIGIN-005-node-a").Results, Key: wafval.CorrelationKey{TestExecutionID: "node-a", RequestID: "node-a"}},
				{NodeID: "node-b", Evidence: missed("WAFORIGIN-005-node-b").Results, Key: wafval.CorrelationKey{TestExecutionID: "node-b", RequestID: "node-b"}},
			},
		},
		// WAFORIGIN-001 deliberately absent -> untested
	}
	result, err := EvaluateOriginResilienceScenario(scenario, originResiliencePolicyBasis, fixtures)
	if err != nil {
		t.Fatalf("EvaluateOriginResilienceScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
	if len(result.UntestedVectorIDs) != 1 || result.UntestedVectorIDs[0] != "WAFORIGIN-001" {
		t.Errorf("UntestedVectorIDs = %v, want [WAFORIGIN-001]", result.UntestedVectorIDs)
	}
}

func TestEvaluateOriginResilienceScenario_UnknownID_ReturnsError(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-ORIGIN-2", "n", "o", []string{"WAFORIGIN-DOES-NOT-EXIST"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	if _, err := EvaluateOriginResilienceScenario(scenario, originResiliencePolicyBasis, map[string]OriginResilienceFixture{}); err == nil {
		t.Fatal("want error for scenario referencing an unknown WAFORIGIN ID, got nil")
	}
}
