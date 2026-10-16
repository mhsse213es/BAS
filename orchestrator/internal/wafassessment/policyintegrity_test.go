package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafpolicygap"
	"github.com/audspect/bas/internal/wafval"
)

func mustPolicyGapCatalog(t *testing.T) ([]wafpolicygap.PolicyGapScenario, []wafcatalog.AttackVector) {
	t.Helper()
	gapCatalog, err := wafpolicygap.AudspectWAFPolicyGapCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFPolicyGapCatalog: %v", err)
	}
	attackCatalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	return gapCatalog, attackCatalog
}

func findGapScenario(t *testing.T, gapCatalog []wafpolicygap.PolicyGapScenario, id string) wafpolicygap.PolicyGapScenario {
	t.Helper()
	for _, g := range gapCatalog {
		if g.ID == id {
			return g
		}
	}
	t.Fatalf("gap scenario %q not found", id)
	return wafpolicygap.PolicyGapScenario{}
}

func findVector(t *testing.T, catalog []wafcatalog.AttackVector, id string) wafcatalog.AttackVector {
	t.Helper()
	for _, v := range catalog {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("vector %q not found", id)
	return wafcatalog.AttackVector{}
}

// Review Focus: a paired weakness (GAP-002, exclusion rule) with a
// trustworthy Blocked baseline and a Missed weakened leg, under a
// confirmed policy differentiation, must genuinely derive VerdictMissed
// through the real wafval.EvaluatePolicyGap -- not be asserted.
func TestEvaluateContributingPolicyGapVector_PairedMissedWeakening_ReturnsMissed(t *testing.T) {
	gapCatalog, attackCatalog := mustPolicyGapCatalog(t)
	gap002 := findGapScenario(t, gapCatalog, "GAP-002")
	sqli001 := findVector(t, attackCatalog, "SQLI-001")

	fixture := PolicyGapFixture{
		BaselineEvidence:               blocked("GAP-002-baseline").Results,
		WeakenedEvidence:               missed("GAP-002-weakened").Results,
		PolicyDifferentiationConfirmed: true,
	}
	verdict, _, err := EvaluateContributingPolicyGapVector(gap002, sqli001, "owasp-crs-default", fixture)
	if err != nil {
		t.Fatalf("EvaluateContributingPolicyGapVector: %v", err)
	}
	if verdict != wafval.VerdictMissed {
		t.Errorf("verdict = %q, want %q", verdict, wafval.VerdictMissed)
	}
}

// A paired weakness where the weakened leg still blocks must resolve
// to VerdictBlocked ("no gap demonstrated") -- a pass, not a failure.
func TestEvaluateContributingPolicyGapVector_PairedStillBlocked_ReturnsBlocked(t *testing.T) {
	gapCatalog, attackCatalog := mustPolicyGapCatalog(t)
	gap001 := findGapScenario(t, gapCatalog, "GAP-001")
	policy001 := findVector(t, attackCatalog, "POLICY-001")

	fixture := PolicyGapFixture{
		BaselineEvidence:               blocked("GAP-001-baseline").Results,
		WeakenedEvidence:               blocked("GAP-001-weakened").Results,
		PolicyDifferentiationConfirmed: true,
	}
	verdict, _, err := EvaluateContributingPolicyGapVector(gap001, policy001, "owasp-crs-default", fixture)
	if err != nil {
		t.Fatalf("EvaluateContributingPolicyGapVector: %v", err)
	}
	if verdict != wafval.VerdictBlocked {
		t.Errorf("verdict = %q, want %q", verdict, wafval.VerdictBlocked)
	}
}

// A coverage-gap weakness (GAP-005, unprotected route) with Missed-shaped
// evidence must genuinely derive VerdictMissed through the real
// wafpolicygap.EvaluateCoverageGapScenario / wafval.EvaluateClaim --
// there is no baseline leg for this weakness type.
func TestEvaluateContributingPolicyGapVector_CoverageGapMissed_ReturnsMissed(t *testing.T) {
	gapCatalog, attackCatalog := mustPolicyGapCatalog(t)
	gap005 := findGapScenario(t, gapCatalog, "GAP-005")
	ssrf001 := findVector(t, attackCatalog, "SSRF-001")

	fixture := PolicyGapFixture{CoverageEvidence: missed("GAP-005-coverage").Results}
	verdict, _, err := EvaluateContributingPolicyGapVector(gap005, ssrf001, "owasp-crs-default", fixture)
	if err != nil {
		t.Fatalf("EvaluateContributingPolicyGapVector: %v", err)
	}
	if verdict != wafval.VerdictMissed {
		t.Errorf("verdict = %q, want %q", verdict, wafval.VerdictMissed)
	}
}

// Review Focus: the non-offsetting rule must hold for policy-gap
// scenarios too -- one real Missed paired weakness among several
// "no gap demonstrated" passes, plus an untested coverage-gap
// weakness, must still resolve ScenarioFail.
func TestEvaluatePolicyIntegrityScenario_OneMissedAmongPassesPlusUntested_ReturnsFail(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-POLICY", "n", "o", []string{"GAP-001", "GAP-002", "GAP-005"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	fixtures := map[string]PolicyGapFixture{
		"GAP-001": {BaselineEvidence: blocked("GAP-001-baseline").Results, WeakenedEvidence: blocked("GAP-001-weakened").Results, PolicyDifferentiationConfirmed: true},
		"GAP-002": {BaselineEvidence: blocked("GAP-002-baseline").Results, WeakenedEvidence: missed("GAP-002-weakened").Results, PolicyDifferentiationConfirmed: true},
		// GAP-005 deliberately absent -> untested
	}
	result, err := EvaluatePolicyIntegrityScenario(scenario, "owasp-crs-default", fixtures)
	if err != nil {
		t.Fatalf("EvaluatePolicyIntegrityScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
	if len(result.UntestedVectorIDs) != 1 || result.UntestedVectorIDs[0] != "GAP-005" {
		t.Errorf("UntestedVectorIDs = %v, want [GAP-005]", result.UntestedVectorIDs)
	}
}

func TestEvaluatePolicyIntegrityScenario_UnknownGapID_ReturnsError(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-POLICY-2", "n", "o", []string{"GAP-DOES-NOT-EXIST"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	if _, err := EvaluatePolicyIntegrityScenario(scenario, "owasp-crs-default", map[string]PolicyGapFixture{}); err == nil {
		t.Fatal("want error for scenario referencing an unknown GAP ID, got nil")
	}
}
