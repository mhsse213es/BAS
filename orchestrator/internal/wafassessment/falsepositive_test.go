package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

// Review Focus: a legitimate (benign) request correctly allowed must
// derive VerdictAllowed through the real wafval.EvaluateClaim under
// ClaimFalsePositive, and a legitimate request incorrectly blocked
// must derive VerdictIncorrectlyBlocked -- neither is reachable
// through EvaluateContributingVector's hardcoded ClaimPrevention.
func TestEvaluateContributingVectorAsClaim_FalsePositive_AllowedEvidence_ReturnsAllowed(t *testing.T) {
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, Enforcement: wafval.EnforcementAllowed, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result, err := EvaluateContributingVectorAsClaim("V-1", wafval.ClaimFalsePositive, results)
	if err != nil {
		t.Fatalf("EvaluateContributingVectorAsClaim: %v", err)
	}
	if result.Verdict != wafval.VerdictAllowed {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictAllowed)
	}
}

func TestEvaluateContributingVectorAsClaim_FalsePositive_BlockedEvidence_ReturnsIncorrectlyBlocked(t *testing.T) {
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, Enforcement: wafval.EnforcementBlocked, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result, err := EvaluateContributingVectorAsClaim("V-2", wafval.ClaimFalsePositive, results)
	if err != nil {
		t.Fatalf("EvaluateContributingVectorAsClaim: %v", err)
	}
	if result.Verdict != wafval.VerdictIncorrectlyBlocked {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictIncorrectlyBlocked)
	}
}

// EvaluateContributingVector (ClaimPrevention) must still behave
// identically to before -- the generalization must not change its
// existing callers.
func TestEvaluateContributingVector_StillClaimPrevention_BlockedEvidence_ReturnsBlocked(t *testing.T) {
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, Enforcement: wafval.EnforcementBlocked, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result, err := EvaluateContributingVector("V-3", results)
	if err != nil {
		t.Fatalf("EvaluateContributingVector: %v", err)
	}
	if result.Verdict != wafval.VerdictBlocked {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictBlocked)
	}
}

// Review Focus: a real VerdictIncorrectlyBlocked must register as a
// scenario-level failure through the shared aggregateByPrecedence
// path -- this requires failingVerdict to recognize it, since neither
// of its two prior failing values would.
func TestEvaluateLegitimateTrafficScenario_IncorrectlyBlocked_ReturnsFail(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-LEGIT", "n", "o", []string{"V-1", "V-2"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	fixtures := map[string]VectorFixture{
		"V-1": allowedLegitFixture("V-1"),
		"V-2": incorrectlyBlockedLegitFixture("V-2"),
	}
	severityByID := map[string]wafcatalog.Severity{"V-1": wafcatalog.SeverityCritical, "V-2": wafcatalog.SeverityCritical}
	result, err := EvaluateLegitimateTrafficScenario(scenario, fixtures, severityByID)
	if err != nil {
		t.Fatalf("EvaluateLegitimateTrafficScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
	var sawV2 bool
	for _, a := range result.Assertions {
		if a.VectorID == "V-2" {
			sawV2 = true
			if a.Verdict != wafval.VerdictIncorrectlyBlocked {
				t.Errorf("V-2 Verdict = %q, want %q", a.Verdict, wafval.VerdictIncorrectlyBlocked)
			}
		}
	}
	if !sawV2 {
		t.Error("V-2 not found in Assertions")
	}
}

// Review Focus: EvaluateLegitimateTrafficScenario has its own
// hardcoded-EvidenceSource bug, a second occurrence of the exact one
// fixed in EvaluateScenarioWithSeverities -- a VectorFixture carrying
// live evidence must not render as "fixture" here either.
func TestEvaluateLegitimateTrafficScenario_FixtureEvidenceSourceOverride_PropagatesToAssertion(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-LEGIT-2", "n", "o", []string{"V-1", "V-2"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	live := allowedLegitFixture("V-1")
	live.EvidenceSource = EvidenceSourceLiveExecution
	fixtures := map[string]VectorFixture{
		"V-1": live,
		"V-2": allowedLegitFixture("V-2"), // EvidenceSource left unset
	}
	severityByID := map[string]wafcatalog.Severity{"V-1": wafcatalog.SeverityCritical, "V-2": wafcatalog.SeverityCritical}
	result, err := EvaluateLegitimateTrafficScenario(scenario, fixtures, severityByID)
	if err != nil {
		t.Fatalf("EvaluateLegitimateTrafficScenario: %v", err)
	}
	var sawV1, sawV2 bool
	for _, a := range result.Assertions {
		switch a.VectorID {
		case "V-1":
			sawV1 = true
			if a.EvidenceSource != EvidenceSourceLiveExecution {
				t.Errorf("V-1 EvidenceSource = %q, want %q", a.EvidenceSource, EvidenceSourceLiveExecution)
			}
		case "V-2":
			sawV2 = true
			if a.EvidenceSource != EvidenceSourceFixture {
				t.Errorf("V-2 EvidenceSource = %q, want %q (unset should default)", a.EvidenceSource, EvidenceSourceFixture)
			}
		}
	}
	if !sawV1 || !sawV2 {
		t.Fatalf("expected assertions for both V-1 and V-2, got %+v", result.Assertions)
	}
}
