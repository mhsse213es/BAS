package avcatalog

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/avval"
)

func TestAudspectAVAttackCatalog_LoadsWithoutError(t *testing.T) {
	catalog, err := AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectAVAttackCatalog: %v", err)
	}
	if len(catalog) < 10 {
		t.Errorf("len(catalog) = %d, want at least 10 real vectors", len(catalog))
	}
}

func TestAudspectAVAttackCatalog_AllSixFamiliesPresent(t *testing.T) {
	catalog, err := AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectAVAttackCatalog: %v", err)
	}
	seen := map[AttackFamily]bool{}
	for _, v := range catalog {
		seen[v.Family] = true
	}
	for _, want := range []AttackFamily{
		FamilyFileBasedThreat, FamilyScriptFileless, FamilyBehavioralExploit,
		FamilyNetworkDelivered, FamilyCredentialPersistence, FamilyFalsePositiveResilience,
	} {
		if !seen[want] {
			t.Errorf("family %q has no vector in the catalog", want)
		}
	}
}

func TestAudspectAVAttackCatalog_NoDuplicateIDs(t *testing.T) {
	catalog, err := AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectAVAttackCatalog: %v", err)
	}
	if err := ValidateCatalog(catalog); err != nil {
		t.Errorf("catalog has a validation error: %v", err)
	}
}

// Review Focus: a real seed vector's Expectations() must resolve through
// the real avval.EvaluateClaim, not just construct without error -- this
// proves the catalog-to-evaluator wiring actually works end to end for both
// the prevention-shaped and false-positive-shaped vectors this catalog
// seeds.
func TestAVFILE001_PrimaryLeg_ThroughRealEvaluateClaim_Blocked(t *testing.T) {
	catalog, err := AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectAVAttackCatalog: %v", err)
	}
	var vector Vector
	for _, v := range catalog {
		if v.ID == "AV-FILE-001" {
			vector = v
		}
	}
	if vector.ID == "" {
		t.Fatal("AV-FILE-001 not found in catalog")
	}
	legs := vector.Expectations("baseline-policy")
	primary := legs[0]
	results := []avval.CollectionResult{
		{ControlSource: avval.ControlSourceAVEngine, Coverage: avval.CoverageFound, Observations: []avval.Observation{
			{ControlSource: avval.ControlSourceAVEngine, EventID: "e1", Prevention: avval.PreventionBlocked, EvidenceKind: avval.EvidenceObserved},
		}},
	}
	result := avval.EvaluateClaim(primary.Expectation, results, avval.CorrelationKey{TestExecutionID: vector.ID})
	if result.Finding != avval.FindingVerifiedProtection {
		t.Errorf("Finding = %q, want %q (reason: %s)", result.Finding, avval.FindingVerifiedProtection, result.Reason)
	}
}

func TestAVFP001_PrimaryLeg_ThroughRealEvaluateClaim_IncorrectlyBlocked(t *testing.T) {
	catalog, err := AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectAVAttackCatalog: %v", err)
	}
	var vector Vector
	for _, v := range catalog {
		if v.ID == "AV-FP-001" {
			vector = v
		}
	}
	if vector.ID == "" {
		t.Fatal("AV-FP-001 not found in catalog")
	}
	legs := vector.Expectations("baseline-policy")
	if len(legs) != 1 {
		t.Fatalf("len(legs) = %d, want 1 (AV-FP-001 has no counterpart)", len(legs))
	}
	if legs[0].Expectation.Claim != avval.ClaimFalsePositive {
		t.Fatalf("legs[0].Expectation.Claim = %q, want %q", legs[0].Expectation.Claim, avval.ClaimFalsePositive)
	}
	results := []avval.CollectionResult{
		{ControlSource: avval.ControlSourceAVEngine, Coverage: avval.CoverageFound, Observations: []avval.Observation{
			{ControlSource: avval.ControlSourceAVEngine, EventID: "e1", Prevention: avval.PreventionBlocked, EvidenceKind: avval.EvidenceObserved},
		}},
	}
	result := avval.EvaluateClaim(legs[0].Expectation, results, avval.CorrelationKey{TestExecutionID: vector.ID, Window: avval.TimeWindow{Start: time.Now(), End: time.Now()}})
	if result.Finding != avval.FindingConfirmedGap {
		t.Errorf("Finding = %q, want %q (an approved signed business script incorrectly blocked is a confirmed gap, reason: %s)", result.Finding, avval.FindingConfirmedGap, result.Reason)
	}
}
