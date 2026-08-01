package endpointrisk

import (
	"testing"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
)

func TestComputeHealth_ScoresOnlyCollectedCategories(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Scores: exposure.ScoreBreakdown{ExposureScore: 80, AttackPathScore: 60, DetectionCoverageScore: 90, VulnerabilityScore: 70, CriticalityRisk: 40},
	}
	compliance := ComplianceInput{Collected: false}
	bas := BASReadinessInput{Collected: false}
	got := ComputeHealth("agent-1", profile, compliance, bas, compliance, bas)

	// exposureAttackPath = mean(80,60) = 70; detection=90; vulns=70 -> mean(70,90,70) = 76.67 -> round 77
	if got.HealthScore != 77 {
		t.Errorf("HealthScore = %d, want 77", got.HealthScore)
	}
	if got.CriticalityRisk != 40 {
		t.Errorf("CriticalityRisk = %d, want 40 (not folded into HealthScore)", got.CriticalityRisk)
	}
	var sawCompliance, sawBAS bool
	for _, c := range got.Categories {
		if c.ID == CategoryCompliance {
			sawCompliance = true
			if c.Collected {
				t.Error("Compliance category should be Collected=false")
			}
		}
		if c.ID == CategoryBASReadiness {
			sawBAS = true
			if c.Collected {
				t.Error("BAS Readiness category should be Collected=false")
			}
		}
	}
	if !sawCompliance || !sawBAS {
		t.Error("expected both Compliance and BAS Readiness categories present even when uncollected")
	}
}

func TestComputeHealth_NotYetCollectedCategoriesAlwaysPresent(t *testing.T) {
	got := ComputeHealth("agent-1", exposure.AssetExposureProfile{}, ComplianceInput{}, BASReadinessInput{}, ComplianceInput{}, BASReadinessInput{})
	want := map[string]bool{CategorySecurityConfig: false, CategoryIdentity: false, CategoryPatchManagement: false, CategoryApplicationRisk: false}
	for _, c := range got.Categories {
		if _, ok := want[c.ID]; ok {
			if c.Collected {
				t.Errorf("category %s should be Collected=false", c.ID)
			}
			delete(want, c.ID)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing not-yet-collected categories: %v", want)
	}
}

func TestComputeHealth_ActionPlanRankedByDeficit(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Scores:    exposure.ScoreBreakdown{ExposureScore: 90, AttackPathScore: 90, DetectionCoverageScore: 40, VulnerabilityScore: 95},
		Detection: exposure.DetectionContext{Gap: 1},
	}
	got := ComputeHealth("agent-1", profile, ComplianceInput{}, BASReadinessInput{}, ComplianceInput{}, BASReadinessInput{})
	if len(got.ActionPlan) == 0 {
		t.Fatal("expected at least one action item")
	}
	if got.ActionPlan[0].CategoryID != CategoryDetectionHealth {
		t.Errorf("top action = %s, want %s (biggest deficit: detection health at 60)", got.ActionPlan[0].CategoryID, CategoryDetectionHealth)
	}
}

func TestComputeHealth_AttackPathChainFromRecommendations(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Recommendations: []pathcorrelation.PrioritizedGap{
			{Edge: attackpath.Edge{From: "HOST-A", To: "HOST-B", Kind: "rdp"}, Priority: "Critical", Reason: "RDP reachable", Remediation: "Disable RDP or require MFA"},
		},
	}
	got := ComputeHealth("agent-1", profile, ComplianceInput{}, BASReadinessInput{}, ComplianceInput{}, BASReadinessInput{})
	if len(got.AttackPathChain) != 1 {
		t.Fatalf("got %d chain steps, want 1", len(got.AttackPathChain))
	}
	if got.AttackPathChain[0].From != "HOST-A" || got.AttackPathChain[0].To != "HOST-B" {
		t.Errorf("chain step = %+v, want From=HOST-A To=HOST-B", got.AttackPathChain[0])
	}
}

func TestComputeTrend_BothCollected_BandComparison(t *testing.T) {
	now := ComplianceInput{Collected: true, PercentByFramework: map[string]float64{"ISO": 90}}
	nowBAS := BASReadinessInput{Collected: true, PassRate: 90}
	past := ComplianceInput{Collected: true, PercentByFramework: map[string]float64{"ISO": 40}}
	pastBAS := BASReadinessInput{Collected: true, PassRate: 40}
	got := computeTrend(now, past, nowBAS, pastBAS)
	if got != "Improving" {
		t.Errorf("computeTrend = %q, want Improving (band moved from Poor to Good)", got)
	}
}

func TestComputeTrend_NeitherCollected_InsufficientData(t *testing.T) {
	got := computeTrend(ComplianceInput{}, ComplianceInput{}, BASReadinessInput{}, BASReadinessInput{})
	if got != "InsufficientData" {
		t.Errorf("computeTrend = %q, want InsufficientData", got)
	}
}
