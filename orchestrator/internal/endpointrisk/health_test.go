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
	got := ComputeHealth("agent-1", profile, HealthInputs{}, HealthInputs{})

	// exposureAttackPath = mean(80,60) = 70; detection=90; vulns=70 -> mean(70,90,70) = 76.67 -> round 77
	if got.HealthScore != 77 {
		t.Errorf("HealthScore = %d, want 77", got.HealthScore)
	}
	if got.CriticalityRisk != 40 {
		t.Errorf("CriticalityRisk = %d, want 40 (not folded into HealthScore)", got.CriticalityRisk)
	}
	want := map[string]bool{CategoryCompliance: false, CategoryBASReadiness: false, CategorySecurityConfig: false, CategoryIdentity: false}
	for _, c := range got.Categories {
		if _, ok := want[c.ID]; ok {
			if c.Collected {
				t.Errorf("category %s should be Collected=false", c.ID)
			}
			delete(want, c.ID)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing categories present-but-uncollected: %v", want)
	}
}

func TestComputeHealth_NotYetCollectedCategoriesAlwaysPresent(t *testing.T) {
	got := ComputeHealth("agent-1", exposure.AssetExposureProfile{}, HealthInputs{}, HealthInputs{})
	want := map[string]bool{CategoryPatchManagement: false, CategoryApplicationRisk: false}
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

func TestComputeHealth_SecurityConfigAndIdentity_CollectedWhenPresent(t *testing.T) {
	now := HealthInputs{
		SecurityConfig: PostureCheckInput{Collected: true, Score: 80, Passed: 4, Failed: 1, Total: 5, Findings: []Finding{{ID: "windows-bitlocker-enabled", Title: "BitLocker disabled"}}},
		Identity:       PostureCheckInput{Collected: true, Score: 100, Passed: 5, Failed: 0, Total: 5},
	}
	got := ComputeHealth("agent-1", exposure.AssetExposureProfile{}, now, HealthInputs{})
	var secCat, idCat *CategoryScore
	for i := range got.Categories {
		switch got.Categories[i].ID {
		case CategorySecurityConfig:
			secCat = &got.Categories[i]
		case CategoryIdentity:
			idCat = &got.Categories[i]
		}
	}
	if secCat == nil || !secCat.Collected || secCat.Score != 80 || secCat.Deficit != 20 || len(secCat.Findings) != 1 {
		t.Errorf("Security Configuration category = %+v, want Collected=true Score=80 Deficit=20 1 finding", secCat)
	}
	if idCat == nil || !idCat.Collected || idCat.Score != 100 || idCat.Deficit != 0 {
		t.Errorf("Identity category = %+v, want Collected=true Score=100 Deficit=0", idCat)
	}
}

func TestComputeHealth_ActionPlanRankedByDeficit(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Scores:    exposure.ScoreBreakdown{ExposureScore: 90, AttackPathScore: 90, DetectionCoverageScore: 40, VulnerabilityScore: 95},
		Detection: exposure.DetectionContext{Gap: 1},
	}
	got := ComputeHealth("agent-1", profile, HealthInputs{}, HealthInputs{})
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
	got := ComputeHealth("agent-1", profile, HealthInputs{}, HealthInputs{})
	if len(got.AttackPathChain) != 1 {
		t.Fatalf("got %d chain steps, want 1", len(got.AttackPathChain))
	}
	if got.AttackPathChain[0].From != "HOST-A" || got.AttackPathChain[0].To != "HOST-B" {
		t.Errorf("chain step = %+v, want From=HOST-A To=HOST-B", got.AttackPathChain[0])
	}
}

func TestComputeTrend_BothCollected_BandComparison(t *testing.T) {
	now := HealthInputs{
		Compliance: ComplianceInput{Collected: true, PercentByFramework: map[string]float64{"ISO": 90}},
		BAS:        BASReadinessInput{Collected: true, PassRate: 90},
	}
	past := HealthInputs{
		Compliance: ComplianceInput{Collected: true, PercentByFramework: map[string]float64{"ISO": 40}},
		BAS:        BASReadinessInput{Collected: true, PassRate: 40},
	}
	got := computeTrend(now, past)
	if got.Direction != "Improving" {
		t.Errorf("Direction = %q, want Improving (band moved from Poor to Good)", got.Direction)
	}
}

func TestComputeTrend_NeitherCollected_InsufficientData(t *testing.T) {
	got := computeTrend(HealthInputs{}, HealthInputs{})
	if got.Direction != "InsufficientData" {
		t.Errorf("Direction = %q, want InsufficientData", got.Direction)
	}
}

func TestComputeTrend_NewAndResolvedFindings(t *testing.T) {
	now := HealthInputs{
		SecurityConfig: PostureCheckInput{Collected: true, Score: 80, Findings: []Finding{{ID: "windows-bitlocker-enabled", Title: "BitLocker disabled"}}},
	}
	past := HealthInputs{
		SecurityConfig: PostureCheckInput{Collected: true, Score: 80, Findings: []Finding{{ID: "windows-firewall-enabled", Title: "Firewall disabled"}}},
	}
	got := computeTrend(now, past)
	if len(got.NewFindings) != 1 || got.NewFindings[0].ID != "windows-bitlocker-enabled" {
		t.Errorf("NewFindings = %+v, want exactly windows-bitlocker-enabled", got.NewFindings)
	}
	if len(got.ResolvedFindings) != 1 || got.ResolvedFindings[0].ID != "windows-firewall-enabled" {
		t.Errorf("ResolvedFindings = %+v, want exactly windows-firewall-enabled", got.ResolvedFindings)
	}
}

func TestComputeTrend_SameFindingsBothSides_NoNewNoResolved(t *testing.T) {
	shared := PostureCheckInput{Collected: true, Score: 80, Findings: []Finding{{ID: "windows-bitlocker-enabled", Title: "BitLocker disabled"}}}
	got := computeTrend(HealthInputs{SecurityConfig: shared}, HealthInputs{SecurityConfig: shared})
	if len(got.NewFindings) != 0 || len(got.ResolvedFindings) != 0 {
		t.Errorf("expected no new/resolved findings when both sides match, got new=%+v resolved=%+v", got.NewFindings, got.ResolvedFindings)
	}
}
