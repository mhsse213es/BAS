package endpointrisk

import (
	"testing"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
)

func TestComputeHealth_ScoresOnlyCollectedCategories(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		// The *Measurable flags mark this as really-collected exposure data.
		// Without them these three categories are correctly treated as "not
		// collected" and excluded from HealthScore -- see
		// TestComputeHealth_UncollectedExposureIsNotAPerfectScore.
		Scores: exposure.ScoreBreakdown{
			ExposureScore: 80, AttackPathScore: 60, DetectionCoverageScore: 90, VulnerabilityScore: 70, CriticalityRisk: 40,
			ExposureMeasurable: true, AttackPathMeasurable: true, DetectionMeasurable: true, VulnerabilityMeasurable: true,
		},
	}
	got := ComputeHealth("agent-1", profile, HealthInputs{}, HealthInputs{})

	// exposureAttackPath = mean(80,60) = 70; detection=90; vulns=70 -> mean(70,90,70) = 76.67 -> round 77
	if got.HealthScore != 77 {
		t.Errorf("HealthScore = %d, want 77", got.HealthScore)
	}
	if got.CriticalityRisk != 40 {
		t.Errorf("CriticalityRisk = %d, want 40 (not folded into HealthScore)", got.CriticalityRisk)
	}
	want := map[string]bool{
		CategoryCompliance: false, CategoryBASReadiness: false, CategorySecurityConfig: false,
		CategoryIdentity: false, CategoryPatchManagement: false, CategoryApplicationRisk: false,
	}
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

func TestComputeHealth_AllNineCategoriesAlwaysPresent(t *testing.T) {
	got := ComputeHealth("agent-1", exposure.AssetExposureProfile{}, HealthInputs{}, HealthInputs{})
	if len(got.Categories) != 9 {
		t.Errorf("got %d categories, want 9 (every category is now real-or-uncollected)", len(got.Categories))
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

func TestComputeHealth_PatchManagementAndApplicationRisk_CollectedWhenPresent(t *testing.T) {
	now := HealthInputs{
		PatchManagement: PostureCheckInput{Collected: true, Score: 100, Passed: 1, Total: 1},
		ApplicationRisk: ApplicationRiskInput{Collected: true, Score: 60, AppsScanned: 3, Findings: []Finding{{ID: "flash", Title: "Flash Player"}, {ID: "java8", Title: "Java 8"}}},
	}
	got := ComputeHealth("agent-1", exposure.AssetExposureProfile{}, now, HealthInputs{})
	var patchCat, appRiskCat *CategoryScore
	for i := range got.Categories {
		switch got.Categories[i].ID {
		case CategoryPatchManagement:
			patchCat = &got.Categories[i]
		case CategoryApplicationRisk:
			appRiskCat = &got.Categories[i]
		}
	}
	if patchCat == nil || !patchCat.Collected || patchCat.Score != 100 || patchCat.Deficit != 0 {
		t.Errorf("Patch Management category = %+v, want Collected=true Score=100 Deficit=0", patchCat)
	}
	if appRiskCat == nil || !appRiskCat.Collected || appRiskCat.Score != 60 || appRiskCat.Deficit != 40 || len(appRiskCat.Findings) != 2 {
		t.Errorf("Application Risk category = %+v, want Collected=true Score=60 Deficit=40 2 findings", appRiskCat)
	}
}

func TestComputeHealth_ActionPlanRankedByDeficit(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Scores: exposure.ScoreBreakdown{
			ExposureScore: 90, AttackPathScore: 90, DetectionCoverageScore: 40, VulnerabilityScore: 95,
			ExposureMeasurable: true, AttackPathMeasurable: true, DetectionMeasurable: true, VulnerabilityMeasurable: true,
		},
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

func TestComputeTrend_NewAndResolvedFindings_AcrossFourStableCategories(t *testing.T) {
	now := HealthInputs{
		SecurityConfig:  PostureCheckInput{Collected: true, Score: 80, Findings: []Finding{{ID: "windows-bitlocker-enabled", Title: "BitLocker disabled"}}},
		PatchManagement: PostureCheckInput{Collected: true, Score: 100, Findings: []Finding{{ID: "windows-last-patch-age", Title: "Patch overdue"}}},
	}
	past := HealthInputs{
		SecurityConfig:  PostureCheckInput{Collected: true, Score: 80, Findings: []Finding{{ID: "windows-firewall-enabled", Title: "Firewall disabled"}}},
		ApplicationRisk: ApplicationRiskInput{Collected: true, Score: 75, Findings: []Finding{{ID: "flash", Title: "Flash Player"}}},
	}
	got := computeTrend(now, past)
	newIDs := map[string]bool{}
	for _, f := range got.NewFindings {
		newIDs[f.ID] = true
	}
	if !newIDs["windows-bitlocker-enabled"] || !newIDs["windows-last-patch-age"] || len(got.NewFindings) != 2 {
		t.Errorf("NewFindings = %+v, want exactly windows-bitlocker-enabled + windows-last-patch-age", got.NewFindings)
	}
	resolvedIDs := map[string]bool{}
	for _, f := range got.ResolvedFindings {
		resolvedIDs[f.ID] = true
	}
	if !resolvedIDs["windows-firewall-enabled"] || !resolvedIDs["flash"] || len(got.ResolvedFindings) != 2 {
		t.Errorf("ResolvedFindings = %+v, want exactly windows-firewall-enabled + flash", got.ResolvedFindings)
	}
}

func TestComputeTrend_SameFindingsBothSides_NoNewNoResolved(t *testing.T) {
	shared := PostureCheckInput{Collected: true, Score: 80, Findings: []Finding{{ID: "windows-bitlocker-enabled", Title: "BitLocker disabled"}}}
	got := computeTrend(HealthInputs{SecurityConfig: shared}, HealthInputs{SecurityConfig: shared})
	if len(got.NewFindings) != 0 || len(got.ResolvedFindings) != 0 {
		t.Errorf("expected no new/resolved findings when both sides match, got new=%+v resolved=%+v", got.NewFindings, got.ResolvedFindings)
	}
}

// TestComputeHealth_UncollectedExposureIsNotAPerfectScore pins a real defect.
// Every exposure score is a pure-deficit model (100 - risk), so an endpoint
// with nothing collected produced ExposureScore/AttackPathScore/
// DetectionCoverageScore/VulnerabilityScore all = 100 (verified empirically
// against exposure.Build). These three categories used to hardcode
// Collected:true, and only Collected categories feed HealthScore -- so an
// endpoint about which NOTHING was known reported HealthScore 100 on a
// dashboard labelled "higher is safer". They must now be excluded entirely.
func TestComputeHealth_UncollectedExposureIsNotAPerfectScore(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Scores: exposure.ScoreBreakdown{
			// Exactly what exposure.Build emits with zero collected data.
			ExposureScore: 100, AttackPathScore: 100,
			DetectionCoverageScore: 100, VulnerabilityScore: 100,
			// ...and nothing was actually measurable.
			ExposureMeasurable: false, AttackPathMeasurable: false,
			DetectionMeasurable: false, VulnerabilityMeasurable: false,
		},
	}
	got := ComputeHealth("agent-nodata", profile, HealthInputs{}, HealthInputs{})

	if got.Measurable {
		t.Error("Measurable = true, want false — not one category was collected")
	}
	if got.HealthScore == 100 {
		t.Fatal("HealthScore = 100 for an endpoint with nothing collected — the exact defect this guards")
	}
	for _, c := range got.Categories {
		if c.Collected {
			t.Errorf("category %s Collected=true, want false — nothing was collected", c.ID)
		}
		if c.Score != 0 {
			t.Errorf("category %s Score=%d, want 0 — an uncollected category must not carry a fabricated score", c.ID, c.Score)
		}
	}
	if len(got.ActionPlan) != 0 {
		t.Errorf("ActionPlan = %+v, want empty — no data means no actionable findings", got.ActionPlan)
	}
}

// TestComputeHealth_PartialCollectionScoresOnlyWhatIsReal proves the fix is
// per-category, not all-or-nothing: detection genuinely collected, attack
// path and vulnerabilities not, so only detection's score counts.
func TestComputeHealth_PartialCollectionScoresOnlyWhatIsReal(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Scores: exposure.ScoreBreakdown{
			ExposureScore: 100, AttackPathScore: 100,
			DetectionCoverageScore: 40, VulnerabilityScore: 100,
			DetectionMeasurable: true, // only this one is real
		},
	}
	got := ComputeHealth("agent-partial", profile, HealthInputs{}, HealthInputs{})

	if !got.Measurable {
		t.Error("Measurable = false, want true — detection was collected")
	}
	if got.HealthScore != 40 {
		t.Errorf("HealthScore = %d, want 40 — only the genuinely-collected detection score counts", got.HealthScore)
	}
	for _, c := range got.Categories {
		switch c.ID {
		case CategoryDetectionHealth:
			if !c.Collected || c.Score != 40 {
				t.Errorf("detection = %+v, want Collected=true Score=40", c)
			}
		case CategoryExposureAttackPath, CategoryVulnerabilities:
			if c.Collected {
				t.Errorf("category %s Collected=true, want false — its 100 is a no-data artifact", c.ID)
			}
		}
	}
}
