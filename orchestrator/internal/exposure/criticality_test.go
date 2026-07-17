package exposure

import "testing"

func TestCriticalityRisk_UntaggedIsZero(t *testing.T) {
	if got := CriticalityRisk(AssetCriticalityInputs{}); got != 0 {
		t.Fatalf("untagged asset should score 0, got %d", got)
	}
}

func TestCriticalityRisk_TierBases(t *testing.T) {
	cases := map[string]int{"critical": 100, "high": 70, "medium": 40, "low": 15, "": 0}
	for tier, want := range cases {
		got := CriticalityRisk(AssetCriticalityInputs{CriticalityTier: tier})
		if got != want {
			t.Errorf("tier %q: got %d, want %d", tier, got, want)
		}
	}
}

func TestCriticalityRisk_BooleanBumpsAddUp(t *testing.T) {
	got := CriticalityRisk(AssetCriticalityInputs{
		IsDomainController: true, InternetFacing: true, IdentityExposed: true, Production: true,
		ComplianceScope: []string{"SEBI-CSCRF"}, ThreatGroupCount: 3,
	})
	want := 15 + 10 + 10 + 10 + 10 + 5 // 60, no tier set
	if got != want {
		t.Fatalf("got %d, want %d", got, want)
	}
}

func TestCriticalityRisk_CappedAt100(t *testing.T) {
	got := CriticalityRisk(AssetCriticalityInputs{
		CriticalityTier: "critical", IsDomainController: true, InternetFacing: true, IdentityExposed: true,
		Production: true, ComplianceScope: []string{"PCI-DSS"}, ThreatGroupCount: 1,
	})
	if got != 100 {
		t.Fatalf("got %d, want capped at 100", got)
	}
}
