package adchain

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestPathRisk_EmptyPathIsZero(t *testing.T) {
	if got := PathRisk(nil); got != 0 {
		t.Errorf("expected 0 for empty path, got %d", got)
	}
}

func TestPathRisk_SumsPerClassWeights(t *testing.T) {
	path := []adprimitive.Primitive{
		{ID: "a", RiskClass: adprimitive.RiskNonDestructive},         // 1
		{ID: "b", RiskClass: adprimitive.RiskPotentiallyDestructive}, // 3
		{ID: "c", RiskClass: adprimitive.RiskDestructive},            // 9
	}
	if got := PathRisk(path); got != 13 {
		t.Errorf("expected 1+3+9=13, got %d", got)
	}
}

func TestPathRisk_UnclassifiedScoresFailClosedMax(t *testing.T) {
	path := []adprimitive.Primitive{{ID: "x", RiskClass: ""}}
	if got := PathRisk(path); got != 9 {
		t.Errorf("expected unclassified primitive to score the fail-closed max 9, got %d", got)
	}
}

func adaptiveCatalog() []adprimitive.Primitive {
	// Two independent routes from CapDomainUser to CapLocalAdmin:
	//   cheap-a -> cheap-b  (both potentially_destructive)
	//   risky-direct        (one destructive step)
	return []adprimitive.Primitive{
		{
			ID: "cheap-a", RiskClass: adprimitive.RiskPotentiallyDestructive,
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapGroupMember}},
		},
		{
			ID: "cheap-b", RiskClass: adprimitive.RiskPotentiallyDestructive,
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapGroupMember}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapLocalAdmin}},
		},
		{
			ID: "risky-direct", RiskClass: adprimitive.RiskDestructive,
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapLocalAdmin}},
		},
	}
}

func TestPlanExcluding_AvoidsExcludedPrimitiveAndReroutes(t *testing.T) {
	held := []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}
	target := adprimitive.Capability{Kind: adprimitive.CapLocalAdmin}

	// Exclude the direct risky step -> must re-route via cheap-a/cheap-b.
	path, ok := PlanExcluding(adaptiveCatalog(), held, target, MapResolver{}, map[string]bool{"risky-direct": true})
	if !ok {
		t.Fatal("expected a re-route to exist avoiding risky-direct")
	}
	for _, p := range path {
		if p.ID == "risky-direct" {
			t.Fatalf("excluded primitive risky-direct appeared in the path: %+v", path)
		}
	}
}

func TestPlanExcluding_UnreachableWhenAllRoutesExcluded(t *testing.T) {
	held := []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}
	target := adprimitive.Capability{Kind: adprimitive.CapLocalAdmin}

	// Excluding cheap-b AND risky-direct leaves no route to CapLocalAdmin.
	_, ok := PlanExcluding(adaptiveCatalog(), held, target, MapResolver{}, map[string]bool{"cheap-b": true, "risky-direct": true})
	if ok {
		t.Fatal("expected ok=false: every route to the target is excluded")
	}
}
