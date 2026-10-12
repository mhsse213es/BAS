package adcoverage

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestMap_CoveredGapAndNoTechnique(t *testing.T) {
	index := map[string][]StepRef{
		"T1558.003": {{Scenario: "kerb.yaml", StepName: "SPN enum", Framework: "custom", TechniqueID: "T1558.003"}},
	}
	primitives := []adprimitive.Primitive{
		{ID: "spn-enumerate", TechniqueID: "T1558.003"},  // covered
		{ID: "dcsync", TechniqueID: "T1003.006"},         // technique present on primitive, absent from index -> gap
		{ID: "acl-genericall-takeover", TechniqueID: ""}, // no technique -> gap
	}
	rep := Map(primitives, index)

	if len(rep.Covered) != 1 || rep.Covered[0].Primitive.ID != "spn-enumerate" {
		t.Fatalf("expected spn-enumerate covered, got %+v", rep.Covered)
	}
	if len(rep.Covered[0].Steps) != 1 || rep.Covered[0].Steps[0].Scenario != "kerb.yaml" {
		t.Fatalf("expected the matching step attached, got %+v", rep.Covered[0].Steps)
	}
	gapIDs := map[string]bool{}
	for _, g := range rep.Gaps {
		gapIDs[g.Primitive.ID] = true
		if len(g.Steps) != 0 {
			t.Errorf("gap %s must carry no steps, got %+v", g.Primitive.ID, g.Steps)
		}
	}
	if !gapIDs["dcsync"] || !gapIDs["acl-genericall-takeover"] {
		t.Fatalf("expected dcsync and acl-genericall-takeover in gaps, got %+v", rep.Gaps)
	}
}

func TestMap_DeterministicOrderWithinBuckets(t *testing.T) {
	index := map[string][]StepRef{"T1": {{TechniqueID: "T1"}}}
	// Supplied out of ID order; both covered.
	primitives := []adprimitive.Primitive{
		{ID: "zeta", TechniqueID: "T1"},
		{ID: "alpha", TechniqueID: "T1"},
	}
	rep := Map(primitives, index)
	if len(rep.Covered) != 2 || rep.Covered[0].Primitive.ID != "alpha" || rep.Covered[1].Primitive.ID != "zeta" {
		t.Fatalf("expected covered sorted by ID [alpha zeta], got %+v", rep.Covered)
	}
}
