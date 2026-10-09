package adlibinv

import (
	"reflect"
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/scenario"
)

// fakeART / fakeCaldera are in-memory sources keyed by technique ID.
type fakeART map[string][]scenario.ScenarioStep

func (f fakeART) GetSteps(t string) []scenario.ScenarioStep { return f[t] }

type fakeCaldera map[string][]scenario.ScenarioStep

func (f fakeCaldera) GetAbilities(t string) []scenario.ScenarioStep { return f[t] }

func prim(id, tech string) adprimitive.Primitive {
	return adprimitive.Primitive{ID: id, TechniqueID: tech}
}

func steps(n int) []scenario.ScenarioStep {
	return make([]scenario.ScenarioStep, n)
}

func TestInventory_TechniqueCoveredByARTIsReportedCovered(t *testing.T) {
	rep := Inventory(
		[]adprimitive.Primitive{prim("dcsync", "T1003.006")},
		fakeART{"T1003.006": steps(2)},
		fakeCaldera{},
	)
	if len(rep.Covered) != 1 || len(rep.Missing) != 0 {
		t.Fatalf("expected 1 covered / 0 missing, got %+v", rep)
	}
	c := rep.Covered[0]
	if c.TechniqueID != "T1003.006" || c.ARTAtomics != 2 || c.CalderaAbils != 0 || !c.Covered {
		t.Fatalf("unexpected coverage row: %+v", c)
	}
}

func TestInventory_TechniqueCoveredOnlyByCalderaIsReportedCovered(t *testing.T) {
	rep := Inventory(
		[]adprimitive.Primitive{prim("p", "T9999")},
		fakeART{},
		fakeCaldera{"T9999": steps(3)},
	)
	if len(rep.Covered) != 1 || rep.Covered[0].CalderaAbils != 3 || rep.Covered[0].ARTAtomics != 0 {
		t.Fatalf("expected caldera-only coverage, got %+v", rep)
	}
}

func TestInventory_TechniqueInNeitherStoreIsMissing(t *testing.T) {
	rep := Inventory(
		[]adprimitive.Primitive{prim("adcs-esc1", "T1649")},
		fakeART{},
		fakeCaldera{},
	)
	if len(rep.Missing) != 1 || rep.Missing[0].Covered || len(rep.Covered) != 0 {
		t.Fatalf("expected 1 missing / 0 covered, got %+v", rep)
	}
}

func TestInventory_PrimitivesSharingTechniqueCollapseToOneRow(t *testing.T) {
	rep := Inventory(
		[]adprimitive.Primitive{prim("adcs-esc2", "T1649"), prim("adcs-esc1", "T1649")},
		fakeART{},
		fakeCaldera{},
	)
	if len(rep.Missing) != 1 {
		t.Fatalf("expected the two T1649 primitives to collapse to one row, got %+v", rep.Missing)
	}
	got := rep.Missing[0].PrimitiveIDs
	if !reflect.DeepEqual(got, []string{"adcs-esc1", "adcs-esc2"}) {
		t.Fatalf("expected sorted primitive IDs, got %v", got)
	}
}

func TestInventory_EmptyTechniqueIDGoesToNoTechniqueID(t *testing.T) {
	rep := Inventory(
		[]adprimitive.Primitive{prim("rbcd-impersonate", ""), prim("acl-genericall-takeover", "")},
		fakeART{},
		fakeCaldera{},
	)
	if len(rep.Covered) != 0 || len(rep.Missing) != 0 {
		t.Fatalf("empty-technique primitives must not appear in Covered/Missing, got %+v", rep)
	}
	if !reflect.DeepEqual(rep.NoTechniqueID, []string{"acl-genericall-takeover", "rbcd-impersonate"}) {
		t.Fatalf("expected sorted NoTechniqueID, got %v", rep.NoTechniqueID)
	}
}

func TestInventory_NilSourcesDoNotPanicAndFallToMissing(t *testing.T) {
	rep := Inventory([]adprimitive.Primitive{prim("dcsync", "T1003.006")}, nil, nil)
	if len(rep.Missing) != 1 || rep.Missing[0].ARTAtomics != 0 || rep.Missing[0].CalderaAbils != 0 {
		t.Fatalf("nil sources must yield a missing row with zero counts, got %+v", rep)
	}
}

func TestInventory_OutputIsSortedByTechniqueID(t *testing.T) {
	rep := Inventory(
		[]adprimitive.Primitive{prim("c", "T3000"), prim("a", "T1000"), prim("b", "T2000")},
		fakeART{"T1000": steps(1), "T2000": steps(1), "T3000": steps(1)},
		fakeCaldera{},
	)
	if len(rep.Covered) != 3 ||
		rep.Covered[0].TechniqueID != "T1000" ||
		rep.Covered[1].TechniqueID != "T2000" ||
		rep.Covered[2].TechniqueID != "T3000" {
		t.Fatalf("expected techniques sorted ascending, got %+v", rep.Covered)
	}
}
