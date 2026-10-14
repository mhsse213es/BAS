package adbench

import (
	"reflect"
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestCompute_EmptyInputIsZeroValueButNonNil(t *testing.T) {
	b := Compute()
	if b.TotalPrimitives != 0 {
		t.Errorf("expected 0 total, got %d", b.TotalPrimitives)
	}
	if b.ByRiskClass == nil {
		t.Error("ByRiskClass must be non-nil even for empty input")
	}
	if b.DistinctTechniques == nil {
		t.Error("DistinctTechniques must be non-nil even for empty input")
	}
	if len(b.ByRiskClass) != 0 || len(b.DistinctTechniques) != 0 {
		t.Errorf("expected empty maps/slices, got %+v", b)
	}
}

func TestCompute_CountsDedupsAndSorts(t *testing.T) {
	catalog := []adprimitive.Primitive{
		{ID: "a", TechniqueID: "T1649", RiskClass: adprimitive.RiskPotentiallyDestructive},
		{ID: "b", TechniqueID: "T1649", RiskClass: adprimitive.RiskPotentiallyDestructive}, // shares T1649
		{ID: "c", TechniqueID: "T1003.006", RiskClass: adprimitive.RiskPotentiallyDestructive},
		{ID: "d", TechniqueID: "", RiskClass: adprimitive.RiskNonDestructive}, // no technique
	}
	b := Compute(catalog)

	if b.TotalPrimitives != 4 {
		t.Errorf("expected 4 total, got %d", b.TotalPrimitives)
	}
	// Risk buckets sum to total.
	sum := 0
	for _, n := range b.ByRiskClass {
		sum += n
	}
	if sum != b.TotalPrimitives {
		t.Errorf("ByRiskClass sums to %d, expected %d", sum, b.TotalPrimitives)
	}
	if b.ByRiskClass[adprimitive.RiskPotentiallyDestructive] != 3 || b.ByRiskClass[adprimitive.RiskNonDestructive] != 1 {
		t.Errorf("unexpected risk breakdown: %+v", b.ByRiskClass)
	}
	// TechniqueMapped counts PRIMITIVES with a technique (3), not distinct techniques (2).
	if b.TechniqueMapped != 3 {
		t.Errorf("expected 3 technique-mapped primitives, got %d", b.TechniqueMapped)
	}
	// Distinct techniques: deduped, no empty string, sorted.
	if !reflect.DeepEqual(b.DistinctTechniques, []string{"T1003.006", "T1649"}) {
		t.Errorf("expected [T1003.006 T1649], got %v", b.DistinctTechniques)
	}
}

func TestAll_ReturnsTheTwentyShippedPrimitives(t *testing.T) {
	// Grew from 14: ADCS 4->7 (ESC6/8 additions) and DCSync 1->2, plus
	// ACL-abuse/RBCD gained 2 mapped primitives (combined 6->8, still 6
	// unmapped). Re-derive from adprimitive's catalogs directly rather than
	// re-hardcoding a second snapshot if this needs updating again.
	all := All()
	if len(all) != 20 {
		t.Fatalf("expected 20 primitives across the five shipped catalogs, got %d", len(all))
	}
	b := Compute(All())
	if b.TotalPrimitives != 20 {
		t.Errorf("expected benchmark total 20, got %d", b.TotalPrimitives)
	}
	// Of the 20, exactly 14 carry a TechniqueID (Kerberoasting 3 + ACLAbuse 1
	// + RBCD 1 + DCSync 2 + ADCS 7); the remaining 6 (4 ACL-abuse + 2 RBCD)
	// carry none.
	if b.TechniqueMapped != 14 {
		t.Errorf("expected 14 technique-mapped primitives, got %d", b.TechniqueMapped)
	}
}
