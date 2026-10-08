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

func TestAll_ReturnsTheFourteenShippedPrimitives(t *testing.T) {
	all := All()
	if len(all) != 14 {
		t.Fatalf("expected 14 primitives across the five shipped catalogs, got %d", len(all))
	}
	b := Compute(All())
	if b.TotalPrimitives != 14 {
		t.Errorf("expected benchmark total 14, got %d", b.TotalPrimitives)
	}
	// Of the 14, exactly 8 carry a TechniqueID (Kerberoasting 3 + DCSync 1 +
	// ADCS 4); the 6 ACL-abuse/RBCD primitives carry none.
	if b.TechniqueMapped != 8 {
		t.Errorf("expected 8 technique-mapped primitives, got %d", b.TechniqueMapped)
	}
}
