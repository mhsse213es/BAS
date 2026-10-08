// Package adbench implements AD-M12 ("AD Mastery Benchmark"): a pure,
// read-only aggregation that measures the AD primitive library built by
// this initiative -- total primitives, breakdown by RiskClass, how many
// are MITRE-technique-mapped, and the distinct ATT&CK techniques covered.
// Depends one-way on adprimitive only; no DB, no external universe to
// measure coverage against -- the catalogs are self-contained Go data, so
// this benchmarks the library itself.
package adbench

import (
	"sort"

	"github.com/audspect/bas/internal/adprimitive"
)

// Benchmark is the read-only summary of a set of primitive catalogs.
type Benchmark struct {
	TotalPrimitives    int
	ByRiskClass        map[adprimitive.RiskClass]int
	TechniqueMapped    int      // primitives with a non-empty TechniqueID
	DistinctTechniques []string // deduped, sorted, no empty string
}

// All returns the five shipped primitive catalogs concatenated, so a
// caller can benchmark the whole library with Compute(All()).
func All() []adprimitive.Primitive {
	var out []adprimitive.Primitive
	out = append(out, adprimitive.KerberoastingCatalog...)
	out = append(out, adprimitive.ACLAbuseCatalog...)
	out = append(out, adprimitive.RBCDCatalog...)
	out = append(out, adprimitive.DCSyncCatalog...)
	out = append(out, adprimitive.ADCSCatalog...)
	return out
}

// Compute aggregates any set of primitive catalogs into a Benchmark. Its
// maps and slices are always non-nil, safe to range over for empty input.
func Compute(catalogs ...[]adprimitive.Primitive) Benchmark {
	b := Benchmark{
		ByRiskClass:        map[adprimitive.RiskClass]int{},
		DistinctTechniques: []string{},
	}
	techniques := map[string]bool{}
	for _, catalog := range catalogs {
		for _, p := range catalog {
			b.TotalPrimitives++
			b.ByRiskClass[p.RiskClass]++
			if p.TechniqueID != "" {
				b.TechniqueMapped++
				techniques[p.TechniqueID] = true
			}
		}
	}
	for id := range techniques {
		b.DistinctTechniques = append(b.DistinctTechniques, id)
	}
	sort.Strings(b.DistinctTechniques)
	return b
}
