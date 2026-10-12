// Package adcoverage maps AD-M04 primitives to the executable capabilities
// Audspect already ships, by joining each primitive to existing scenario
// steps on MITRE TechniqueID. It authors nothing and executes nothing --
// it reads already-shipped scenario metadata and reports coverage vs. gaps
// (sub-project A of the executable-content decomposition). Depends one-way
// on adprimitive and scenario.
package adcoverage

import (
	"sort"

	"github.com/audspect/bas/internal/adprimitive"
)

// StepRef points at an existing capability: one step in a shipped scenario.
type StepRef struct {
	Scenario    string
	StepName    string
	Framework   string // art | caldera | custom
	TechniqueID string
}

// PrimitiveCoverage pairs one primitive with the existing scenario steps
// that implement its technique. Steps empty => the primitive is a gap.
type PrimitiveCoverage struct {
	Primitive adprimitive.Primitive
	Steps     []StepRef
}

// Report separates covered primitives from gaps.
type Report struct {
	Covered []PrimitiveCoverage
	Gaps    []PrimitiveCoverage
}

// Map joins each primitive to index by TechniqueID equality. A primitive
// with an empty TechniqueID, or one whose technique has no index entry,
// lands in Gaps. Both buckets are sorted by primitive ID.
func Map(primitives []adprimitive.Primitive, index map[string][]StepRef) Report {
	var rep Report
	for _, p := range primitives {
		if steps := index[p.TechniqueID]; p.TechniqueID != "" && len(steps) > 0 {
			rep.Covered = append(rep.Covered, PrimitiveCoverage{Primitive: p, Steps: steps})
		} else {
			rep.Gaps = append(rep.Gaps, PrimitiveCoverage{Primitive: p})
		}
	}
	sort.Slice(rep.Covered, func(i, j int) bool { return rep.Covered[i].Primitive.ID < rep.Covered[j].Primitive.ID })
	sort.Slice(rep.Gaps, func(i, j int) bool { return rep.Gaps[i].Primitive.ID < rep.Gaps[j].Primitive.ID })
	return rep
}
