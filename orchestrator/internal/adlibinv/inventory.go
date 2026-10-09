// Package adlibinv inventories whether the live ART atomic and Caldera ability
// libraries already cover a set of AD gap primitives, per ATT&CK technique. It
// answers sub-project E's "reusable vs genuinely missing" question without
// authoring or executing any content.
//
// The ART/Caldera libraries are runtime-only (ART in Postgres, Caldera in the
// bas-caldera image), so the pure logic here is wired to the live stores only
// at runtime. Deferred live wiring, for when a running system is available:
//
//	art, _ := scenario.NewARTStoreFromDB(ctx, pool, payloads)
//	caldera := scenario.NewCalderaStore(calderaURL, apiKey)
//	rep := adlibinv.Inventory(primitives, art, caldera)
//
// That construction needs the DB pool and a running Caldera, so it is not built
// or tested in this package; the logic and the interface seam below are.
package adlibinv

import (
	"sort"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/scenario"
)

// ARTSource is the subset of *scenario.ARTStore this package consumes.
type ARTSource interface {
	GetSteps(techniqueID string) []scenario.ScenarioStep
}

// CalderaSource is the subset of *scenario.CalderaStore this package consumes.
type CalderaSource interface {
	GetAbilities(techniqueID string) []scenario.ScenarioStep
}

// TechCoverage is the inventory result for one distinct ATT&CK technique that
// at least one input primitive maps to.
type TechCoverage struct {
	TechniqueID  string
	PrimitiveIDs []string
	ARTAtomics   int
	CalderaAbils int
	Covered      bool
}

// Report is the full inventory over a set of primitives.
type Report struct {
	Covered       []TechCoverage
	Missing       []TechCoverage
	NoTechniqueID []string
}

// Inventory reports, per technique, whether the live ART/Caldera libraries
// already cover it. A nil source contributes zero (fail-safe: the inventory
// still runs with one store unavailable). Pure and total; executes nothing.
func Inventory(primitives []adprimitive.Primitive, art ARTSource, caldera CalderaSource) Report {
	byTech := map[string][]string{}
	var techniques []string
	var noTech []string
	for _, p := range primitives {
		if p.TechniqueID == "" {
			noTech = append(noTech, p.ID)
			continue
		}
		if _, seen := byTech[p.TechniqueID]; !seen {
			techniques = append(techniques, p.TechniqueID)
		}
		byTech[p.TechniqueID] = append(byTech[p.TechniqueID], p.ID)
	}

	sort.Strings(noTech)
	sort.Strings(techniques)

	rep := Report{NoTechniqueID: noTech}
	for _, tid := range techniques {
		ids := byTech[tid]
		sort.Strings(ids)
		artN := 0
		if art != nil {
			artN = len(art.GetSteps(tid))
		}
		calN := 0
		if caldera != nil {
			calN = len(caldera.GetAbilities(tid))
		}
		tc := TechCoverage{
			TechniqueID:  tid,
			PrimitiveIDs: ids,
			ARTAtomics:   artN,
			CalderaAbils: calN,
			Covered:      artN+calN > 0,
		}
		if tc.Covered {
			rep.Covered = append(rep.Covered, tc)
		} else {
			rep.Missing = append(rep.Missing, tc)
		}
	}
	return rep
}
