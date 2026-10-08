// Package adcve bridges AD-M10 ("Continuous AD Research/CVE Pipeline")
// into the existing, already-built CVE/technique relationship store
// (internal/relationships). It adds no scheduling, no CVE fetching, and
// no AD-specific tagging anywhere -- the project's existing continuous-
// intelligence pipeline (internal/connector.Scheduler) and CVE data
// model (relationships.Store) already cover those; this package only
// cross-references into them by TechniqueID.
package adcve

import (
	"context"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/relationships"
)

// RelatedCVEs looks up CVE relationships already recorded for p's
// TechniqueID via store.ForTechnique. Returns ok=false, without
// querying store, when p.TechniqueID is empty -- relationships are
// keyed on technique ID, so a primitive with no 1:1 MITRE mapping has
// nothing to look up.
func RelatedCVEs(ctx context.Context, store *relationships.Store, p adprimitive.Primitive) ([]relationships.Relationship, bool, error) {
	if p.TechniqueID == "" {
		return nil, false, nil
	}
	rels, err := store.ForTechnique(ctx, p.TechniqueID)
	if err != nil {
		return nil, false, err
	}
	return rels, true, nil
}
