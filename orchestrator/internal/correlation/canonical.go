package correlation

import (
	"strings"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

// resolveCanonicalTechnique is the package's single Canonical Resolution
// entry point -- the only function permitted to set a TechniqueCorrelation's
// Technique field. attackdata.Lookup already sub-technique-falls-back to a
// parent's data (attackdata.go:224-228) when a sub-technique has no
// enrichment of its own; ID is always set to the originally-queried,
// normalized id -- NOT attackdata.Enrichment.TechniqueID, which on a
// parent-fallback would be the PARENT's ID and would misidentify which
// technique this is. When even the fallback misses (an ID with relationship
// or scenario data but no bundle entry at all), this still returns a
// non-empty CanonicalTechnique{ID: id, Name: id}, so "every technique
// leaving the engine is canonicalized" holds even in the miss case.
func resolveCanonicalTechnique(id string) CanonicalTechnique {
	id = strings.ToUpper(strings.TrimSpace(id))
	e := attackdata.Lookup(id)
	if e == nil {
		return CanonicalTechnique{ID: id, Name: id}
	}
	return CanonicalTechnique{
		ID:          id,
		Name:        e.Name,
		Description: e.Description,
		Platforms:   e.Platforms,
		Tactics:     e.Tactics,
		URL:         e.URL,
	}
}
