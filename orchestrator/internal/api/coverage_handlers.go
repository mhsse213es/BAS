package api

import (
	"net/http"
	"sort"

	"github.com/audspect/bas/internal/coverage"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

// GET /api/coverage/matrix?actor=<name>
//
// If actor is omitted, returns rows for the union of every technique in
// attackdata.GroupTechniqueIndex() (the bundled MITRE STIX baseline) --
// i.e. every technique associated with any known ATT&CK group. If actor
// is given, returns just that actor's technique list from the same index.
//
// This is content-existence coverage (does a simulation/profile/exercise/
// mapping exist at all), distinct from the pre-existing
// GET /api/coverage/analytics (run-result pass/fail aggregation across
// executed runs) -- no overlap, no shared code path.
func (h *Handler) CoverageMatrix(w http.ResponseWriter, r *http.Request) {
	actor := r.URL.Query().Get("actor")
	idx := attackdata.GroupTechniqueIndex()

	var techIDs []string
	if actor != "" {
		techIDs = idx[actor]
	} else {
		seen := make(map[string]bool)
		for _, ids := range idx {
			for _, id := range ids {
				if !seen[id] {
					seen[id] = true
					techIDs = append(techIDs, id)
				}
			}
		}
		sort.Strings(techIDs)
	}

	scenarios := h.engine.List()
	sim := coverage.BuildSimulationIndex(scenarios)
	compliance := coverage.BuildComplianceIndex(scenarios)
	profileIdx := coverage.BuildProfileIndex(h.engine.Profiles())

	purple := make(map[string]bool)
	for _, tmpl := range exercise.BuiltinTemplates {
		for _, id := range tmpl.Metadata.ExpectedTechniques {
			purple[id] = true
		}
	}

	rows := coverage.Compute(techIDs, sim, profileIdx, purple, compliance)
	respond(w, rows)
}

// GET /api/coverage/actors
//
// Returns the sorted list of ATT&CK group names known to
// attackdata.GroupTechniqueIndex() -- populates the actor picker on the
// Technique Coverage tab.
func (h *Handler) CoverageActors(w http.ResponseWriter, r *http.Request) {
	idx := attackdata.GroupTechniqueIndex()
	names := make([]string, 0, len(idx))
	for name := range idx {
		names = append(names, name)
	}
	sort.Strings(names)
	respond(w, map[string][]string{"actors": names})
}
