package api

import (
	"net/http"

	"github.com/audspect/bas/internal/phishcatalog"
)

// Library entry types. The type is set by the server from the source the entry
// came from, never inferred from a name or an ID. A client routes on this field
// alone, so an entry with a missing or unknown type has no execution path.
const (
	LibraryTypeAgent    = "agent"
	LibraryTypePhishing = "phishing"
)

// Library entry statuses. "executable" means the server can run it right now.
// "experimental" means runnable but flagged as a best-effort heuristic.
// "available" means catalog-only: it is listed, and the server cannot run it.
const (
	LibraryStatusExecutable   = "executable"
	LibraryStatusExperimental = "experimental"
	LibraryStatusAvailable    = "available"
)

// ScenarioLibraryEntry is one row of the Scenario Library.
type ScenarioLibraryEntry struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// phishingLibraryEntries turns the phishing catalog into library rows. The
// status comes from the registry (executable), never from the catalog alone:
// an entry the registry cannot run is "available" whatever the catalog says.
func phishingLibraryEntries(catalog []phishcatalog.Scenario, executable func(id string) bool) []ScenarioLibraryEntry {
	out := make([]ScenarioLibraryEntry, 0, len(catalog))
	for _, sc := range catalog {
		status := LibraryStatusAvailable
		if executable(sc.ID) {
			status = LibraryStatusExecutable
			if sc.Experimental {
				status = LibraryStatusExperimental
			}
		}
		out = append(out, ScenarioLibraryEntry{
			Type: LibraryTypePhishing, ID: sc.ID, Name: sc.Name, Status: status,
		})
	}
	return out
}

// GET /api/scenarios/library -- read-only, same viewer tier as /api/scenarios.
// Running a phishing entry still requires CanRunScenario on POST /api/phishing-runs.
// This endpoint grants no execution rights.
func (h *Handler) ListScenarioLibrary(w http.ResponseWriter, r *http.Request) {
	entries := make([]ScenarioLibraryEntry, 0)
	for _, sc := range h.engine.List() {
		entries = append(entries, ScenarioLibraryEntry{
			Type: LibraryTypeAgent, ID: sc.ID, Name: sc.Name, Status: LibraryStatusExecutable,
		})
	}
	catalog, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		jsonError(w, "phishing catalog unavailable", http.StatusInternalServerError)
		return
	}
	entries = append(entries, phishingLibraryEntries(catalog, func(id string) bool {
		_, ok := LookupPhishingRunExecutor(id)
		return ok
	})...)
	respond(w, entries)
}
