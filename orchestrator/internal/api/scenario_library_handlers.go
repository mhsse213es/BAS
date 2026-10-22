package api

import (
	"net/http"

	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/phishcatalog"
)

// Library entry types. The server sets the type from the source the entry came
// from, never from a name or an ID. A client routes on this field alone.
const (
	LibraryTypeAgent    = "agent"
	LibraryTypePhishing = "phishing"
)

// ScenarioLibraryEntry is one row of the Scenario Library. Three facts are kept
// apart. Status is what this installation can run now (with a Reason when it
// cannot). Experimental is a property of the scenario and stays set in every
// state. LiveValidated is set only when a live integration has exercised the
// scenario, and no scenario is marked that way yet.
type ScenarioLibraryEntry struct {
	Type          string      `json:"type"`
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Status        string      `json:"status"`
	Reason        string      `json:"reason,omitempty"`
	Experimental  bool        `json:"experimental"`
	LiveValidated bool        `json:"liveValidated"`
	Parameters    []ParamSpec `json:"parameters,omitempty"`
}

// phishingLibraryEntries turns the catalog into library rows. Each row's status
// comes from phishingCapabilityFor, which reads the same environment the trigger
// uses, so a row can never report runnable when the trigger would refuse it.
func phishingLibraryEntries(catalog []phishcatalog.Scenario, env PhishingRunExecutorEnv) []ScenarioLibraryEntry {
	out := make([]ScenarioLibraryEntry, 0, len(catalog))
	for _, sc := range catalog {
		c := phishingCapabilityFor(env, sc.ID, sc.Experimental)
		out = append(out, ScenarioLibraryEntry{
			Type:          LibraryTypePhishing,
			ID:            sc.ID,
			Name:          sc.Name,
			Status:        c.Status,
			Reason:        c.Reason,
			Experimental:  sc.Experimental,
			LiveValidated: sc.Coverage == phishcatalog.CoverageLiveValidated,
			Parameters:    phishingRunParams[sc.ID],
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
			Type: LibraryTypeAgent, ID: sc.ID, Name: sc.Name, Status: CapAvailable,
		})
	}
	// Phishing is an Advanced product. A licence without it gets no phishing entries, and the
	// catalogue is not read at all.
	if license.PermitsNow(license.ProductPhishing) {
		catalog, err := phishcatalog.AudspectPhishingCatalog()
		if err != nil {
			jsonError(w, "phishing catalog unavailable", http.StatusInternalServerError)
			return
		}
		entries = append(entries, phishingLibraryEntries(catalog, h.phishingRunEnv())...)
	}
	respond(w, entries)
}
