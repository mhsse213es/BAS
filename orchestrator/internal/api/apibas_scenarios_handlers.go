package api

import (
	"log"
	"net/http"
	"sort"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
)

// loadAPIBASCatalog is the source of API BAS definitions. A variable so a test can supply its own.
var loadAPIBASCatalog = catalog.All

// apiBASIDCollisions returns the API BAS IDs that also name an engine scenario, sorted. The two sets
// are kept apart so a run request can never resolve an HTTP attack by an engine ID or the reverse.
func apiBASIDCollisions(engineIDs []string, apiScenarios []contract.Scenario) []string {
	engine := make(map[string]bool, len(engineIDs))
	for _, id := range engineIDs {
		engine[id] = true
	}
	var out []string
	for _, s := range apiScenarios {
		if engine[s.ID] {
			out = append(out, s.ID)
		}
	}
	sort.Strings(out)
	return out
}

// apiBASListItem is one API BAS definition in the listing. Source is always "apibas". RunnableHere is
// false: these run through the API BAS runner, never through the agent scenario engine.
type apiBASListItem struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Category     string `json:"category"`
	Claim        string `json:"claim"`
	Source       string `json:"source"`
	RunnableHere bool   `json:"runnableHere"`
}

// ListAPIBASScenarios lists API BAS definitions separately from the engine's scenarios. It fails
// closed: if an API BAS ID is also an engine ID, nothing is listed and the colliding IDs are reported.
// GET /api/scenarios/api-bas
func (h *Handler) ListAPIBASScenarios(w http.ResponseWriter, r *http.Request) {
	all, err := loadAPIBASCatalog()
	if err != nil {
		log.Printf("[scenarios] API BAS catalog failed to load: %v", err)
		jsonError(w, "API BAS catalog could not be loaded", http.StatusInternalServerError)
		return
	}
	engineIDs := make([]string, 0)
	for _, sc := range h.engine.List() {
		engineIDs = append(engineIDs, sc.ID)
	}
	if clash := apiBASIDCollisions(engineIDs, all); len(clash) > 0 {
		log.Printf("[scenarios] API BAS IDs collide with engine scenarios, listing none: %v", clash)
		respondStatus(w, map[string]any{
			"error":      "API BAS IDs collide with engine scenarios; nothing listed",
			"collisions": clash,
		}, http.StatusConflict)
		return
	}
	out := make([]apiBASListItem, 0, len(all))
	for _, s := range all {
		out = append(out, apiBASListItem{
			ID: s.ID, Name: s.Name, Category: s.Category, Claim: s.Claim,
			Source: "apibas", RunnableHere: false,
		})
	}
	respond(w, out)
}
