package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/coverage"
	"github.com/audspect/bas/internal/threatpriority"
)

// GET /api/threat-priority/actors
// Ranked list of every actor with a threat_actor_profiles row, sorted Score
// desc then ActorName asc (same determinism convention as
// internal/recommend's sort). Distinct from GET /api/coverage/matrix
// (technique-level content existence) and GET /api/recommend/simulations
// (technique-level ranking) -- this is the actor-level view.
func (h *Handler) ThreatPriorityActors(w http.ResponseWriter, r *http.Request) {
	if h.threatPriorityEngine == nil {
		respond(w, []threatpriority.ActorPriority{})
		return
	}
	scores, err := h.threatPriorityEngine.ScoreAll(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, scores)
}

// threatPriorityActorDetail is the GET /api/threat-priority/actors/{name}
// response shape: the actor's ActorPriority plus history and the concrete
// list of uncovered techniques (feeds the Actor Details "Techniques"/
// "Coverage" tabs).
type threatPriorityActorDetail struct {
	threatpriority.ActorPriority
	History             []threatpriority.ActorPriorityHistory `json:"history"`
	UncoveredTechniques []string                              `json:"uncoveredTechniques"`
}

// GET /api/threat-priority/actors/{name}
func (h *Handler) ThreatPriorityActorDetail(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if h.threatPriorityEngine == nil {
		respond(w, threatPriorityActorDetail{UncoveredTechniques: []string{}})
		return
	}
	ap, err := h.threatPriorityEngine.Score(r.Context(), name)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hist, err := h.threatPriorityEngine.History(r.Context(), name, 30)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	scenarios := h.engine.List()
	sim := coverage.BuildSimulationIndex(scenarios)
	detect := coverage.BuildProfileIndex(h.engine.Profiles())
	compliant := coverage.BuildComplianceIndex(scenarios)

	uncovered := []string{}
	for _, id := range ap.TechniqueIDs {
		if !sim[id] && !detect[id] && !compliant[id] {
			uncovered = append(uncovered, id)
		}
	}

	respond(w, threatPriorityActorDetail{
		ActorPriority: ap, History: hist, UncoveredTechniques: uncovered,
	})
}
