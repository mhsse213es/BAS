package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/recommend"
)

// GetRecommendedSimulations ranks the ART-testable ATT&CK techniques by how
// much value testing them next would add — Phase 6, now weighted by actor
// priority too. Read-only (Viewer+).
// Query params: limit (default 20, clamped to [1,100]).
// GET /api/recommend/simulations
func (h *Handler) GetRecommendedSimulations(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 100 {
			limit = n
		}
	}

	// Same "caller builds the graph once" convention as the exposure handlers —
	// reuses the Handler's existing loaders rather than duplicating them inside
	// internal/recommend. A fleet with no collections yields an empty graph, and
	// every technique simply scores 0 on environment relevance.
	cols := h.loadAttackPathCollections(r)
	g, s := attackpath.BuildGraphAndAnalyze(cols, h.loadAssetTags(r))

	var sectors, regions []string
	if h.reportingEngine != nil {
		sectors = h.reportingEngine.Sectors()
		regions = h.reportingEngine.Regions()
	}

	actorPriorityByTechnique := h.buildActorPriorityByTechnique(r.Context())

	recs, err := recommend.Build(r.Context(), h.db, g, s, limit, sectors, regions, actorPriorityByTechnique)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, recs)
}

// buildActorPriorityByTechnique takes the max ActorPriority score among all
// actors known to use each technique -- a technique used by even one
// Critical-priority actor should read as urgent, never averaged down by
// low-priority actors sharing it. nil (not an error) when no priority
// engine is attached or scoring fails, so recommendations degrade to their
// pre-Threat-Prioritization behavior rather than erroring out.
func (h *Handler) buildActorPriorityByTechnique(ctx context.Context) map[string]int {
	if h.threatPriorityEngine == nil {
		return nil
	}
	scores, err := h.threatPriorityEngine.ScoreAll(ctx)
	if err != nil {
		return nil
	}
	out := map[string]int{}
	for _, ap := range scores {
		for _, id := range ap.TechniqueIDs {
			key := strings.ToUpper(id)
			if ap.Score > out[key] {
				out[key] = ap.Score
			}
		}
	}
	return out
}
