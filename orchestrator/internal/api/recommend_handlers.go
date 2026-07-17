package api

import (
	"net/http"
	"strconv"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/recommend"
)

// GetRecommendedSimulations ranks the ART-testable ATT&CK techniques by how
// much value testing them next would add — Phase 6. Read-only (Viewer+).
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

	recs, err := recommend.Build(r.Context(), h.db, g, s, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, recs)
}
