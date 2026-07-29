package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/threatgraph"
)

// GET /api/knowledge-graph/{type}/{id}
func (h *Handler) KnowledgeGraphNeighborhood(w http.ResponseWriter, r *http.Request) {
	nodeType := chi.URLParam(r, "type")
	id := chi.URLParam(r, "id")
	n, err := threatgraph.Lookup(r.Context(), h.db, nodeType, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	respond(w, n)
}
