package api

import (
	"net/http"
	"strconv"

	"github.com/audspect/bas/internal/search"
)

// GET /api/search?q=<term>&limit=<n>
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	results, err := search.Query(r.Context(), h.db, q, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, results)
}

// POST /api/search/reindex
func (h *Handler) SearchReindex(w http.ResponseWriter, r *http.Request) {
	if err := search.ReindexAll(r.Context(), h.db, h.engine); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]string{"status": "ok"})
}
