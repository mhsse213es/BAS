package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/audspect/bas/internal/auth"
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

	c, hasClaims := auth.ClaimsFrom(r.Context())
	results = filterByPermission(results, hasClaims, c)

	// Personalization is best-effort: if it fails, fall back to
	// unpersonalized relevance-only results rather than erroring the whole
	// search -- a degraded ranking beats no results.
	if hasClaims && c != nil {
		if personalized, perr := search.Personalize(r.Context(), h.db, c.UserID, results); perr == nil {
			results = personalized
		}
	}
	respond(w, results)
}

// filterByPermission drops connector-type documents the caller's role
// can't see via their own dedicated list endpoints -- the first RBAC-aware
// filtering Search has needed (Phase 5). Every other doc type stays
// visible to any authenticated user, unchanged from Phase 1-4. Two
// explicit checks, not a generic per-type permission map: only 2 of 12
// doc types need gating today.
func filterByPermission(docs []search.Document, hasClaims bool, c *auth.Claims) []search.Document {
	canDetection := hasClaims && c != nil && auth.HasPermission(c.Role, auth.CanListDetectionConnectors)
	canAction := hasClaims && c != nil && auth.HasPermission(c.Role, auth.CanListResponseConnectors)
	if canDetection && canAction {
		return docs // fast path: nothing to filter
	}
	out := docs[:0]
	for _, d := range docs {
		if d.DocType == "detection_connector" && !canDetection {
			continue
		}
		if d.DocType == "action_connector" && !canAction {
			continue
		}
		out = append(out, d)
	}
	return out
}

// POST /api/search/reindex
func (h *Handler) SearchReindex(w http.ResponseWriter, r *http.Request) {
	if err := search.ReindexAll(r.Context(), h.db, h.engine, h.rules, h.complianceMapper); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]string{"status": "ok"})
}

type searchEntityBody struct {
	DocType  string `json:"docType"`
	SourceID string `json:"sourceId"`
}

// POST /api/search/select — fire-and-forget selection tracking, called by
// the frontend right when a search result is opened. Any authenticated
// user; failures here never block navigation client-side.
func (h *Handler) SearchSelect(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.ClaimsFrom(r.Context())
	if !ok || c == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body searchEntityBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DocType == "" || body.SourceID == "" {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO search_selections (user_id, doc_type, source_id) VALUES ($1,$2,$3)`,
		c.UserID, body.DocType, body.SourceID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]string{"status": "ok"})
}

// POST /api/search/favorite — toggles: inserts if absent, deletes if
// present. Any authenticated user.
func (h *Handler) SearchFavorite(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.ClaimsFrom(r.Context())
	if !ok || c == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body searchEntityBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DocType == "" || body.SourceID == "" {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}

	var exists bool
	if err := h.db.QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM search_favorites WHERE user_id=$1 AND doc_type=$2 AND source_id=$3)`,
		c.UserID, body.DocType, body.SourceID).Scan(&exists); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if exists {
		if _, err := h.db.Exec(r.Context(),
			`DELETE FROM search_favorites WHERE user_id=$1 AND doc_type=$2 AND source_id=$3`,
			c.UserID, body.DocType, body.SourceID); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respond(w, map[string]bool{"favorited": false})
		return
	}

	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO search_favorites (user_id, doc_type, source_id) VALUES ($1,$2,$3)`,
		c.UserID, body.DocType, body.SourceID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]bool{"favorited": true})
}

// GET /api/search/recents — favorites + recent selections for the empty-
// input ⌘K palette state. Any authenticated user.
func (h *Handler) SearchRecents(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.ClaimsFrom(r.Context())
	if !ok || c == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	results, err := search.Recents(r.Context(), h.db, c.UserID, 5)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, results)
}

// searchOperatorInfo describes one supported search-box operator and the
// values it accepts, for the ⌘K palette's discoverability hint.
type searchOperatorInfo struct {
	Name   string   `json:"name"`
	Values []string `json:"values,omitempty"`
}

// GET /api/search/operators — advertises every field: operator ParseQuery
// currently validates and applies, plus their valid values, so a future
// frontend never has to hardcode a second copy of this list. Any
// authenticated user.
func (h *Handler) SearchOperators(w http.ResponseWriter, r *http.Request) {
	ops := make([]searchOperatorInfo, 0, len(search.SupportedOperators))
	for _, name := range search.SupportedOperators {
		info := searchOperatorInfo{Name: name}
		if name == "type" {
			info.Values = search.KnownDocTypes
		}
		ops = append(ops, info)
	}
	respond(w, map[string]any{"operators": ops})
}
