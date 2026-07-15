package api

import (
	"net/http"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/pathcorrelation"
)

// GetAttackPathCorrelation annotates the fleet attack-path graph's
// dangerous paths and choke points with expected/verified detection
// coverage — SP3. Read-only (Viewer+). Returns a zero-value, 100-scored
// correlation (never an error) when there is no attack-path collection yet
// or when h.rules is not wired, matching the rest of this API's nil-safe
// convention for optional subsystems.
// GET /api/attackpath/correlation
func (h *Handler) GetAttackPathCorrelation(w http.ResponseWriter, r *http.Request) {
	cols := h.loadAttackPathCollections(r)
	g, s := attackpath.BuildGraphAndAnalyze(cols, h.loadAssetTags(r))

	// h.rules is a *rulelib.Engine; a nil pointer passed directly into the
	// pathcorrelation.RuleLibrary interface parameter would produce a
	// non-nil interface wrapping a nil pointer (Go's classic typed-nil
	// trap), so guard explicitly rather than passing h.rules through as-is.
	var rules pathcorrelation.RuleLibrary
	if h.rules != nil {
		rules = h.rules
	}

	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(
		r.Context(), g, s, paths,
		pathcorrelation.DefaultEdgeTechniqueMapper{},
		pathcorrelation.NewSQLRunLookup(h.db),
		rules,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, corr)
}
