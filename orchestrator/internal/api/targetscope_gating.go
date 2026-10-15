package api

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/targetscope"
)

// resolveTargetScopeImport resolves the target-scope import context
// an active-probe handler needs to run targetscope.UnauthorizedTargets.
// An explicit, caller-supplied id is loaded directly (404 if it does
// not exist); an omitted id falls back to the most recently created
// target-scope import, so a request that never mentions the field
// still gets checked against whatever the operator has declared.
//
// When no target-scope import has EVER been created, the returned
// scope is nil -- callers must treat this as fail-open (nothing was
// ever declared, so there is nothing to check a target against). A
// genuine lookup failure -- anything other than "never created" --
// writes an error response and returns ok=false: the caller MUST fail
// closed and must not proceed as if nothing had been imported.
func (h *Handler) resolveTargetScopeImport(w http.ResponseWriter, r *http.Request, targetScopeImportID string) (scope *targetscope.TargetScopeImport, ok bool) {
	if targetScopeImportID != "" {
		s, err := db.GetTargetScopeImport(r.Context(), h.db, targetScopeImportID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "target scope import not found", http.StatusNotFound)
				return nil, false
			}
			jsonError(w, "failed to load the declared target scope import: "+err.Error(), http.StatusInternalServerError)
			return nil, false
		}
		return s, true
	}

	latest, err := db.ListTargetScopeImports(r.Context(), h.db, 1)
	if err != nil {
		jsonError(w, "failed to resolve the current target scope import for target authorization gating: "+err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	if len(latest) > 0 {
		return latest[0], true
	}
	return nil, true
}
