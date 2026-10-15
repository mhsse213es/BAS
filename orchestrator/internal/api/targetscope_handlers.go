package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/targetscope"
)

const maxTargetScopeImportRequestBytes = 5 << 20

// CreateTargetScopeImport -- POST /api/target-scope-imports.
func (h *Handler) CreateTargetScopeImport(w http.ResponseWriter, r *http.Request) {
	var req targetscope.TargetScopeImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTargetScopeImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateTargetScopeImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertTargetScopeImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "targetscope.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "targetscope.import", req.ID, map[string]any{"authorizedTargetCount": len(req.AuthorizedTargets)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

// validateTargetScopeImport mirrors validateOTSafetyImport's discipline:
// a cap on declared entries, and limitations required whenever any
// entry is declared. Each entry must declare exactly one of
// cidr/host, and a declared cidr must parse.
func validateTargetScopeImport(imp *targetscope.TargetScopeImport) error {
	if len(imp.AuthorizedTargets) > targetscope.MaxAuthorizedTargetsPerImport {
		return fmt.Errorf("too many authorized targets — got %d, max %d", len(imp.AuthorizedTargets), targetscope.MaxAuthorizedTargetsPerImport)
	}

	hasLimitations := len(imp.Limitations) > 0
	if len(imp.AuthorizedTargets) > 0 && !hasLimitations {
		return fmt.Errorf("limitations must be non-empty whenever any authorized target is declared — targets are never cross-validated against a real network-topology import")
	}

	for i, at := range imp.AuthorizedTargets {
		hasCIDR, hasHost := at.CIDR != "", at.Host != ""
		if hasCIDR == hasHost {
			return fmt.Errorf("authorizedTargets[%d]: exactly one of cidr or host is required", i)
		}
		if hasCIDR {
			if _, _, err := net.ParseCIDR(at.CIDR); err != nil {
				return fmt.Errorf("authorizedTargets[%d]: invalid cidr %q: %w", i, at.CIDR, err)
			}
		}
	}
	return nil
}

// ListTargetScopeImports -- GET /api/target-scope-imports.
func (h *Handler) ListTargetScopeImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListTargetScopeImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*targetscope.TargetScopeImport{}
	}
	respond(w, imports)
}

// GetTargetScopeImport -- GET /api/target-scope-imports/{id}.
func (h *Handler) GetTargetScopeImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetTargetScopeImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "target scope import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
