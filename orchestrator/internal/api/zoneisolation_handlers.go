package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/zoneisolation"
)

const maxZoneIsolationImportRequestBytes = 5 << 20

// CreateZoneIsolationImport -- POST /api/zone-isolation-imports.
func (h *Handler) CreateZoneIsolationImport(w http.ResponseWriter, r *http.Request) {
	var req zoneisolation.IsolationImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxZoneIsolationImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateZoneIsolationImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertZoneIsolationImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "zoneisolation.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "zoneisolation.import", req.ID, map[string]any{"zonePairIsolationCount": len(req.ZonePairIsolations)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateZoneIsolationImport(imp *zoneisolation.IsolationImport) error {
	if len(imp.ZonePairIsolations) > zoneisolation.MaxZonePairIsolationsPerImport {
		return fmt.Errorf("too many zone pair isolations — got %d, max %d", len(imp.ZonePairIsolations), zoneisolation.MaxZonePairIsolationsPerImport)
	}

	hasLimitations := len(imp.Limitations) > 0
	if len(imp.ZonePairIsolations) > 0 && !hasLimitations {
		return fmt.Errorf("limitations must be non-empty whenever any zone pair isolation is declared — zone names are never cross-validated against a real network-topology import")
	}

	for i, zp := range imp.ZonePairIsolations {
		if zp.ZoneA == "" || zp.ZoneB == "" {
			return fmt.Errorf("zonePairIsolations[%d]: zoneA and zoneB are both required", i)
		}
	}
	return nil
}

// ListZoneIsolationImports -- GET /api/zone-isolation-imports.
func (h *Handler) ListZoneIsolationImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListZoneIsolationImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*zoneisolation.IsolationImport{}
	}
	respond(w, imports)
}

// GetZoneIsolationImport -- GET /api/zone-isolation-imports/{id}.
func (h *Handler) GetZoneIsolationImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetZoneIsolationImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "zone isolation import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
