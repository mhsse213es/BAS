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
	"github.com/audspect/bas/internal/otsafety"
)

const maxOTSafetyImportRequestBytes = 5 << 20

// CreateOTSafetyImport -- POST /api/ot-safety-imports.
func (h *Handler) CreateOTSafetyImport(w http.ResponseWriter, r *http.Request) {
	var req otsafety.OTSafetyImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOTSafetyImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateOTSafetyImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertOTSafetyImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "otsafety.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "otsafety.import", req.ID, map[string]any{"sensitiveZoneCount": len(req.SensitiveZones), "requiredTransitCount": len(req.RequiredTransits)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateOTSafetyImport(imp *otsafety.OTSafetyImport) error {
	if len(imp.SensitiveZones) > otsafety.MaxSensitiveZonesPerImport {
		return fmt.Errorf("too many sensitive zones — got %d, max %d", len(imp.SensitiveZones), otsafety.MaxSensitiveZonesPerImport)
	}
	if len(imp.RequiredTransits) > otsafety.MaxRequiredTransitsPerImport {
		return fmt.Errorf("too many required transits — got %d, max %d", len(imp.RequiredTransits), otsafety.MaxRequiredTransitsPerImport)
	}

	hasLimitations := len(imp.Limitations) > 0
	if (len(imp.SensitiveZones) > 0 || len(imp.RequiredTransits) > 0) && !hasLimitations {
		return fmt.Errorf("limitations must be non-empty whenever any sensitive zone or required transit is declared — zone names are never cross-validated against a real network-topology import")
	}

	for i, sz := range imp.SensitiveZones {
		if sz.ZoneName == "" {
			return fmt.Errorf("sensitiveZones[%d]: zoneName is required", i)
		}
		if sz.Tier != otsafety.TierOT && sz.Tier != otsafety.TierClinical {
			return fmt.Errorf("sensitiveZones[%d]: unknown tier %q", i, sz.Tier)
		}
	}
	for i, t := range imp.RequiredTransits {
		if t.FromZone == "" || t.ToZone == "" || t.ViaZone == "" {
			return fmt.Errorf("requiredTransits[%d]: fromZone, toZone, and viaZone are all required", i)
		}
	}
	return nil
}

// ListOTSafetyImports -- GET /api/ot-safety-imports.
func (h *Handler) ListOTSafetyImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListOTSafetyImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*otsafety.OTSafetyImport{}
	}
	respond(w, imports)
}

// GetOTSafetyImport -- GET /api/ot-safety-imports/{id}.
func (h *Handler) GetOTSafetyImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetOTSafetyImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "ot safety import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
