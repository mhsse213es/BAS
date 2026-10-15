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
	"github.com/audspect/bas/internal/regobligation"
)

const maxRegulatoryObligationRequestBytes = 1 << 16

// CreateRegulatoryObligation -- POST /api/regulatory-obligations.
func (h *Handler) CreateRegulatoryObligation(w http.ResponseWriter, r *http.Request) {
	var req regobligation.Obligation
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRegulatoryObligationRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateObligation(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var createdBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		createdBy = c.UserID
	}
	req.ID = newID()
	req.CreatedBy = createdBy

	if err := db.InsertRegulatoryObligation(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "regobligation.create", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "regobligation.create", req.ID, map[string]any{"jurisdiction": req.Jurisdiction, "regulator": req.Regulator}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

// validateObligation enforces spec §3.1's required-field and
// ObligationType-enum discipline.
func validateObligation(ob *regobligation.Obligation) error {
	if ob.Jurisdiction == "" {
		return fmt.Errorf("jurisdiction is required")
	}
	if ob.Regulator == "" {
		return fmt.Errorf("regulator is required")
	}
	if ob.Title == "" {
		return fmt.Errorf("title is required")
	}
	if ob.SourceReference == "" {
		return fmt.Errorf("sourceReference is required")
	}
	if ob.EffectiveDate.IsZero() {
		return fmt.Errorf("effectiveDate is required")
	}
	if ob.Version == "" {
		return fmt.Errorf("version is required")
	}
	switch ob.ObligationType {
	case regobligation.ObligationMandatory, regobligation.ObligationGuidance, regobligation.ObligationContractual, regobligation.ObligationRecommended:
	default:
		return fmt.Errorf("obligationType must be one of mandatory, guidance, contractual, recommended — got %q", ob.ObligationType)
	}
	if len(ob.ControlMappings) == 0 {
		return fmt.Errorf("at least one controlMapping is required")
	}
	if len(ob.ControlMappings) > regobligation.MaxControlMappingsPerObligation {
		return fmt.Errorf("too many control mappings — got %d, max %d", len(ob.ControlMappings), regobligation.MaxControlMappingsPerObligation)
	}
	for i, cm := range ob.ControlMappings {
		if cm.ControlName == "" || cm.CapabilityName == "" {
			return fmt.Errorf("controlMappings[%d]: controlName and capabilityName are both required", i)
		}
	}
	return nil
}

// ListRegulatoryObligations -- GET /api/regulatory-obligations.
func (h *Handler) ListRegulatoryObligations(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	obligations, err := db.ListRegulatoryObligations(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if obligations == nil {
		obligations = []*regobligation.Obligation{}
	}
	respond(w, obligations)
}

// GetRegulatoryObligation -- GET /api/regulatory-obligations/{id}.
func (h *Handler) GetRegulatoryObligation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ob, err := db.GetRegulatoryObligation(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "regulatory obligation not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, ob)
}
