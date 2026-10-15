package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/regobligation"
)

const maxEvidenceSnapshotRequestBytes = 1 << 16

// CreateEvidenceSnapshot -- POST /api/regulatory-evidence-snapshots.
// Unlike every other Create* handler in this codebase, this one is not
// a simple decode-validate-insert: it looks up the referenced
// Obligation and cross-checks the submitted controlMappingId/
// capabilityName against that obligation's own declared control
// mappings (spec §3.2) before persisting. It calls no other package's
// composition logic -- the caller has already run the real check
// elsewhere and is submitting its output for recording.
func (h *Handler) CreateEvidenceSnapshot(w http.ResponseWriter, r *http.Request) {
	var req regobligation.EvidenceSnapshot
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEvidenceSnapshotRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.ObligationID == "" {
		jsonError(w, "obligationId is required", http.StatusBadRequest)
		return
	}
	obligation, err := db.GetRegulatoryObligation(r.Context(), h.db, req.ObligationID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "regulatory obligation not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var matched *regobligation.ControlMapping
	for i := range obligation.ControlMappings {
		if obligation.ControlMappings[i].CanonicalID == req.ControlMappingID {
			matched = &obligation.ControlMappings[i]
			break
		}
	}
	if matched == nil {
		jsonError(w, "controlMappingId does not match any control mapping on this obligation", http.StatusBadRequest)
		return
	}
	if req.CapabilityName != matched.CapabilityName {
		jsonError(w, "capabilityName does not match the referenced control mapping's capabilityName", http.StatusBadRequest)
		return
	}

	switch req.Status {
	case regobligation.SnapshotCaptured:
		if req.CapturedOutcome == "" {
			jsonError(w, "capturedOutcome is required when status is captured", http.StatusBadRequest)
			return
		}
	case regobligation.SnapshotIncomplete:
		if req.IncompleteReason == "" {
			jsonError(w, "incompleteReason is required when status is incomplete", http.StatusBadRequest)
			return
		}
	default:
		jsonError(w, fmt.Sprintf("status must be %q or %q — got %q", regobligation.SnapshotCaptured, regobligation.SnapshotIncomplete, req.Status), http.StatusBadRequest)
		return
	}

	var capturedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		capturedBy = c.UserID
	}
	// Server-assigned -- proven by TestCreateEvidenceSnapshot_ServerAssignedFields_OverwriteCallerValues
	// to overwrite whatever the caller sent for these three fields.
	req.ID = newID()
	req.SchemaVersion = regobligation.CurrentSnapshotSchemaVersion
	req.ObligationVersion = obligation.Version
	req.CapturedBy = capturedBy
	req.CapturedAt = time.Now().UTC()

	if err := db.InsertEvidenceSnapshot(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "regevidence.create", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "regevidence.create", req.ID, map[string]any{"obligationId": req.ObligationID, "status": string(req.Status)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

// ListEvidenceSnapshots -- GET /api/regulatory-evidence-snapshots?obligationId={id}.
func (h *Handler) ListEvidenceSnapshots(w http.ResponseWriter, r *http.Request) {
	obligationID := r.URL.Query().Get("obligationId")
	if obligationID == "" {
		jsonError(w, "obligationId query parameter is required", http.StatusBadRequest)
		return
	}
	snapshots, err := db.ListEvidenceSnapshotsByObligation(r.Context(), h.db, obligationID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if snapshots == nil {
		snapshots = []*regobligation.EvidenceSnapshot{}
	}
	respond(w, snapshots)
}

// GetEvidenceSnapshot -- GET /api/regulatory-evidence-snapshots/{id}.
func (h *Handler) GetEvidenceSnapshot(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	es, err := db.GetEvidenceSnapshot(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "evidence snapshot not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, es)
}
