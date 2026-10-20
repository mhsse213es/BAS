package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
)

// RecordKillChainGroundTruth stores an independent record of whether a run's
// steps executed. The source must name the host or sensor that observed it.
// The scenario run record is refused.
// POST /api/killchain/runs/{runId}/ground-truth (scenarios:run)
func (h *Handler) RecordKillChainGroundTruth(w http.ResponseWriter, r *http.Request) {
	store := h.killChainStore()
	if store == nil {
		jsonError(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		Source    string `json:"source"`
		Executed  string `json:"executed"`
		Reference string `json:"reference"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		jsonError(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		jsonError(w, "invalid JSON body: unexpected data after the object", http.StatusBadRequest)
		return
	}
	recordedBy := ""
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		recordedBy = c.UserID
	}
	runID := chi.URLParam(r, "runId")
	rec := db.GroundTruthRecord{
		RunID:      runID,
		Source:     req.Source,
		Executed:   killchain.Tri(req.Executed),
		Reference:  req.Reference,
		RecordedBy: recordedBy,
	}
	if err := store.PutGroundTruth(r.Context(), rec); err != nil {
		jsonError(w, "ground truth refused: "+err.Error(), http.StatusBadRequest)
		return
	}
	h.auditLog(r, "killchain.ground_truth.record", runID, map[string]any{
		"source": req.Source, "executed": req.Executed,
	}, "success")
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"runId": runID, "executed": req.Executed})
}
