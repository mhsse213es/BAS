package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
)

// RecordKillChainProof stores one scenario's coverage proof. A proof is refused
// unless the scenario is in the catalog and each run reference is a completed
// run of the right mode for this scenario.
// POST /api/killchain/coverage/proofs (scenarios:run)
func (h *Handler) RecordKillChainProof(w http.ResponseWriter, r *http.Request) {
	store := h.killChainStore()
	if store == nil {
		jsonError(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		ScenarioID    string `json:"scenarioId"`
		Domain        string `json:"domain,omitempty"`
		Platform      string `json:"platform,omitempty"`
		Control       string `json:"control,omitempty"`
		Campaign      string `json:"campaign,omitempty"`
		Unsupported   bool   `json:"unsupported,omitempty"`
		FixtureTestID string `json:"fixtureTestId,omitempty"`
		AdapterTestID string `json:"adapterTestId,omitempty"`
		LabRunID      string `json:"labRunId,omitempty"`
		LiveRunID     string `json:"liveRunId,omitempty"`
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
	if req.ScenarioID == "" {
		jsonError(w, "scenarioId is required", http.StatusBadRequest)
		return
	}
	if h.engine == nil {
		jsonError(w, "scenario catalog unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, ok := h.engine.Get(req.ScenarioID); !ok {
		jsonError(w, "scenario is not in the catalog; only catalogued scenarios can carry proof", http.StatusBadRequest)
		return
	}
	if req.LabRunID != "" {
		if err := store.CheckRunRef(r.Context(), req.LabRunID, req.ScenarioID, "lab"); err != nil {
			jsonError(w, "lab proof refused: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.LiveRunID != "" {
		if err := store.CheckRunRef(r.Context(), req.LiveRunID, req.ScenarioID, "telemetry"); err != nil {
			jsonError(w, "live proof refused: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	recordedBy := ""
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		recordedBy = c.UserID
	}
	p := db.CoverageProof{
		ScenarioID: req.ScenarioID, Domain: req.Domain, Platform: req.Platform,
		Control: req.Control, Campaign: req.Campaign, Unsupported: req.Unsupported,
		Proof: killchain.Proof{
			CatalogEntry:  true,
			FixtureTestID: req.FixtureTestID,
			AdapterTestID: req.AdapterTestID,
			LabRunID:      req.LabRunID,
			LiveRunID:     req.LiveRunID,
		},
		RecordedBy: recordedBy,
	}
	if err := store.UpsertCoverageProof(r.Context(), p); err != nil {
		jsonError(w, "could not store proof: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "killchain.coverage.proof", req.ScenarioID, map[string]any{
		"level": p.Proof.Level().String(),
	}, "success")
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"scenarioId": req.ScenarioID, "level": p.Proof.Level().String()})
}

// GetKillChainCoverage reports coverage from stored proofs only. It has one
// table per dimension, per-level counts, and no combined percentage.
// GET /api/killchain/coverage
func (h *Handler) GetKillChainCoverage(w http.ResponseWriter, r *http.Request) {
	store := h.killChainStore()
	if store == nil {
		jsonError(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	rows, err := store.ListCoverageProofs(r.Context())
	if err != nil {
		jsonError(w, "could not load coverage", http.StatusInternalServerError)
		return
	}
	entries := make([]killchain.Entry, 0, len(rows))
	for _, p := range rows {
		entries = append(entries, killchain.Entry{
			ScenarioID: p.ScenarioID, Domain: p.Domain, Platform: p.Platform,
			Control: p.Control, Campaign: p.Campaign, Unsupported: p.Unsupported, Proof: p.Proof,
		})
	}
	jsonOK(w, map[string]any{"report": killchain.Build(entries), "entries": entries})
}
