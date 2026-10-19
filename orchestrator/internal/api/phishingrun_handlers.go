package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/phishingrun"
)

// POST /api/phishing-runs -- starts one real, registered phishing
// scenario run (see LookupPhishingRunExecutor's own doc comment for
// what "registered" means). Mirrors TriggerEmailGWRun's own shape:
// InitiatedBy is never trusted from the request body.
func (h *Handler) TriggerPhishingRun(w http.ResponseWriter, r *http.Request) {
	var req PhishingRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ScenarioID == "" {
		jsonError(w, "scenarioId required", http.StatusBadRequest)
		return
	}
	// Refuse before any run row exists. A stale or crafted request cannot start a
	// scenario whose dependency is not wired here, whatever the library showed.
	capability, err := h.phishingScenarioCapability(req.ScenarioID)
	if err != nil {
		jsonError(w, "phishing catalog unavailable", http.StatusInternalServerError)
		return
	}
	// Unregistered scenarios keep the existing 400 from ExecutePhishingRun.
	if capability.Status != CapAvailable && capability.Status != CapExperimental && capability.Status != CapCatalogOnly {
		jsonError(w, "scenario unavailable on this installation: "+capability.Reason, http.StatusConflict)
		return
	}

	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		req.InitiatedBy = c.UserID
	}

	env := h.phishingRunEnv()
	run, err := ExecutePhishingRun(r.Context(), h.db, env, req)
	if err != nil {
		failedRunID := ""
		if run != nil {
			failedRunID = run.ID
		}
		h.auditLog(r, "phishingrun.trigger", failedRunID, map[string]any{
			"scenarioId": req.ScenarioID, "error": err.Error(),
		}, "error")
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.auditLog(r, "phishingrun.trigger", run.ID, map[string]any{
		"scenarioId": req.ScenarioID, "status": string(run.Status),
	}, "ok")
	respondStatus(w, run, http.StatusCreated)
}

// GET /api/phishing-runs -- lists phishing runs, most recent first.
// Baseline-auth only, matching ListEmailGWRuns' own precedent.
func (h *Handler) ListPhishingRuns(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	runs, err := db.ListPhishingRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []*phishingrun.PhishingRun{}
	}
	respond(w, runs)
}

// GET /api/phishing-runs/{id} -- same baseline-only gate as ListPhishingRuns.
func (h *Handler) GetPhishingRun(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetPhishingRun(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "phishing run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, run)
}
