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
	"github.com/audspect/bas/internal/emailgwrun"
)

// POST /api/emailgw-runs -- starts one real EmailGW scenario run
// (resolves the scenario id, sends the real test message, then waits
// out the dwell window in the background). Returns 503 when no
// provider/injection target is configured (WithEmailGWRun never
// called -- same "clearly unconfigured, not broken" precedent as
// GetCalderaAdversaries when CALDERA_URL is empty).
func (h *Handler) TriggerEmailGWRun(w http.ResponseWriter, r *http.Request) {
	if h.emailgwProvider == nil {
		jsonError(w, "EmailGW real-run execution is not configured on this deployment", http.StatusServiceUnavailable)
		return
	}

	var req EmailGWRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ScenarioID == "" {
		jsonError(w, "scenarioId required", http.StatusBadRequest)
		return
	}

	// InitiatedBy is never trusted from the request body -- always the
	// authenticated caller, matching TriggerCloudPlanRun's own convention.
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		req.InitiatedBy = c.UserID
	}

	run, err := ExecuteEmailGWRun(r.Context(), h.db, h.emailgwProvider, h.emailgwInjectionTarget, req)
	if err != nil {
		failedRunID := ""
		if run != nil {
			failedRunID = run.ID
		}
		h.auditLog(r, "emailgwrun.trigger", failedRunID, map[string]any{
			"scenarioId": req.ScenarioID, "error": err.Error(),
		}, "error")
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.auditLog(r, "emailgwrun.trigger", run.ID, map[string]any{
		"scenarioId": req.ScenarioID, "status": string(run.Status),
	}, "ok")
	respondStatus(w, run, http.StatusCreated)
}

// GET /api/emailgw-runs -- lists EmailGW runs, most recent first. Any
// authenticated user may read this, matching ListCloudRuns' own
// precedent -- only the trigger endpoint is permission-gated.
func (h *Handler) ListEmailGWRuns(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	runs, err := db.ListEmailGWRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []*emailgwrun.EmailGWRun{}
	}
	respond(w, runs)
}

// GET /api/emailgw-runs/{id} -- same baseline-only gate as ListEmailGWRuns.
func (h *Handler) GetEmailGWRun(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetEmailGWRun(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "email gw run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, run)
}
