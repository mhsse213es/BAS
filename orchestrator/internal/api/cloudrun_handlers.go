package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudrun"
	"github.com/audspect/bas/internal/db"
)

// validateCloudPlanRunRequest checks the three required-field/provider
// constraints a single CloudPlanRunRequest must satisfy, shared by
// TriggerCloudPlanRun (one request) and CreateCloudCampaign (N requests,
// each checked the same way before any persistence).
func validateCloudPlanRunRequest(req db.CloudPlanRunRequest) error {
	if req.ScenarioID == "" {
		return errors.New("scenarioId required")
	}
	if req.Target == "" {
		return errors.New("target required")
	}
	switch req.Account.Provider {
	case "aws", "azure", "gcp":
		return nil
	default:
		return errors.New("invalid provider — use aws | azure | gcp")
	}
}

// POST /api/cloud-runs — runs cloudgraph.CloudPlan for one account against a
// caller-supplied permission graph and persists the outcome as a cloud_runs
// row. Synchronous: CloudPlan has no I/O today, so there is nothing to poll.
func (h *Handler) TriggerCloudPlanRun(w http.ResponseWriter, r *http.Request) {
	var req db.CloudPlanRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateCloudPlanRunRequest(req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// InitiatedBy is never trusted from the request body -- always the
	// authenticated caller, matching RunScenario's own convention.
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		req.InitiatedBy = c.UserID
	}

	run, err := db.ExecuteCloudPlanRun(r.Context(), h.db, req)
	if err != nil {
		// run is non-nil whenever a row actually exists (it's always nil only
		// when InsertCloudRun itself never created one) -- use its ID for
		// audit correlation when available, "" otherwise.
		failedRunID := ""
		if run != nil {
			failedRunID = run.ID
		}
		h.auditLog(r, "cloudrun.plan.run", failedRunID, map[string]any{
			"scenarioId": req.ScenarioID, "provider": req.Account.Provider, "error": err.Error(),
		}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "cloudrun.plan.run", run.ID, map[string]any{
		"scenarioId": req.ScenarioID, "provider": req.Account.Provider, "status": string(run.Status),
	}, "ok")
	respondStatus(w, run, http.StatusCreated)
}

// GET /api/cloud-runs — lists cloud runs, most recent first. Any
// authenticated user may read this, matching ListScenarioRuns' own
// precedent -- only the trigger endpoint is permission-gated.
func (h *Handler) ListCloudRuns(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	runs, err := db.ListCloudRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []*cloudrun.CloudRun{}
	}
	respond(w, runs)
}

// GET /api/cloud-runs/{id} — same baseline-only gate as ListCloudRuns.
func (h *Handler) GetCloudRun(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetCloudRun(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "cloud run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, run)
}
