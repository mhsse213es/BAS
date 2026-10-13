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
	"github.com/audspect/bas/internal/cloudgraph"
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

const (
	maxCloudCampaignAccounts = 25
	maxEdgesPerAccount       = 500
)

// cloudCampaignAccountResult is one account's outcome within a campaign
// response. Status is always run.Status verbatim when a row exists --
// never invented from err != nil, since UpdateCloudRunStatus's own
// failure can leave a row honestly sitting at "running", not "failed".
type cloudCampaignAccountResult struct {
	Account cloudgraph.AccountScope `json:"account"`
	RunID   string                  `json:"runId,omitempty"`
	Status  string                  `json:"status,omitempty"`
	Error   string                  `json:"error,omitempty"`
}

// bucketCloudRunStatus folds one account's (run, err) outcome into the
// campaign rollup's three buckets. A run's own real status
// (completed/partial/failed) is used directly; a non-terminal status
// (running/pending -- the UpdateCloudRunStatus-failure edge case) and a
// nil run (the InsertCloudRun-failure edge case) both fold into "failed"
// for rollup purposes only -- the per-account result's own Status field
// is set separately, from run.Status verbatim, never overwritten here.
func bucketCloudRunStatus(run *cloudrun.CloudRun) (bucket string) {
	if run == nil {
		return "failed"
	}
	switch run.Status {
	case cloudrun.StatusCompleted:
		return "completed"
	case cloudrun.StatusPartial:
		return "partial"
	case cloudrun.StatusFailed:
		return "failed"
	default: // StatusRunning, StatusPending -- never confirmed terminal
		return "failed"
	}
}

// POST /api/cloud-campaigns -- fans db.ExecuteCloudPlanRun out across every
// sub-request in runs, sequentially (CloudPlan has no I/O today -- see the
// design spec's Decision 3). Synchronous: every child evaluation finishes
// before this handler returns.
func (h *Handler) CreateCloudCampaign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string                   `json:"name"`
		Runs []db.CloudPlanRunRequest `json:"runs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name required", http.StatusBadRequest)
		return
	}
	if len(req.Runs) == 0 {
		jsonError(w, "at least one run is required", http.StatusBadRequest)
		return
	}
	if len(req.Runs) > maxCloudCampaignAccounts {
		jsonError(w, fmt.Sprintf("too many accounts — got %d, max %d", len(req.Runs), maxCloudCampaignAccounts), http.StatusBadRequest)
		return
	}
	for i, run := range req.Runs {
		if err := validateCloudPlanRunRequest(run); err != nil {
			jsonError(w, fmt.Sprintf("runs[%d]: %s", i, err.Error()), http.StatusBadRequest)
			return
		}
		if len(run.Edges) > maxEdgesPerAccount {
			jsonError(w, fmt.Sprintf("runs[%d]: too many edges — got %d, max %d", i, len(run.Edges), maxEdgesPerAccount), http.StatusBadRequest)
			return
		}
	}

	var initiatedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = c.UserID
	}

	campaign := &db.CloudCampaign{ID: newID(), Name: req.Name, CreatedBy: initiatedBy}
	if err := db.InsertCloudCampaign(r.Context(), h.db, campaign); err != nil {
		h.auditLog(r, "cloudcampaign.create", "", map[string]any{"name": req.Name, "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	results := make([]cloudCampaignAccountResult, len(req.Runs))
	var total, completed, partial, failed int
	for i, subReq := range req.Runs {
		subReq.InitiatedBy = initiatedBy
		subReq.CampaignID = campaign.ID
		run, err := db.ExecuteCloudPlanRun(r.Context(), h.db, subReq)

		res := cloudCampaignAccountResult{Account: subReq.Account}
		if run != nil {
			res.RunID = run.ID
			res.Status = string(run.Status)
		}
		if err != nil {
			res.Error = err.Error()
		}
		results[i] = res

		total++
		switch bucketCloudRunStatus(run) {
		case "completed":
			completed++
		case "partial":
			partial++
		default:
			failed++
		}
	}

	h.auditLog(r, "cloudcampaign.create", campaign.ID, map[string]any{
		"name": req.Name, "total": total, "completed": completed, "partial": partial, "failed": failed,
	}, "ok")
	respondStatus(w, map[string]any{
		"campaignId": campaign.ID,
		"name":       campaign.Name,
		"summary":    map[string]any{"total": total, "completed": completed, "partial": partial, "failed": failed},
		"results":    results,
	}, http.StatusCreated)
}
