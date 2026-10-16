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
	"github.com/audspect/bas/internal/emailgwcampaign"
)

// TriggerEmailGWCampaignRequest is the input to TriggerEmailGWCampaign.
type TriggerEmailGWCampaignRequest struct {
	TemplateID string `json:"templateId"`
}

// POST /api/emailgw-campaigns -- starts one real multi-stage EmailGW
// campaign from a static template (see internal/emailgwcampaign).
// Same 503-when-unconfigured posture as TriggerEmailGWRun -- a
// campaign dispatches through the exact same ExecuteEmailGWRun path,
// so it is unconfigured under exactly the same conditions.
func (h *Handler) TriggerEmailGWCampaign(w http.ResponseWriter, r *http.Request) {
	if h.emailgwProvider == nil {
		jsonError(w, "EmailGW real-run execution is not configured on this deployment", http.StatusServiceUnavailable)
		return
	}

	var req TriggerEmailGWCampaignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.TemplateID == "" {
		jsonError(w, "templateId required", http.StatusBadRequest)
		return
	}

	initiatedBy := ""
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = c.UserID
	}

	campaign, err := TriggerEmailGWCampaign(r.Context(), h.db, h.emailgwProvider, h.emailgwInjectionTarget, h.emailgwEnvironment, req.TemplateID, initiatedBy)
	if err != nil {
		h.auditLog(r, "emailgwcampaign.trigger", "", map[string]any{
			"templateId": req.TemplateID, "error": err.Error(),
		}, "error")
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.auditLog(r, "emailgwcampaign.trigger", campaign.ID, map[string]any{
		"templateId": req.TemplateID, "status": string(campaign.Status),
	}, "ok")
	respondStatus(w, campaign, http.StatusCreated)
}

// GET /api/emailgw-campaigns -- lists campaigns, most recent first.
// Baseline-authenticated only, same as ListEmailGWRuns.
func (h *Handler) ListEmailGWCampaigns(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	campaigns, err := db.ListEmailGWCampaigns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if campaigns == nil {
		campaigns = []*emailgwcampaign.Campaign{}
	}
	respond(w, campaigns)
}

// EmailGWCampaignStageView is one stage's own full record for
// GetEmailGWCampaign's response, inlining its underlying run (when it
// has one) so a caller never has to make a second request to see the
// real evidence behind a "completed" stage. Run is nil for every
// blocked/cancelled stage and for a derived stage -- never populated
// with a fabricated or borrowed result.
type EmailGWCampaignStageView struct {
	*emailgwcampaign.CampaignStage
	Run any `json:"run,omitempty"`
}

// EmailGWCampaignRollup is a compute-on-read count of stage outcomes,
// same "dashboards are pure presentation over real data" posture as
// buildEmailGWRunsSummary -- never a separately persisted total, and
// never collapses a blocked/failed/cancelled stage into "completed".
type EmailGWCampaignRollup struct {
	TotalStages           int `json:"totalStages"`
	Completed             int `json:"completed"`
	Dispatched            int `json:"dispatched"`
	BlockedByPrerequisite int `json:"blockedByPrerequisite"`
	Failed                int `json:"failed"`
	Cancelled             int `json:"cancelled"`
}

// EmailGWCampaignView is GetEmailGWCampaign's full response.
type EmailGWCampaignView struct {
	*emailgwcampaign.Campaign
	Stages []EmailGWCampaignStageView `json:"stages"`
	Rollup EmailGWCampaignRollup      `json:"rollup"`
}

func buildEmailGWCampaignRollup(stages []*emailgwcampaign.CampaignStage) EmailGWCampaignRollup {
	r := EmailGWCampaignRollup{TotalStages: len(stages)}
	for _, s := range stages {
		switch s.Status {
		case emailgwcampaign.StageCompleted:
			r.Completed++
		case emailgwcampaign.StageDispatched:
			r.Dispatched++
		case emailgwcampaign.StageBlockedByPrerequisite:
			r.BlockedByPrerequisite++
		case emailgwcampaign.StageFailed:
			r.Failed++
		case emailgwcampaign.StageCancelled:
			r.Cancelled++
		}
	}
	return r
}

// GET /api/emailgw-campaigns/{id} -- the campaign plus every stage,
// each stage's own run inlined when it has one.
func (h *Handler) GetEmailGWCampaign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	campaign, err := db.GetEmailGWCampaign(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "email gw campaign not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stages, err := db.ListEmailGWCampaignStages(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	views := make([]EmailGWCampaignStageView, 0, len(stages))
	for _, s := range stages {
		v := EmailGWCampaignStageView{CampaignStage: s}
		if s.RunID != nil {
			if run, err := db.GetEmailGWRun(r.Context(), h.db, *s.RunID); err == nil {
				v.Run = run
			}
		}
		views = append(views, v)
	}

	respond(w, EmailGWCampaignView{Campaign: campaign, Stages: views, Rollup: buildEmailGWCampaignRollup(stages)})
}

// POST /api/emailgw-campaigns/{id}/cancel -- requests cancellation;
// see CancelEmailGWCampaign's own doc comment for the best-effort
// semantics (never retroactive on an already-dispatched stage).
func (h *Handler) CancelEmailGWCampaignHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := db.GetEmailGWCampaign(r.Context(), h.db, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "email gw campaign not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := CancelEmailGWCampaign(r.Context(), h.db, id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "emailgwcampaign.cancel", id, nil, "ok")
	campaign, err := db.GetEmailGWCampaign(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, campaign)
}
