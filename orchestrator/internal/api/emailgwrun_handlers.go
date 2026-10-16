package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

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

// EmailGWScenarioSummary is one scenario ID's own real run history
// within a summarized set: how many times it has actually run, broken
// down by outcome, and what its most recent real run's outcome was --
// "what did this scenario do last time it actually ran", never a
// declared or assumed state.
type EmailGWScenarioSummary struct {
	ScenarioID      string            `json:"scenarioId"`
	RunCount        int               `json:"runCount"`
	ByStatus        map[string]int    `json:"byStatus"`
	LatestRunID     string            `json:"latestRunId"`
	LatestStatus    emailgwrun.Status `json:"latestStatus"`
	LatestStartedAt time.Time         `json:"latestStartedAt"`
}

// EmailGWRunsSummary is a compute-on-read aggregation over already-
// persisted email_gw_runs rows -- recomputed fresh on every request,
// never a separately persisted or scheduled snapshot, same
// "dashboards are pure presentation over real data" posture as
// cloudrun's own cloudCampaignRollup. Deliberately excludes MTTD/MTTR:
// this initiative has zero real customer run history yet (every run
// so far is this session's own test data), and a mean computed over
// that would be decorative, not real -- held for a later pass once
// there is enough real run volume to average meaningfully.
type EmailGWRunsSummary struct {
	Total     int                      `json:"total"`
	ByStatus  map[string]int           `json:"byStatus"`
	Scenarios []EmailGWScenarioSummary `json:"scenarios"`
}

// buildEmailGWRunsSummary aggregates runs -- the caller decides how
// much history that is (see GetEmailGWRunsSummary's own limit). Scenario
// order in the result is first-seen order within runs, which
// ListEmailGWRuns itself returns newest-first, so the most recently
// active scenarios surface first without an extra sort.
func buildEmailGWRunsSummary(runs []*emailgwrun.EmailGWRun) EmailGWRunsSummary {
	summary := EmailGWRunsSummary{ByStatus: map[string]int{}}
	byScenario := make(map[string]*EmailGWScenarioSummary)
	var order []string

	for _, run := range runs {
		summary.Total++
		summary.ByStatus[string(run.Status)]++

		sc, ok := byScenario[run.ScenarioID]
		if !ok {
			sc = &EmailGWScenarioSummary{ScenarioID: run.ScenarioID, ByStatus: map[string]int{}}
			byScenario[run.ScenarioID] = sc
			order = append(order, run.ScenarioID)
		}
		sc.RunCount++
		sc.ByStatus[string(run.Status)]++
		if run.StartedAt.After(sc.LatestStartedAt) {
			sc.LatestStartedAt = run.StartedAt
			sc.LatestStatus = run.Status
			sc.LatestRunID = run.ID
		}
	}

	summary.Scenarios = make([]EmailGWScenarioSummary, 0, len(order))
	for _, id := range order {
		summary.Scenarios = append(summary.Scenarios, *byScenario[id])
	}
	return summary
}

// GET /api/emailgw-runs/summary -- same baseline-only gate as
// ListEmailGWRuns/GetEmailGWRun. Registered ahead of
// /api/emailgw-runs/{id} in routes.go; chi's router matches a static
// segment over a named param at the same path depth regardless of
// registration order, but TestEmailGWRunsSummaryRoute_ResolvesToSummaryNotID
// checks this directly rather than relying on that alone. limit here
// defaults far higher than ListEmailGWRuns' own default (20): a
// summary is only honest over as much real history as it actually
// covers.
func (h *Handler) GetEmailGWRunsSummary(w http.ResponseWriter, r *http.Request) {
	limit := 1000
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 5000 {
		limit = l
	}
	runs, err := db.ListEmailGWRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, buildEmailGWRunsSummary(runs))
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
