package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/campaign"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/go-chi/chi/v5"
)

// CreateCampaign launches one scenario across many agents. Each reachable agent
// gets a child run (campaign_id set) via dispatchRun; unavailable agents are
// recorded as skips so targets = dispatched + skipped reconciles.
// POST /api/campaigns
func (h *Handler) CreateCampaign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name            string                   `json:"name"`
		ScenarioID      string                   `json:"scenarioId"`
		AgentIDs        []string                 `json:"agentIds"`
		Mode            string                   `json:"mode"`
		ConfirmLive     bool                     `json:"confirmLive"`
		ConfirmLab      bool                     `json:"confirmLab"`
		Reason          string                   `json:"reason"`
		Techniques      []string                 `json:"techniques"`
		Abilities       []string                 `json:"abilities"`
		Steps           []int                    `json:"steps"`
		Checks          []string                 `json:"checks"`
		Notes           string                   `json:"notes"`
		Tags            []string                 `json:"tags"`
		ExecutionPolicy scenario.ExecutionPolicy `json:"executionPolicy,omitempty"`
		TargetType      string                   `json:"targetType"`
		GroupID         *int64                   `json:"groupId"`
		ExcludeAgentIDs []string                 `json:"excludeAgentIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.ScenarioID == "" {
		jsonError(w, "name and scenarioId are required", http.StatusBadRequest)
		return
	}
	// targetType defaults to "agents" -- every campaign created before this
	// field existed was, in fact, an explicit agent list, so an absent
	// targetType must behave exactly as it always has.
	targetType := req.TargetType
	if targetType == "" {
		targetType = "agents"
	}
	switch targetType {
	case "agents":
		if len(req.AgentIDs) == 0 {
			jsonError(w, "at least one agentId is required for agents targeting", http.StatusBadRequest)
			return
		}
	case "group":
		if req.GroupID == nil {
			jsonError(w, "groupId is required for group targeting", http.StatusBadRequest)
			return
		}
	case "all":
		// Admin-only: targeting the entire fleet is a materially bigger blast
		// radius than a group or an explicit list. The frontend hides this
		// option for non-Admins as a UX simplification -- this check is the
		// actual security boundary.
		claims, ok := auth.ClaimsFrom(r.Context())
		if !ok || !auth.HasPermission(claims.Role, auth.CanTargetAllAgents) {
			jsonError(w, "targeting all agents requires Administrator access", http.StatusForbidden)
			return
		}
	default:
		jsonError(w, "targetType must be agents, group, or all", http.StatusBadRequest)
		return
	}
	sc, ok := h.engine.Get(req.ScenarioID)
	if !ok {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	mode := req.Mode
	if mode == "" {
		mode = "posture"
	}
	if mode != "posture" && mode != "telemetry" && mode != "lab" {
		jsonError(w, "invalid mode — use posture | telemetry | lab", http.StatusBadRequest)
		return
	}

	// Live-execution guardrails — enforced once for the whole fan-out, mirroring
	// RunScenario. A campaign multiplies a live run across the fleet, so these
	// matter more here, not less: an un-gated lab campaign would ship real
	// payloads to every selected agent.
	live := mode == "telemetry" || mode == "lab"
	if live && !sc.Executable {
		jsonError(w, "scenario does not support live execution — run the campaign in posture mode", http.StatusBadRequest)
		return
	}
	if live && !req.ConfirmLive {
		jsonError(w, "live execution requires explicit acknowledgement (confirmLive=true) — it runs real techniques across every target", http.StatusBadRequest)
		return
	}
	if mode == "lab" && !req.ConfirmLab {
		jsonError(w, "lab mode is a second approval gate (confirmLab=true) — full-fidelity emulation must target an isolated AD range only", http.StatusBadRequest)
		return
	}
	if live && sc.LivePolicy != nil && sc.LivePolicy.ExecutionWindow != "" {
		ok, werr := withinWindow(sc.LivePolicy.ExecutionWindow, time.Now())
		if werr != nil {
			jsonError(w, "invalid execution_window in scenario policy: "+werr.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			jsonError(w, "outside the approved execution window ("+sc.LivePolicy.ExecutionWindow+") for live execution", http.StatusBadRequest)
			return
		}
	}

	// Resolve the target set for this targetType. "agents" uses the request's
	// explicit list unchanged; "group" resolves live membership right now
	// (reusing the Fleet Job Engine's already-tested recursive resolver, not
	// a second copy of the query); "all" is every non-retired agent. The
	// result becomes the frozen `targets` snapshot below -- from this point
	// on, later changes to group membership never retroactively affect this
	// campaign.
	var targetAgentIDs []string
	switch targetType {
	case "group":
		if h.jobsStore == nil {
			jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
			return
		}
		resolved, rerr := h.jobsStore.ResolveGroupAgentIDs(r.Context(), []int64{*req.GroupID})
		if rerr != nil {
			jsonError(w, rerr.Error(), http.StatusInternalServerError)
			return
		}
		targetAgentIDs = resolved
	case "all":
		rows, qerr := h.db.Query(r.Context(), `SELECT agent_id FROM agents WHERE COALESCE(state, 'active') != 'retired'`)
		if qerr != nil {
			jsonError(w, qerr.Error(), http.StatusInternalServerError)
			return
		}
		for rows.Next() {
			var aid string
			if rows.Scan(&aid) == nil {
				targetAgentIDs = append(targetAgentIDs, aid)
			}
		}
		rows.Close()
	default:
		targetAgentIDs = req.AgentIDs
	}
	if len(req.ExcludeAgentIDs) > 0 {
		excl := make(map[string]bool, len(req.ExcludeAgentIDs))
		for _, aid := range req.ExcludeAgentIDs {
			excl[aid] = true
		}
		filtered := make([]string, 0, len(targetAgentIDs))
		for _, aid := range targetAgentIDs {
			if !excl[aid] {
				filtered = append(filtered, aid)
			}
		}
		targetAgentIDs = filtered
	}
	if len(targetAgentIDs) == 0 {
		jsonError(w, "no targets resolved for this campaign", http.StatusBadRequest)
		return
	}

	var initiatedBy *string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = &c.UserID
	}

	id := newID()
	subset, _ := json.Marshal(map[string]any{
		"techniques": req.Techniques, "abilities": req.Abilities, "steps": req.Steps, "checks": req.Checks,
		"executionPolicy": req.ExecutionPolicy,
	})
	targets, _ := json.Marshal(targetAgentIDs)
	tags, _ := json.Marshal(req.Tags)
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO campaigns (id, name, scenario_id, scenario_name, mode, subset, reason, targets, notes, tags, created_by, target_type, target_group_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		id, req.Name, sc.ID, sc.Name, mode, subset, req.Reason, targets, req.Notes, tags, initiatedBy, targetType, req.GroupID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	opts := dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		CampaignID: id, InitiatedBy: initiatedBy, MaxPrivilege: req.ExecutionPolicy.MaxPrivilege,
	}
	skips := []map[string]string{}
	dispatched := 0
	for _, agentID := range targetAgentIDs {
		_, skip, err := h.dispatchRun(r.Context(), sc, agentID, opts)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if skip != "" {
			skips = append(skips, map[string]string{"agentId": agentID, "reason": skip})
		} else {
			dispatched++
		}
	}
	skipsJSON, _ := json.Marshal(skips)
	_, _ = h.db.Exec(r.Context(), `UPDATE campaigns SET skips=$1 WHERE id=$2`, skipsJSON, id)

	h.auditLog(r, "campaign.create", id, map[string]any{"name": req.Name, "scenarioId": req.ScenarioID, "agents": len(req.AgentIDs), "mode": mode, "dispatched": dispatched}, "ok")
	respond(w, map[string]any{"campaignId": id, "dispatched": dispatched, "skipped": len(skips)})
}

// campaignRow mirrors the stored campaign for JSON output and rollup.
type campaignRow struct {
	ID, Name, ScenarioID, ScenarioName, Mode, Reason, Notes, CreatedBy string
	Targets                                                            []string
	Skips                                                              []campaign.Skip
	Tags                                                               []string
	CreatedAt                                                          time.Time
	StartedAt                                                          time.Time
	Stopped                                                            bool
	TargetType                                                         string
	TargetGroupID                                                      *int64
}

// childRunOut is the per-agent breakdown row returned in a campaign's detail.
type childRunOut struct {
	RunID           string  `json:"runId"`
	AgentID         string  `json:"agentId"`
	Status          string  `json:"status"`
	PreventionScore float64 `json:"preventionScore"`
	Steps           int     `json:"steps"`
}

// loadChildren loads a campaign's child runs as campaign.ChildRun (for the
// rollup) plus a per-agent childRunOut slice (for the detail view), classifying
// each FAIL step as detected/missed using the run's persisted detection_summary.
func (h *Handler) loadChildren(ctx context.Context, campaignID string) ([]campaign.ChildRun, []childRunOut, error) {
	rows, err := h.db.Query(ctx,
		`SELECT id, agent_id, status, results, score, detection_summary
		   FROM scenario_runs WHERE campaign_id = $1 ORDER BY started_at`, campaignID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var cr []campaign.ChildRun
	out := []childRunOut{}
	for rows.Next() {
		var rid, agentID, status string
		var resultsRaw, scoreRaw, detRaw []byte
		if err := rows.Scan(&rid, &agentID, &status, &resultsRaw, &scoreRaw, &detRaw); err != nil {
			return nil, nil, err
		}
		var results []models.SimulationResult
		_ = json.Unmarshal(resultsRaw, &results)
		var score *models.Score
		if len(scoreRaw) > 0 {
			var s models.Score
			if json.Unmarshal(scoreRaw, &s) == nil {
				score = &s
			}
		}
		det := reporting.DetectedTechniques(detRaw, results)
		cr = append(cr, campaign.ChildRun{Status: status, Results: results, Score: score, DetectedTechs: det})
		var prevPct float64
		if score != nil {
			prevPct = score.PreventionScore
		}
		out = append(out, childRunOut{RunID: rid, AgentID: agentID, Status: status, PreventionScore: prevPct, Steps: len(results)})
	}
	return cr, out, rows.Err()
}

// loadCampaign reads one campaign row, decoding its jsonb columns.
func (h *Handler) loadCampaign(ctx context.Context, id string) (*campaignRow, error) {
	var c campaignRow
	var targetsRaw, skipsRaw, tagsRaw []byte
	var stoppedAt *time.Time
	err := h.db.QueryRow(ctx,
		`SELECT id, name, scenario_id, scenario_name, mode, reason, notes,
		        COALESCE(created_by,''), targets, skips, tags, created_at, started_at, stopped_at,
		        target_type, target_group_id
		   FROM campaigns WHERE id=$1`, id,
	).Scan(&c.ID, &c.Name, &c.ScenarioID, &c.ScenarioName, &c.Mode, &c.Reason, &c.Notes,
		&c.CreatedBy, &targetsRaw, &skipsRaw, &tagsRaw, &c.CreatedAt, &c.StartedAt, &stoppedAt,
		&c.TargetType, &c.TargetGroupID)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(targetsRaw, &c.Targets)
	_ = json.Unmarshal(skipsRaw, &c.Skips)
	_ = json.Unmarshal(tagsRaw, &c.Tags)
	c.Stopped = stoppedAt != nil
	return &c, nil
}

// summaryFor builds the compute-on-read rollup for a campaign and lazily stamps
// completed_at the first time the campaign reads as terminal (and not stopped).
func (h *Handler) summaryFor(ctx context.Context, c *campaignRow) (campaign.Summary, []childRunOut, error) {
	children, out, err := h.loadChildren(ctx, c.ID)
	if err != nil {
		return campaign.Summary{}, nil, err
	}
	s := campaign.Aggregate(children, c.Skips)
	s.Status = campaign.DeriveStatus(children, len(c.Skips), c.Stopped)
	if !c.Stopped && (s.Status == "completed" || s.Status == "partial" || s.Status == "failed") {
		_, _ = h.db.Exec(ctx, `UPDATE campaigns SET completed_at=NOW() WHERE id=$1 AND completed_at IS NULL`, c.ID)
	}
	return s, out, nil
}

// ListCampaigns returns every campaign with its live rollup. GET /api/campaigns
func (h *Handler) ListCampaigns(w http.ResponseWriter, r *http.Request) {
	rollups, err := campaign.ListWithRollups(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rollups))
	for _, c := range rollups {
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "scenarioId": c.ScenarioID, "scenarioName": c.ScenarioName,
			"mode": c.Mode, "createdBy": c.CreatedBy, "startedAt": c.StartedAt, "summary": c.Summary,
			"targetType": c.TargetType, "targetGroupId": c.TargetGroupID,
		})
	}
	respond(w, out)
}

// CampaignSummary returns just the rollup. GET /api/campaigns/{id}/summary
func (h *Handler) CampaignSummary(w http.ResponseWriter, r *http.Request) {
	c, err := h.loadCampaign(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "campaign not found", http.StatusNotFound)
		return
	}
	s, _, err := h.summaryFor(r.Context(), c)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, s)
}

// GET /api/campaigns/{id}/report
// Fleet-wide HTML assessment report for a campaign (aggregates all child runs).
func (h *Handler) GetCampaignReport(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	filter := r.URL.Query().Get("filter")
	rep, err := h.reportingEngine.BuildFromCampaign(r.Context(), chi.URLParam(r, "id"), filter)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	h.auditLog(r, "report.export", chi.URLParam(r, "id"), map[string]any{"format": "html", "type": "campaign"}, "ok")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := reporting.GenerateHTML(w, rep, nil); err != nil {
		log.Printf("[api] campaign report html: %v", err)
	}
}

// GET /api/campaigns/{id}/pdf — fleet-wide PDF report.
// Detailed per-technique results are omitted (they live in the per-run reports
// and the campaign forensic CSV); the campaign PDF is the fleet rollup + per-agent
// breakdown.
func (h *Handler) GetCampaignPDF(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	filter := r.URL.Query().Get("filter")
	rep, err := h.reportingEngine.BuildFromCampaign(r.Context(), chi.URLParam(r, "id"), filter)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	filterSuffix := ""
	if filter != "" && filter != "all" {
		filterSuffix = "-" + filter
	}
	fname := fmt.Sprintf("bas-campaign-%s-%s%s-%s.pdf", sanitizeFilename(rep.Agent.Hostname), sanitizeFilename(rep.ScenarioName), filterSuffix, time.Now().UTC().Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	h.auditLog(r, "report.export", chi.URLParam(r, "id"), map[string]any{"format": "pdf", "type": "campaign"}, "ok")
	if err := h.reportingEngine.PDFFromReport(r.Context(), w, rep, nil, nil); err != nil {
		log.Printf("[api] campaign report pdf: %v", err)
	}
}

// GET /api/campaigns/{id}/forensic.csv — one row per technique result across all
// the campaign's child runs (the fleet evidence layer).
func (h *Handler) GetCampaignCSV(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	filter := r.URL.Query().Get("filter")
	var campName, scenarioName string
	if err := h.db.QueryRow(r.Context(),
		`SELECT name, scenario_name FROM campaigns WHERE id = $1`, id,
	).Scan(&campName, &scenarioName); err != nil {
		jsonError(w, "campaign not found", http.StatusNotFound)
		return
	}
	rows, err := h.db.Query(r.Context(),
		`SELECT results FROM scenario_runs WHERE campaign_id = $1 ORDER BY started_at`, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var all []models.SimulationResult
	totalCount := 0
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			continue
		}
		if len(raw) > 0 {
			var rs []models.SimulationResult
			if json.Unmarshal(raw, &rs) == nil {
				totalCount += len(rs)
				all = append(all, reporting.FilterResults(rs, filter)...)
			}
		}
	}
	filterSuffix := ""
	if filter != "" && filter != "all" {
		filterSuffix = "-" + filter
	}
	fname := fmt.Sprintf("bas-campaign-forensic-%s-%s%s-%s.csv", sanitizeFilename(campName), sanitizeFilename(scenarioName), filterSuffix, time.Now().UTC().Format("2006-01-02"))
	h.auditLog(r, "report.export", id, map[string]any{"format": "csv", "type": "campaign", "filter": filter}, "ok")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	reporting.WriteForensicCSV(w, scenarioName, all, filter, totalCount)
}

// GetCampaign returns a campaign with its rollup and per-agent breakdown.
// GET /api/campaigns/{id}
func (h *Handler) GetCampaign(w http.ResponseWriter, r *http.Request) {
	c, err := h.loadCampaign(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "campaign not found", http.StatusNotFound)
		return
	}
	s, children, err := h.summaryFor(r.Context(), c)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{
		"id": c.ID, "name": c.Name, "scenarioId": c.ScenarioID, "scenarioName": c.ScenarioName,
		"mode": c.Mode, "reason": c.Reason, "notes": c.Notes, "tags": c.Tags,
		"targets": c.Targets, "skips": c.Skips, "createdBy": c.CreatedBy,
		"startedAt": c.StartedAt, "summary": s, "runs": children,
		"targetType": c.TargetType, "targetGroupId": c.TargetGroupID,
	})
}

// StopCampaign marks a campaign stopped and cancels its still-running children.
// POST /api/campaigns/{id}/stop
func (h *Handler) StopCampaign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `UPDATE campaigns SET stopped_at=NOW() WHERE id=$1 AND stopped_at IS NULL`, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		// already stopped or not found — distinguish the two.
		if _, e := h.loadCampaign(r.Context(), id); e != nil {
			jsonError(w, "campaign not found", http.StatusNotFound)
			return
		}
	}
	// Cancel still-running children the same way CancelRun does: send each
	// agent a command_cancel so it actually stops executing, rather than just
	// relabeling the DB row while the agent keeps running in the background
	// unaware — a late "completed" submission from an agent that was never
	// told to stop would otherwise heal the row back past this cancellation
	// (SubmitScenarioResult's REPLACE has no status guard by design, for the
	// separate case of an agent reconnecting after a staleness false-flip).
	// Only agents that are unreachable get the immediate DB fallback, since
	// they will never submit a result to reconcile the status themselves.
	rows, _ := h.db.Query(r.Context(),
		`SELECT id, agent_id FROM scenario_runs WHERE campaign_id=$1 AND status='running'`, id)
	type runRef struct{ id, agentID string }
	var runs []runRef
	for rows != nil && rows.Next() {
		var rr runRef
		if rows.Scan(&rr.id, &rr.agentID) == nil {
			runs = append(runs, rr)
		}
	}
	if rows != nil {
		rows.Close()
	}
	for _, rr := range runs {
		sent := h.hub.SendToAgent(rr.agentID, models.WSMessage{
			Type:    models.MsgCommandCancel,
			AgentID: rr.agentID,
			Data:    map[string]string{"runId": rr.id},
		})
		if !sent {
			_, _ = h.db.Exec(r.Context(),
				`UPDATE scenario_runs SET status='partial', completed_at=NOW() WHERE id=$1 AND status='running'`, rr.id)
		}
	}
	h.auditLog(r, "campaign.stop", id, map[string]any{"cancelledRuns": len(runs)}, "ok")
	respond(w, map[string]any{"stopped": true, "cancelled": len(runs)})
}
