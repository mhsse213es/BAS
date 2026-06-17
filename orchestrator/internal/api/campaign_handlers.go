package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/campaign"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/go-chi/chi/v5"
)

// CreateCampaign launches one scenario across many agents. Each reachable agent
// gets a child run (campaign_id set) via dispatchRun; unavailable agents are
// recorded as skips so targets = dispatched + skipped reconciles.
// POST /api/campaigns
func (h *Handler) CreateCampaign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		ScenarioID  string   `json:"scenarioId"`
		AgentIDs    []string `json:"agentIds"`
		Mode        string   `json:"mode"`
		ConfirmLive bool     `json:"confirmLive"`
		ConfirmLab  bool     `json:"confirmLab"`
		Reason      string   `json:"reason"`
		Techniques  []string `json:"techniques"`
		Abilities   []string `json:"abilities"`
		Steps       []int    `json:"steps"`
		Checks      []string `json:"checks"`
		Notes       string   `json:"notes"`
		Tags        []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.ScenarioID == "" || len(req.AgentIDs) == 0 {
		jsonError(w, "name, scenarioId and at least one agentId are required", http.StatusBadRequest)
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

	var initiatedBy *string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = &c.UserID
	}

	id := newID()
	subset, _ := json.Marshal(map[string]any{
		"techniques": req.Techniques, "abilities": req.Abilities, "steps": req.Steps, "checks": req.Checks,
	})
	targets, _ := json.Marshal(req.AgentIDs)
	tags, _ := json.Marshal(req.Tags)
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO campaigns (id, name, scenario_id, scenario_name, mode, subset, reason, targets, notes, tags, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		id, req.Name, sc.ID, sc.Name, mode, subset, req.Reason, targets, req.Notes, tags, initiatedBy); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	opts := dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		CampaignID: id, InitiatedBy: initiatedBy,
	}
	skips := []map[string]string{}
	dispatched := 0
	for _, agentID := range req.AgentIDs {
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

	respond(w, map[string]any{"campaignId": id, "dispatched": dispatched, "skipped": len(skips)})
}

// campaignRow mirrors the stored campaign for JSON output and rollup.
type campaignRow struct {
	ID, Name, ScenarioID, ScenarioName, Mode, Reason, Notes, CreatedBy string
	Targets   []string
	Skips     []campaign.Skip
	Tags      []string
	CreatedAt time.Time
	StartedAt time.Time
	Stopped   bool
}

// childRunOut is the per-agent breakdown row returned in a campaign's detail.
type childRunOut struct {
	RunID           string  `json:"runId"`
	AgentID         string  `json:"agentId"`
	Status          string  `json:"status"`
	PreventionScore float64 `json:"preventionScore"`
	Steps           int     `json:"steps"`
}

// detectedTechs returns the set of technique ids whose FAIL was detected, from
// the run's persisted detection_summary.techniques (the agent's post-run alert
// sweep), falling back to the coarse per-step event classifier when no sweep was
// submitted. This mirrors how reporting.buildKillChain decides detected vs missed.
func detectedTechs(detRaw []byte, results []models.SimulationResult) map[string]bool {
	out := map[string]bool{}
	if len(detRaw) > 0 {
		var ds struct {
			Techniques []struct {
				TechniqueID string `json:"techniqueId"`
				Verdict     string `json:"verdict"`
			} `json:"techniques"`
		}
		if json.Unmarshal(detRaw, &ds) == nil {
			for _, t := range ds.Techniques {
				if t.Verdict == "detected" {
					out[t.TechniqueID] = true
				}
			}
		}
	}
	for _, res := range results {
		if res.Result == models.ResultFail && !out[res.Technique.ID] {
			if reporting.ClassifyDetectionStatus(res.Events) == "Detected" {
				out[res.Technique.ID] = true
			}
		}
	}
	return out
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
		det := detectedTechs(detRaw, results)
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
		        COALESCE(created_by,''), targets, skips, tags, created_at, started_at, stopped_at
		   FROM campaigns WHERE id=$1`, id,
	).Scan(&c.ID, &c.Name, &c.ScenarioID, &c.ScenarioName, &c.Mode, &c.Reason, &c.Notes,
		&c.CreatedBy, &targetsRaw, &skipsRaw, &tagsRaw, &c.CreatedAt, &c.StartedAt, &stoppedAt)
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
	rows, err := h.db.Query(r.Context(), `SELECT id FROM campaigns ORDER BY started_at DESC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	out := []map[string]any{}
	for _, id := range ids {
		c, err := h.loadCampaign(r.Context(), id)
		if err != nil {
			continue
		}
		s, _, _ := h.summaryFor(r.Context(), c)
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "scenarioName": c.ScenarioName, "mode": c.Mode,
			"startedAt": c.StartedAt, "summary": s,
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
	})
}

// StopCampaign marks a campaign stopped and frees its still-running children as
// 'partial' (their executed steps stand). POST /api/campaigns/{id}/stop
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
	// Free still-running children (best-effort), mirroring the staleness monitor:
	// their executed steps stand, so they become 'partial' rather than 'failed'.
	rows, _ := h.db.Query(r.Context(),
		`SELECT id FROM scenario_runs WHERE campaign_id=$1 AND status='running'`, id)
	var runIDs []string
	for rows != nil && rows.Next() {
		var rid string
		if rows.Scan(&rid) == nil {
			runIDs = append(runIDs, rid)
		}
	}
	if rows != nil {
		rows.Close()
	}
	for _, rid := range runIDs {
		_, _ = h.db.Exec(r.Context(),
			`UPDATE scenario_runs SET status='partial', completed_at=NOW() WHERE id=$1 AND status='running'`, rid)
	}
	respond(w, map[string]any{"stopped": true, "cancelled": len(runIDs)})
}
