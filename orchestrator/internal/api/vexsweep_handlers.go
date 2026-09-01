package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/vexsweep"
)

// POST /api/vex/sweeps
// Creates a new Full Variant Sweep. Techniques are resolved server-side --
// every eligible ART technique, followed by every eligible Caldera ability
// -- and never trusts a client-submitted list. Rejects (409) if the agent
// already has a running sweep, or a running ad-hoc variant run (the two
// directions of the same-agent conflict rule; see design spec
// Architecture §3).
func (h *Handler) CreateVexSweep(w http.ResponseWriter, r *http.Request) {
	if h.vexSweep == nil {
		jsonError(w, "vex sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		AgentID         string `json:"agentId"`
		Mode            string `json:"mode"`
		IncludeAdvanced bool   `json:"includeAdvanced"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.AgentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	if h.artStore == nil {
		jsonError(w, "ART content not loaded", http.StatusServiceUnavailable)
		return
	}
	mode := coalesce(req.Mode, "sequential")
	ctx := r.Context()

	var runningVariantRunID string
	if err := h.db.QueryRow(ctx,
		`SELECT id FROM variant_runs WHERE agent_id = $1 AND status = 'running' LIMIT 1`, req.AgentID,
	).Scan(&runningVariantRunID); err == nil {
		jsonError(w, "agent has an active variant run — stop it before starting a sweep", http.StatusConflict)
		return
	}

	metas := h.artStore.ListTechniqueMeta()
	techniques := make([]string, 0, len(metas))
	counts := make([]int, 0, len(metas))
	baseTypes := make([]string, 0, len(metas))
	total := 0
	for _, m := range metas {
		templates, _, err := h.resolveTemplates(ctx, m.ID, "art", "", "", "", req.IncludeAdvanced)
		if err != nil || len(templates) == 0 {
			continue // matches vexRunFullSweep's own behavior of skipping techniques with no generated variants
		}
		techniques = append(techniques, m.ID)
		counts = append(counts, len(templates))
		baseTypes = append(baseTypes, "art")
		total += len(templates)
	}
	// Append Caldera abilities after every ART technique -- a combined
	// sweep runs ART first, then Caldera, per technique-index order.
	for _, techID := range h.calderaStore.ListTechniqueIDs() {
		templates, _, err := h.resolveTemplates(ctx, techID, "caldera", "", "", "", req.IncludeAdvanced)
		if err != nil || len(templates) == 0 {
			continue
		}
		techniques = append(techniques, techID)
		counts = append(counts, len(templates))
		baseTypes = append(baseTypes, "caldera")
		total += len(templates)
	}
	if len(techniques) == 0 {
		jsonError(w, "no techniques with generatable variants found", http.StatusUnprocessableEntity)
		return
	}

	c, _ := auth.ClaimsFrom(ctx)
	createdBy := ""
	if c != nil {
		createdBy = c.UserID
	}

	sw, err := h.vexSweep.Create(ctx, vexsweep.Sweep{
		AgentID: req.AgentID, Mode: mode, IncludeAdvanced: req.IncludeAdvanced,
		Techniques: techniques, TechniqueVariantCounts: counts, BaseTypes: baseTypes, TotalVariants: total, CreatedBy: createdBy,
	})
	if err != nil {
		if err == vexsweep.ErrAgentAlreadySweeping {
			jsonError(w, "agent already has a running sweep", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "vexsweep.create", sw.ID, map[string]any{"agentId": req.AgentID, "totalVariants": total, "techniqueCount": len(techniques)}, "ok")
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, sweepToJSON(h.db, sw))
}

// GET /api/vex/sweeps/active?agentId=X
func (h *Handler) GetActiveVexSweep(w http.ResponseWriter, r *http.Request) {
	if h.vexSweep == nil {
		jsonError(w, "vex sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	agentID := r.URL.Query().Get("agentId")
	if agentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	sw, found, err := h.vexSweep.GetActiveForAgent(r.Context(), agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "no active sweep for this agent", http.StatusNotFound)
		return
	}
	jsonOK(w, sweepToJSON(h.db, sw))
}

// GET /api/vex/sweeps/{id}
func (h *Handler) GetVexSweep(w http.ResponseWriter, r *http.Request) {
	if h.vexSweep == nil {
		jsonError(w, "vex sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	sw, err := h.vexSweep.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "sweep not found", http.StatusNotFound)
		return
	}
	jsonOK(w, sweepToJSON(h.db, sw))
}

// GET /api/vex/sweeps/{id}/runs
// Returns the sweep's summary plus EVERY scenario_runs row it dispatched,
// unbounded (not subject to ListScenarioRuns' 100-row cap) -- a sweep can
// dispatch far more than 100 techniques over its lifetime, so an aggregate
// or drill-down built only from the paginated main list would be silently
// wrong for large or older sweeps. See
// docs/superpowers/specs/2026-08-11-sweep-run-grouping-design.md.
func (h *Handler) GetVexSweepRuns(w http.ResponseWriter, r *http.Request) {
	if h.vexSweep == nil {
		jsonError(w, "vex sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	sw, err := h.vexSweep.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "sweep not found", http.StatusNotFound)
		return
	}

	rows, err := h.db.Query(r.Context(),
		`SELECT id, scenario_id, agent_id, sweep_id, em_sweep_id, name, status, results, score, initiated_by, started_at, completed_at,
		        steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
		        alerts_total, alerts_high_fidelity, noise_score, reverted, mode, max_privilege, paused, dispatch_subset, fail_reason
		 FROM scenario_runs WHERE sweep_id = $1 ORDER BY started_at`,
		id,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	runs, err := scanRunRows(rows)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []runRow{}
	}

	jsonOK(w, map[string]any{"sweep": sweepToJSON(h.db, sw), "runs": runs})
}

// GET /api/vex/sweeps/{id}/report
// Combined HTML report for a Full Variant Sweep: one row per dispatched
// technique (Blocked/Detected/Missed/Error rollup) plus an
// encoding-effectiveness breakdown, aggregated from every scenario_runs row
// the sweep dispatched.
func (h *Handler) GetSweepReport(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	rep, err := h.reportingEngine.BuildFromSweep(r.Context(), id, r.URL.Query().Get("filter"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	h.auditLog(r, "report.export", id, map[string]any{"format": "html", "type": "sweep"}, "ok")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := reporting.GenerateHTML(w, rep, nil); err != nil {
		log.Printf("[api] sweep report html: %v", err)
	}
}

// GET /api/vex/sweeps/{id}/pdf
func (h *Handler) GetSweepPDF(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	rep, err := h.reportingEngine.BuildFromSweep(r.Context(), id, r.URL.Query().Get("filter"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	fname := buildReportFilename("Variant_Sweep", rep.Agent.Hostname, "pdf")
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	h.auditLog(r, "report.export", id, map[string]any{"format": "pdf", "type": "sweep"}, "ok")
	if err := h.reportingEngine.PDFFromReport(r.Context(), w, rep, nil, nil); err != nil {
		log.Printf("[api] sweep report pdf: %v", err)
	}
}

// GET /api/vex/sweeps?status=running
func (h *Handler) ListVexSweeps(w http.ResponseWriter, r *http.Request) {
	if h.vexSweep == nil {
		jsonOK(w, []map[string]any{})
		return
	}
	status := coalesce(strings.TrimSpace(r.URL.Query().Get("status")), "running")
	sweeps, err := h.vexSweep.ListByStatus(r.Context(), status)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(sweeps))
	for _, sw := range sweeps {
		out = append(out, sweepToJSON(h.db, sw))
	}
	jsonOK(w, out)
}

// POST /api/vex/sweeps/{id}/cancel
func (h *Handler) CancelVexSweep(w http.ResponseWriter, r *http.Request) {
	if h.vexSweep == nil {
		jsonError(w, "vex sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	ctx := r.Context()
	sw, err := h.vexSweep.Get(ctx, id)
	if err != nil {
		jsonError(w, "sweep not found", http.StatusNotFound)
		return
	}
	if sw.Status != "running" && sw.Status != "agent_disconnected" {
		jsonError(w, "sweep is not running (status: "+sw.Status+")", http.StatusConflict)
		return
	}
	if sw.CurrentScenarioRunID != "" {
		if _, _, err := h.cancelScenarioRun(ctx, sw.CurrentScenarioRunID); err != nil && err != errRunNotRunning {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := h.vexSweep.MarkStopped(ctx, id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "vexsweep.cancel", id, map[string]any{"agentId": sw.AgentID}, "ok")
	jsonOK(w, map[string]string{"id": id, "status": "stopped"})
}

// sweepToJSON serializes a Sweep plus a live-computed completedVariants
// that includes the in-flight technique's already-finished steps (read
// from scenario_runs.steps_done) -- not just the last fully completed
// technique's tally that Sweep.CompletedVariants alone holds. steps_done
// is what SubmitRunEvents increments per completed step as an agent
// executes, in real time; scenario_runs.results is not usable for this --
// the agent only ever writes it once, atomically, with the run's complete
// final snapshot (see submitScenarioResult's "REPLACE, never append"),
// so it stays empty for the run's entire in-flight duration. See design
// spec Architecture §4.
func sweepToJSON(db *pgxpool.Pool, sw vexsweep.Sweep) map[string]any {
	live := sw.CompletedVariants
	if sw.CurrentScenarioRunID != "" {
		var n int
		if err := db.QueryRow(context.Background(),
			`SELECT COALESCE(steps_done, 0) FROM scenario_runs WHERE id = $1`,
			sw.CurrentScenarioRunID,
		).Scan(&n); err == nil {
			live += n
		}
	}
	return map[string]any{
		"id": sw.ID, "agentId": sw.AgentID, "mode": sw.Mode, "includeAdvanced": sw.IncludeAdvanced,
		"techniques": sw.Techniques, "baseTypes": sw.BaseTypes, "currentIndex": sw.CurrentIndex,
		"currentTechnique": currentTechnique(sw), "currentVariantRunId": sw.CurrentVariantRunID,
		"currentScenarioRunId": sw.CurrentScenarioRunID, "completedVariants": live,
		"totalVariants": sw.TotalVariants, "totalTechniques": len(sw.Techniques),
		"status": sw.Status, "error": sw.Error, "createdBy": sw.CreatedBy,
		"startedAt": sw.StartedAt, "completedAt": sw.CompletedAt, "disconnectedAt": sw.DisconnectedAt,
	}
}

func currentTechnique(sw vexsweep.Sweep) string {
	if sw.CurrentIndex >= 0 && sw.CurrentIndex < len(sw.Techniques) {
		return sw.Techniques[sw.CurrentIndex]
	}
	return ""
}
