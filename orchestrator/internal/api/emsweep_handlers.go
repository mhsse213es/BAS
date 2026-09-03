package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/emsweep"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
)

// emLayerIDs lists the 14 Endpoint Mastery scenario IDs, in sweep order.
// Mirrors EM_CATALOG in wwwroot/index.html:17683-17697 -- keep both lists
// in sync if EM layers are ever added/removed/reordered.
var emLayerIDs = []string{
	"em-01-control-validation", "em-02-attack-behavioral-depth", "em-03-memory-attacks",
	"em-04-credential-theft", "em-05-persistence-validation", "em-06-defense-evasion",
	"em-07-ransomware-readiness", "em-08-exploit-mitigation", "em-09-browser-attack",
	"em-10-endpoint-exfiltration", "em-11-hardening-validation", "em-12-adversary-emulation",
	"em-13-product-validation", "em-14-continuous-validation",
}

// isEMCategoryScenario mirrors wwwroot/index.html's scenarioCategoryOf --
// a scenario is Endpoint Mastery-category if its ID is prefixed "em-" or it
// carries the "endpoint-mastery" tag. Keep both in sync.
func isEMCategoryScenario(sc *scenario.Scenario) bool {
	return strings.HasPrefix(sc.ID, "em-") || slices.Contains(sc.Tags, "endpoint-mastery")
}

// POST /api/em/sweeps
// Creates a new Endpoint Mastery Full Sweep. Layers are resolved
// server-side by filtering emLayerIDs against the live scenario engine --
// never trusts a client-submitted list. Rejects (409) if the agent already
// has a running EM sweep.
func (h *Handler) CreateEMSweep(w http.ResponseWriter, r *http.Request) {
	if h.emSweep == nil {
		jsonError(w, "EM sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		AgentID          string   `json:"agentId"`
		ExtraScenarioIDs []string `json:"extraScenarioIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.AgentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	if h.engine == nil {
		jsonError(w, "scenario engine not loaded", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()

	var layers []string
	fixed := make(map[string]bool, len(emLayerIDs))
	for _, id := range emLayerIDs {
		if _, ok := h.engine.Get(id); ok {
			layers = append(layers, id)
			fixed[id] = true
		}
	}
	if len(layers) == 0 {
		jsonError(w, "no EM layer scenarios loaded on the server", http.StatusUnprocessableEntity)
		return
	}

	// Extra scenarios are appended after the 14 fixed layers -- never
	// trust the client-submitted list either: only IDs that resolve on the
	// live scenario engine AND are themselves Endpoint Mastery-category
	// scenarios are kept (mirrors wwwroot/index.html's scenarioCategoryOf:
	// id starting "em-", or tagged endpoint-mastery). A standard/non-EM
	// scenario ID submitted here -- accidentally or otherwise -- is
	// silently dropped, not appended; the fixed 14 are deduped out in case
	// the client accidentally resubmits one.
	seenExtra := make(map[string]bool, len(req.ExtraScenarioIDs))
	for _, id := range req.ExtraScenarioIDs {
		if id == "" || fixed[id] || seenExtra[id] {
			continue
		}
		sc, ok := h.engine.Get(id)
		if !ok || !isEMCategoryScenario(sc) {
			continue
		}
		layers = append(layers, id)
		seenExtra[id] = true
	}

	c, _ := auth.ClaimsFrom(ctx)
	createdBy := ""
	if c != nil {
		createdBy = c.UserID
	}

	sw, err := h.emSweep.Create(ctx, emsweep.Sweep{
		AgentID: req.AgentID, Layers: layers, TotalLayers: len(layers), CreatedBy: createdBy,
	})
	if err != nil {
		if err == emsweep.ErrAgentAlreadySweeping {
			jsonError(w, "agent already has a running EM sweep", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "emsweep.create", sw.ID, map[string]any{"agentId": req.AgentID, "layerCount": len(layers), "extraCount": len(seenExtra)}, "ok")
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, emSweepToJSON(sw))
}

// GET /api/em/sweeps/active?agentId=X
func (h *Handler) GetActiveEMSweep(w http.ResponseWriter, r *http.Request) {
	if h.emSweep == nil {
		jsonError(w, "EM sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	agentID := r.URL.Query().Get("agentId")
	if agentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	sw, found, err := h.emSweep.GetActiveForAgent(r.Context(), agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "no active EM sweep for this agent", http.StatusNotFound)
		return
	}
	jsonOK(w, emSweepToJSON(sw))
}

// GET /api/em/sweeps/{id}
func (h *Handler) GetEMSweep(w http.ResponseWriter, r *http.Request) {
	if h.emSweep == nil {
		jsonError(w, "EM sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	sw, err := h.emSweep.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "sweep not found", http.StatusNotFound)
		return
	}
	jsonOK(w, emSweepToJSON(sw))
}

// GET /api/em/sweeps/{id}/runs
func (h *Handler) GetEMSweepRuns(w http.ResponseWriter, r *http.Request) {
	if h.emSweep == nil {
		jsonError(w, "EM sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	sw, err := h.emSweep.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "sweep not found", http.StatusNotFound)
		return
	}

	rows, err := h.db.Query(r.Context(),
		`SELECT id, scenario_id, agent_id, sweep_id, em_sweep_id, name, status, results, score, initiated_by, started_at, completed_at,
		        steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
		        alerts_total, alerts_high_fidelity, noise_score, reverted, mode, max_privilege, paused, dispatch_subset, fail_reason
		 FROM scenario_runs WHERE em_sweep_id = $1 ORDER BY started_at`,
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

	jsonOK(w, map[string]any{"sweep": emSweepToJSON(sw), "runs": runs})
}

// GET /api/em/sweeps/{id}/report
func (h *Handler) GetEMSweepReport(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	rep, err := h.reportingEngine.BuildFromEMSweep(r.Context(), id, r.URL.Query().Get("filter"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	h.auditLog(r, "report.export", id, map[string]any{"format": "html", "type": "em_sweep"}, "ok")
	writeBufferedReport(w, "text/html; charset=utf-8", "", "em sweep report html",
		func(out io.Writer) error { return reporting.GenerateHTML(out, rep, nil) })
}

// GET /api/em/sweeps/{id}/pdf
func (h *Handler) GetEMSweepPDF(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	rep, err := h.reportingEngine.BuildFromEMSweep(r.Context(), id, r.URL.Query().Get("filter"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	fname := buildReportFilename("Endpoint_Mastery_Sweep", rep.Agent.Hostname, "pdf")
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	h.auditLog(r, "report.export", id, map[string]any{"format": "pdf", "type": "em_sweep"}, "ok")
	if err := h.reportingEngine.PDFFromReport(r.Context(), w, rep, nil, nil); err != nil {
		log.Printf("[api] em sweep report pdf: %v", err)
	}
}

// GET /api/em/sweeps?status=running
func (h *Handler) ListEMSweeps(w http.ResponseWriter, r *http.Request) {
	if h.emSweep == nil {
		jsonOK(w, []map[string]any{})
		return
	}
	status := coalesce(strings.TrimSpace(r.URL.Query().Get("status")), "running")
	sweeps, err := h.emSweep.ListByStatus(r.Context(), status)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(sweeps))
	for _, sw := range sweeps {
		out = append(out, emSweepToJSON(sw))
	}
	jsonOK(w, out)
}

// POST /api/em/sweeps/{id}/cancel
func (h *Handler) CancelEMSweep(w http.ResponseWriter, r *http.Request) {
	if h.emSweep == nil {
		jsonError(w, "EM sweep engine not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	ctx := r.Context()
	sw, err := h.emSweep.Get(ctx, id)
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
	if err := h.emSweep.MarkStopped(ctx, id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "emsweep.cancel", id, map[string]any{"agentId": sw.AgentID}, "ok")
	jsonOK(w, map[string]string{"id": id, "status": "stopped"})
}

func emSweepToJSON(sw emsweep.Sweep) map[string]any {
	return map[string]any{
		"id": sw.ID, "agentId": sw.AgentID, "layers": sw.Layers, "currentIndex": sw.CurrentIndex,
		"currentLayer": currentEMLayer(sw), "currentScenarioRunId": sw.CurrentScenarioRunID,
		"completedLayers": sw.CompletedLayers, "totalLayers": sw.TotalLayers,
		"status": sw.Status, "error": sw.Error, "createdBy": sw.CreatedBy,
		"startedAt": sw.StartedAt, "completedAt": sw.CompletedAt, "disconnectedAt": sw.DisconnectedAt,
	}
}

func currentEMLayer(sw emsweep.Sweep) string {
	if sw.CurrentIndex >= 0 && sw.CurrentIndex < len(sw.Layers) {
		return sw.Layers[sw.CurrentIndex]
	}
	return ""
}
