package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/detect"
	"github.com/audspect/bas/internal/models"
	"github.com/go-chi/chi/v5"
)

// SubmitRunDetections ingests an agent's post-run alert sweep, correlates it
// against the run's stored results, scores it, and persists raw + summary.
// Agent-authed. Idempotent: REPLACES detections for the run (re-delivery heals).
// POST /api/scenarios/runs/{runId}/detections
func (h *Handler) SubmitRunDetections(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized — check AGENT_SECRET", http.StatusUnauthorized)
		return
	}
	runID := chi.URLParam(r, "runId")
	var body struct {
		Alerts    []detect.AlertRecord `json:"alerts"`
		Truncated bool                 `json:"truncated"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid detections payload", http.StatusBadRequest)
		return
	}

	// Load the run's executed results to correlate against.
	var resultsRaw []byte
	if err := h.db.QueryRow(r.Context(),
		`SELECT results FROM scenario_runs WHERE id = $1`, runID).Scan(&resultsRaw); err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	var results []models.SimulationResult
	_ = json.Unmarshal(resultsRaw, &results)

	steps := make([]detect.ExecutedStep, 0, len(results))
	for _, res := range results {
		steps = append(steps, detect.ExecutedStep{
			TechniqueID: res.Technique.ID,
			Verdict:     string(res.Result),
			ExecutedAt:  res.ExecutedAt,
			DurationMs:  res.DurationMs,
		})
	}

	dets := detect.Correlate(steps, body.Alerts, 5*time.Minute, detect.DefenderDetectIDs())
	sum := detect.Score(dets)

	rawJSON, _ := json.Marshal(body.Alerts)
	summaryJSON, _ := json.Marshal(map[string]any{"summary": sum, "techniques": dets, "truncated": body.Truncated})
	if _, err := h.db.Exec(r.Context(),
		`UPDATE scenario_runs SET detections_raw=$1, detection_summary=$2,
		        detection_rate=$3, undetected_rate=$4, mttd_ms=$5 WHERE id=$6`,
		rawJSON, summaryJSON, sum.DetectionRate, sum.UndetectedRate, sum.MTTDMs, runID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"runId": runID, "detectionRate": sum.DetectionRate,
		"undetectedRate": sum.UndetectedRate, "mttdMs": sum.MTTDMs, "alerts": len(body.Alerts)})
}
