package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/detect"
	"github.com/audspect/bas/internal/iocregistry"
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

	// Load the run's executed results to correlate against. scenarioID/agentID
	// are also needed for IOC-sighting ownership below.
	var resultsRaw []byte
	var scenarioID, agentID string
	if err := h.db.QueryRow(r.Context(),
		`SELECT scenario_id, agent_id, results FROM scenario_runs WHERE id = $1`, runID).
		Scan(&scenarioID, &agentID, &resultsRaw); err != nil {
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

	// Merge per-technique detection verdicts into SimulationResult so reports
	// show PREVENTED / DETECTED / UNDETECTED alongside the execution verdict.
	detIdx := make(map[string]detect.TechniqueDetection, len(dets))
	for _, d := range dets {
		detIdx[d.TechniqueID] = d
	}
	for i := range results {
		d, ok := detIdx[results[i].Technique.ID]
		if !ok {
			continue
		}
		results[i].DetectionVerdict = d.Verdict
		if d.Alert != nil {
			results[i].DetectionAlert = &models.DetectionAlert{
				Channel:     d.Alert.Channel,
				Provider:    d.Alert.Provider,
				EventID:     d.Alert.EventID,
				ThreatName:  d.Alert.ThreatName,
				ProcessName: d.Alert.ProcessName,
				CommandLine: d.Alert.CommandLine,
				Timestamp:   d.Alert.Timestamp,
				Confidence:  d.Confidence,
				MTTDMs:      d.TimeToDetectMs,
			}
		}
		if d.BlockingControl != nil {
			results[i].BlockingControl = &models.BlockingControl{
				Name:    d.BlockingControl.Name,
				RuleID:  d.BlockingControl.RuleID,
				EventID: d.BlockingControl.EventID,
				Channel: d.BlockingControl.Channel,
			}
		}
	}
	updatedResultsJSON, _ := json.Marshal(results)

	totalAlerts := len(body.Alerts)
	highFidelity := 0
	detectIDs := detect.DefenderDetectIDs()
	for _, alert := range body.Alerts {
		// Same attribution rule Correlate uses. Keeping a second copy here is
		// how the two drifted: this one also demanded a threat name alongside
		// an EDR provider, so every POSIX alert scored as pure noise.
		if detect.IsAttributable(alert, detectIDs) {
			highFidelity++
		}
	}
	var noiseScore float64
	if totalAlerts > 0 {
		noiseScore = float64(totalAlerts-highFidelity) / float64(totalAlerts) * 100.0
	} else {
		noiseScore = 0.0
	}

	rawJSON, _ := json.Marshal(body.Alerts)
	summaryJSON, _ := json.Marshal(map[string]any{"summary": sum, "techniques": dets, "truncated": body.Truncated})
	if _, err := h.db.Exec(r.Context(),
		`UPDATE scenario_runs SET detections_raw=$1, detection_summary=$2,
		        detection_rate=$3, undetected_rate=$4, mttd_ms=$5, results=$6,
		        alerts_total=$7, alerts_high_fidelity=$8, noise_score=$9 WHERE id=$10`,
		rawJSON, summaryJSON, sum.DetectionRate, sum.UndetectedRate, sum.MTTDMs, updatedResultsJSON,
		totalAlerts, highFidelity, noiseScore, runID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Refresh findings now that detection verdicts are known — fails that were
	// caught flip missed → detected_only (same-run refinement, idempotent).
	h.upsertFindingsForRun(r.Context(), runID)

	// Best-effort IOC extraction -- never fails the request. See
	// docs/superpowers/specs/2026-07-31-ioc-registry-design.md and
	// docs/superpowers/specs/2026-07-31-ioc-relationships-analytics-design.md.
	for i := range results {
		if err := iocregistry.ExtractFromDetectionAlert(r.Context(), h.db, scenarioID, runID, agentID,
			results[i].Technique.ID, results[i].DetectionVerdict, results[i]); err != nil {
			log.Printf("[ioc] extraction failed for run %s: %v", runID, err)
		}
	}

	// "logged" counts techniques with an in-window alert that nothing attributed
	// to a control. Reported alongside the rates so a low detection rate reads
	// correctly: those are leads to review, not detections.
	respond(w, map[string]any{
		"runId":              runID,
		"detectionRate":      sum.DetectionRate,
		"undetectedRate":     sum.UndetectedRate,
		"logged":             sum.Logged,
		"loggedRate":         sum.LoggedRate,
		"mttdMs":             sum.MTTDMs,
		"alerts":             totalAlerts,
		"alertsTotal":        totalAlerts,
		"alertsHighFidelity": highFidelity,
		"noiseScore":         noiseScore,
	})
}
