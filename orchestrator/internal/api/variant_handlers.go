package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/variant"
)

// cmdPreview returns the first 120 chars of a command for UI display.
func cmdPreview(s string) string {
	if len(s) <= 120 {
		return s
	}
	return s[:120] + "…"
}

// POST /api/variants/generate
// Preview-only: generate and return the variant Templates for a base technique
// step without dispatching anything to an agent. Useful for the UI picker.
//
// Body: { "techniqueId": "T1059.001", "baseType": "art", "baseId": "Mimikatz" }
// Optionally the caller can supply "command" and "executor" directly; if absent
// the server looks up the first ART step for techniqueId.
func (h *Handler) GenerateVariants(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TechniqueID string `json:"techniqueId"`
		BaseType    string `json:"baseType"`
		BaseID      string `json:"baseId"`
		Command     string `json:"command"`
		Executor    string `json:"executor"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.TechniqueID == "" {
		jsonError(w, "techniqueId required", http.StatusBadRequest)
		return
	}

	cmd, exec, baseID, err := h.resolveBaseCommand(req.TechniqueID, req.BaseID, req.Command, req.Executor)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	templates := variant.Generate(req.TechniqueID, coalesce(req.BaseType, "art"), baseID, cmd, exec)
	jsonOK(w, map[string]any{
		"techniqueId": req.TechniqueID,
		"baseId":      baseID,
		"count":       len(templates),
		"templates":   templates,
	})
}

// POST /api/variants/run
// Dispatch all generated variants for a technique to a connected agent.
// Results flow through the existing scenario result pipeline.
//
// Body: { "agentId": "...", "techniqueId": "T1059.001", "baseType": "art", "baseId": "..." }
func (h *Handler) RunVariants(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID     string `json:"agentId"`
		TechniqueID string `json:"techniqueId"`
		BaseType    string `json:"baseType"`
		BaseID      string `json:"baseId"`
		Command     string `json:"command"`
		Executor    string `json:"executor"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.AgentID == "" || req.TechniqueID == "" {
		jsonError(w, "agentId and techniqueId required", http.StatusBadRequest)
		return
	}

	cmd, exec, baseID, err := h.resolveBaseCommand(req.TechniqueID, req.BaseID, req.Command, req.Executor)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	templates := variant.Generate(req.TechniqueID, coalesce(req.BaseType, "art"), baseID, cmd, exec)
	if len(templates) == 0 {
		jsonError(w, "no variants generated — technique may use an unsupported executor or baseScript is empty", http.StatusUnprocessableEntity)
		return
	}

	ctx := r.Context()
	runID, vrID, err := h.dispatchVariantRun(ctx, req.AgentID, req.TechniqueID, coalesce(req.BaseType, "art"), baseID, templates)
	if err != nil {
		log.Printf("[variant] dispatch failed for %s on %s: %v", req.TechniqueID, req.AgentID, err)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "variant.run", req.TechniqueID, map[string]any{
		"agentId":       req.AgentID,
		"variantRunId":  vrID,
		"totalVariants": len(templates),
	}, "ok")

	jsonOK(w, map[string]any{
		"variantRunId":  vrID,
		"scenarioRunId": runID,
		"totalVariants": len(templates),
	})
}

// GET /api/variants/run/:id
// Returns the variant run detail with per-variant verdicts joined from
// the scenario_run results.
func (h *Handler) GetVariantRun(w http.ResponseWriter, r *http.Request) {
	vrID := chi.URLParam(r, "id")
	ctx := r.Context()

	// Load the variant_run row.
	var vr variant.Run
	var completedAt *time.Time
	err := h.db.QueryRow(ctx,
		`SELECT id, agent_id, technique_id, base_type, base_id, scenario_run_id,
		        total_variants, status, created_at, completed_at
		   FROM variant_runs WHERE id = $1`, vrID,
	).Scan(&vr.ID, &vr.AgentID, &vr.TechniqueID, &vr.BaseType, &vr.BaseID,
		&vr.ScenarioRunID, &vr.TotalVariants, &vr.Status, &vr.CreatedAt, &completedAt)
	if err != nil {
		jsonError(w, "variant run not found", http.StatusNotFound)
		return
	}
	vr.CompletedAt = completedAt

	// Load the step records (encoding/ctx/evasion per task_id).
	stepRows, err := h.db.Query(ctx,
		`SELECT task_id, encoding, exec_context, evasion, executor, cmd_preview
		   FROM variant_run_steps WHERE variant_run_id = $1
		  ORDER BY id`, vrID)
	if err != nil {
		jsonError(w, "step records unavailable", http.StatusInternalServerError)
		return
	}
	defer stepRows.Close()

	stepMap := make(map[string]variant.StepRecord)
	for stepRows.Next() {
		var sr variant.StepRecord
		if err := stepRows.Scan(&sr.TaskID, &sr.Encoding, &sr.ExecContext, &sr.Evasion, &sr.Executor, &sr.CmdPreview); err != nil {
			continue
		}
		stepMap[sr.TaskID] = sr
	}

	// Load the scenario_run results JSONB and join with step records.
	var resultsRaw []byte
	var runStatus string
	err = h.db.QueryRow(ctx,
		`SELECT status, COALESCE(results::text,'[]') FROM scenario_runs WHERE id = $1`,
		vr.ScenarioRunID,
	).Scan(&runStatus, &resultsRaw)
	if err != nil {
		resultsRaw = []byte("[]")
	}

	// Update variant_run.status from the underlying scenario_run if it completed.
	if runStatus == "completed" || runStatus == "failed" {
		if vr.Status == "running" {
			now := time.Now().UTC()
			vr.Status = runStatus
			vr.CompletedAt = &now
			h.db.Exec(ctx,
				`UPDATE variant_runs SET status = $1, completed_at = NOW() WHERE id = $2`,
				runStatus, vrID)
		}
	}

	var simResults []models.SimulationResult
	json.Unmarshal(resultsRaw, &simResults)

	// Build result index from scenario results: taskId → SimulationResult.
	srMap := make(map[string]models.SimulationResult)
	for _, sr := range simResults {
		srMap[sr.ID] = sr
	}

	// Build per-variant result list ordered by step record insertion order.
	// We re-query steps to preserve insertion order.
	stepOrder, err := h.db.Query(ctx,
		`SELECT task_id, encoding, exec_context, evasion, executor, cmd_preview
		   FROM variant_run_steps WHERE variant_run_id = $1 ORDER BY id`, vrID)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer stepOrder.Close()

	var results []variant.Result
	summary := variant.Summary{}
	firstBypassSet := false

	for stepOrder.Next() {
		var sr variant.StepRecord
		if err := stepOrder.Scan(&sr.TaskID, &sr.Encoding, &sr.ExecContext, &sr.Evasion, &sr.Executor, &sr.CmdPreview); err != nil {
			continue
		}
		res := variant.Result{
			TaskID:      sr.TaskID,
			Encoding:    sr.Encoding,
			ExecContext: sr.ExecContext,
			Evasion:     sr.Evasion,
			Executor:    sr.Executor,
			CmdPreview:  sr.CmdPreview,
			Verdict:     "PENDING",
		}
		summary.Total++

		if sim, found := srMap[sr.TaskID]; found {
			res.Verdict = simResultToVerdict(sim.Result)
			res.Detail = sim.Details
			ts := sim.ExecutedAt
			if !ts.IsZero() {
				res.ExecutedAt = &ts
			}
		}

		switch res.Verdict {
		case "PREVENTED":
			summary.Prevented++
		case "ALLOWED":
			summary.Allowed++
			if !firstBypassSet {
				summary.FirstBypass = sr.Encoding + "|" + sr.ExecContext + "|" + sr.Evasion
				firstBypassSet = true
			}
		case "ERROR":
			summary.Errored++
		default:
			summary.Pending++
		}
		results = append(results, res)
	}

	jsonOK(w, variant.RunDetail{Run: vr, Results: results, Summary: summary})
}

// GET /api/variants/coverage
// Returns per-technique aggregate coverage across all completed variant runs.
func (h *Handler) GetVariantCoverage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.db.Query(ctx,
		`SELECT vr.technique_id, vr.base_type, vr.base_id, vr.scenario_run_id
		   FROM variant_runs vr
		  WHERE vr.status = 'completed'
		  ORDER BY vr.created_at DESC`)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type runRef struct {
		techniqueID   string
		baseType      string
		baseID        string
		scenarioRunID string
	}
	var runs []runRef
	for rows.Next() {
		var rr runRef
		if err := rows.Scan(&rr.techniqueID, &rr.baseType, &rr.baseID, &rr.scenarioRunID); err == nil {
			runs = append(runs, rr)
		}
	}

	// Aggregate by technique_id — most recent run wins.
	seen := make(map[string]bool)
	var coverage []variant.CoverageRow
	for _, rr := range runs {
		if seen[rr.techniqueID] {
			continue
		}
		seen[rr.techniqueID] = true

		var resultsRaw []byte
		h.db.QueryRow(ctx,
			`SELECT COALESCE(results::text,'[]') FROM scenario_runs WHERE id = $1`,
			rr.scenarioRunID,
		).Scan(&resultsRaw)

		var simResults []models.SimulationResult
		json.Unmarshal(resultsRaw, &simResults)

		row := variant.CoverageRow{
			TechniqueID: rr.techniqueID,
			BaseType:    rr.baseType,
			BaseID:      rr.baseID,
			TotalTested: len(simResults),
		}
		for _, sr := range simResults {
			switch simResultToVerdict(sr.Result) {
			case "PREVENTED":
				row.Prevented++
			case "ALLOWED":
				row.Allowed++
				if row.FirstBypass == "" {
					row.FirstBypass = sr.Details
				}
			case "ERROR":
				row.Errored++
			}
		}
		coverage = append(coverage, row)
	}

	jsonOK(w, coverage)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// resolveBaseCommand resolves the base command and executor for a variant run.
// Caller can supply them directly (overrides); otherwise they are looked up from
// the ART store using techniqueID + baseID (optional ART test name).
func (h *Handler) resolveBaseCommand(techniqueID, baseID, cmdOverride, execOverride string) (cmd, exec, resolvedBaseID string, err error) {
	if cmdOverride != "" && execOverride != "" {
		bid := baseID
		if bid == "" {
			bid = "custom"
		}
		return cmdOverride, execOverride, bid, nil
	}

	if h.artStore == nil {
		return "", "", "", fmt.Errorf("ART store not loaded")
	}
	steps := h.artStore.GetSteps(strings.ToUpper(strings.TrimSpace(techniqueID)))
	if len(steps) == 0 {
		return "", "", "", fmt.Errorf("no ART steps found for technique %s", techniqueID)
	}

	// Pick the step matching baseID (ART test name), or the first step.
	step := steps[0]
	for _, s := range steps {
		if baseID != "" && s.Name == baseID {
			step = s
			break
		}
	}
	return step.Command, step.Executor, step.Name, nil
}

// dispatchVariantRun creates the DB records and dispatches the variant scenario
// to the agent via the existing WebSocket command pipeline.
func (h *Handler) dispatchVariantRun(
	ctx context.Context,
	agentID, techniqueID, baseType, baseID string,
	templates []variant.Template,
) (scenarioRunID, variantRunID string, err error) {

	// Create scenario_run row (synthetic scenario_id identifies this as a variant run).
	syntheticScenarioID := "__variant__" + strings.ToLower(techniqueID)
	runName := "Variant: " + techniqueID + " (" + baseID + ")"

	err = h.db.QueryRow(ctx,
		`INSERT INTO scenario_runs
			(scenario_id, agent_id, name, status, results, steps_total, initiated_by)
		 VALUES ($1, $2, $3, 'running', '[]', $4, 'variant-executor')
		 RETURNING id`,
		syntheticScenarioID, agentID, runName, len(templates),
	).Scan(&scenarioRunID)
	if err != nil {
		return "", "", fmt.Errorf("create scenario_run: %w", err)
	}

	// Create variant_run row.
	err = h.db.QueryRow(ctx,
		`INSERT INTO variant_runs
			(agent_id, technique_id, base_type, base_id, scenario_run_id, total_variants, status)
		 VALUES ($1, $2, $3, $4, $5, $6, 'running')
		 RETURNING id`,
		agentID, techniqueID, baseType, baseID, scenarioRunID, len(templates),
	).Scan(&variantRunID)
	if err != nil {
		return "", "", fmt.Errorf("create variant_run: %w", err)
	}

	// Build ScenarioSteps from templates and record per-step metadata.
	steps := make([]scenario.ScenarioStep, 0, len(templates))
	for _, t := range templates {
		stepName := "variant|" + t.Encoding + "|" + t.ExecContext + "|" + t.Evasion + "|" + t.BaseID
		taskID := scenario.TaskID(t.TechniqueID, stepName)

		steps = append(steps, scenario.ScenarioStep{
			TaskID:      taskID,
			TechniqueID: t.TechniqueID,
			Name:        stepName,
			Framework:   "variant",
			Executor:    t.Executor,
			Command:     t.Command,
			TimeoutSec:  30,
		})

		if _, insErr := h.db.Exec(ctx,
			`INSERT INTO variant_run_steps
				(variant_run_id, task_id, technique_id, encoding, exec_context, evasion, executor, cmd_preview)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			variantRunID, taskID, t.TechniqueID,
			t.Encoding, t.ExecContext, t.Evasion, t.Executor, cmdPreview(t.Command),
		); insErr != nil {
			log.Printf("[variant] insert step record %s: %v", taskID, insErr)
		}
	}

	// Persist step_meta so SubmitScenarioResult can interpret results.
	h.persistStepMeta(ctx, scenarioRunID, steps)

	// Dispatch to agent via the existing WebSocket command pipeline.
	cmd := scenario.ScenarioCommand{
		RunID:      scenarioRunID,
		ScenarioID: syntheticScenarioID,
		Name:       runName,
		Steps:      steps,
		Mode:       "posture",
	}
	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    models.MsgCommandScenario,
		AgentID: agentID,
		Data:    cmd,
	})
	if !sent {
		h.db.Exec(ctx,
			`UPDATE scenario_runs  SET status = 'failed', completed_at = NOW() WHERE id = $1`, scenarioRunID)
		h.db.Exec(ctx,
			`UPDATE variant_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, variantRunID)
		return "", "", fmt.Errorf("agent %s not connected", agentID)
	}

	log.Printf("[variant] dispatched %d variants for %s → agent %s (run %s / variant_run %s)",
		len(templates), techniqueID, agentID, scenarioRunID, variantRunID)
	return scenarioRunID, variantRunID, nil
}

// simResultToVerdict maps a BAS CheckResult to a variant verdict label.
//   - pass  → PREVENTED  (the control blocked the technique — good for defender)
//   - fail  → ALLOWED    (the technique executed without being stopped — gap found)
//   - error → ERROR
//   - skipped → SKIPPED (treated as ERROR for coverage purposes)
func simResultToVerdict(r models.CheckResult) string {
	switch r {
	case models.ResultPass:
		return "PREVENTED"
	case models.ResultFail:
		return "ALLOWED"
	case models.ResultError, models.ResultSkipped:
		return "ERROR"
	}
	return "PENDING"
}

func coalesce(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}

// jsonOK writes a 200 JSON response.
func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
