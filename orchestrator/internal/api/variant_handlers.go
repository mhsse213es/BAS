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
	"github.com/audspect/bas/internal/vexsweep"
)

// cmdPreview returns the first 120 chars of a command for UI display.
func cmdPreview(s string) string {
	if len(s) <= 120 {
		return s
	}
	return s[:120] + "…"
}

// POST /api/variants/generate
// Preview all variant Templates for a technique without dispatching to an agent.
// Auto-loads payload families from DB when they exist (no command override given).
// Set includeAdvanced=true to include the Advanced Evasion Pack (AMSI bypass).
func (h *Handler) GenerateVariants(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TechniqueID     string `json:"techniqueId"`
		BaseType        string `json:"baseType"`
		BaseID          string `json:"baseId"`
		Command         string `json:"command"`
		Executor        string `json:"executor"`
		IncludeAdvanced bool   `json:"includeAdvanced"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.TechniqueID == "" {
		jsonError(w, "techniqueId required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	templates, baseID, err := h.resolveTemplates(ctx, req.TechniqueID, coalesce(req.BaseType, "art"),
		req.BaseID, req.Command, req.Executor, req.IncludeAdvanced)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonOK(w, map[string]any{
		"techniqueId":     req.TechniqueID,
		"baseId":          baseID,
		"count":           len(templates),
		"includeAdvanced": req.IncludeAdvanced,
		"templates":       templates,
	})
}

// POST /api/variants/run
// Dispatch all generated variants for a technique to a connected agent.
// Auto-loads payload families from DB when they exist.
// executionMode: "sequential" (default) | "adaptive" (stop after first ALLOWED)
func (h *Handler) RunVariants(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID         string `json:"agentId"`
		TechniqueID     string `json:"techniqueId"`
		BaseType        string `json:"baseType"`
		BaseID          string `json:"baseId"`
		Command         string `json:"command"`
		Executor        string `json:"executor"`
		IncludeAdvanced bool   `json:"includeAdvanced"`
		ExecutionMode   string `json:"executionMode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.AgentID == "" || req.TechniqueID == "" {
		jsonError(w, "agentId and techniqueId required", http.StatusBadRequest)
		return
	}
	if h.vexSweep != nil {
		if _, found, err := h.vexSweep.GetActiveForAgent(r.Context(), req.AgentID); err == nil && found {
			jsonError(w, "agent has an active Full Sweep — stop it before running an individual variant test", http.StatusConflict)
			return
		}
	}

	ctx := r.Context()
	templates, baseID, err := h.resolveTemplates(ctx, req.TechniqueID, coalesce(req.BaseType, "art"),
		req.BaseID, req.Command, req.Executor, req.IncludeAdvanced)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(templates) == 0 {
		jsonError(w, "no variants generated — technique may use an unsupported executor or script is empty", http.StatusUnprocessableEntity)
		return
	}

	mode := coalesce(req.ExecutionMode, variant.ExecutionSequential)
	runID, vrID, err := h.dispatchVariantRun(ctx, "", req.AgentID, req.TechniqueID,
		coalesce(req.BaseType, "art"), baseID, mode, templates, "", "", false)
	if err != nil {
		log.Printf("[variant] dispatch failed for %s on %s: %v", req.TechniqueID, req.AgentID, err)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "variant.run", req.TechniqueID, map[string]any{
		"agentId":       req.AgentID,
		"variantRunId":  vrID,
		"totalVariants": len(templates),
		"advanced":      req.IncludeAdvanced,
		"mode":          mode,
	}, "ok")

	jsonOK(w, map[string]any{
		"variantRunId":  vrID,
		"scenarioRunId": runID,
		"totalVariants": len(templates),
	})
}

// GET /api/variants/run/:id
// Returns per-variant verdicts joined from the underlying scenario_run results.
func (h *Handler) GetVariantRun(w http.ResponseWriter, r *http.Request) {
	vrID := chi.URLParam(r, "id")
	ctx := r.Context()

	var vr variant.Run
	var completedAt *time.Time
	err := h.db.QueryRow(ctx,
		`SELECT id, agent_id, technique_id, base_type, base_id, scenario_run_id,
		        total_variants, status, execution_mode, generator_version,
		        created_at, completed_at
		   FROM variant_runs WHERE id = $1`, vrID,
	).Scan(&vr.ID, &vr.AgentID, &vr.TechniqueID, &vr.BaseType, &vr.BaseID,
		&vr.ScenarioRunID, &vr.TotalVariants, &vr.Status, &vr.ExecutionMode,
		&vr.GeneratorVersion, &vr.CreatedAt, &completedAt)
	if err != nil {
		jsonError(w, "variant run not found", http.StatusNotFound)
		return
	}
	vr.CompletedAt = completedAt

	// Load scenario_run status + results JSONB + live steps_done. results is
	// only ever written once, atomically, with the run's complete final
	// snapshot (see submitScenarioResult's "REPLACE, never append"), so it
	// stays empty for the run's entire in-flight duration -- steps_done is
	// what SubmitRunEvents increments live, per completed step, and is the
	// only column that actually reflects progress before completion.
	var resultsRaw []byte
	var runStatus string
	var stepsDone int
	if err := h.db.QueryRow(ctx,
		`SELECT status, COALESCE(results::text,'[]'), COALESCE(steps_done, 0) FROM scenario_runs WHERE id = $1`,
		vr.ScenarioRunID,
	).Scan(&runStatus, &resultsRaw, &stepsDone); err != nil {
		resultsRaw = []byte("[]")
	}

	// Sync variant_run status from underlying scenario_run. Includes
	// "partial" (a cancelled run) as well as normal terminal outcomes --
	// this is a defense-in-depth backstop for cancelScenarioRun's own
	// markVariantRunPartial, in case that write was ever missed (e.g. a
	// server restart between the two updates).
	if (runStatus == "completed" || runStatus == "failed" || runStatus == "partial") && vr.Status == "running" {
		vr.Status = runStatus
		now := time.Now().UTC()
		vr.CompletedAt = &now
		h.db.Exec(ctx,
			`UPDATE variant_runs SET status = $1, completed_at = NOW() WHERE id = $2`,
			runStatus, vrID)
	}

	var simResults []models.SimulationResult
	json.Unmarshal(resultsRaw, &simResults)
	srMap := make(map[string]models.SimulationResult, len(simResults))
	for _, sr := range simResults {
		srMap[sr.ID] = sr
	}

	// Live per-step verdicts from run_events, for while the run is still in
	// flight: scenario_runs.results is only ever written once, atomically,
	// with the run's complete final snapshot (see the comment above), so
	// srMap stays empty the whole time a run is running -- every variant
	// showed PENDING even for steps the agent had already finished and
	// reported, until the entire batch completed. SubmitRunEvents already
	// writes one 'completed' event per step with the real verdict in its
	// payload (used live to increment steps_passed/steps_failed), so read
	// that back the same way instead of waiting for the final blob.
	liveVerdicts := make(map[string]models.CheckResult)
	if runStatus == "running" {
		evRows, everr := h.db.Query(ctx,
			`SELECT task_id, payload->>'verdict' FROM run_events
			  WHERE run_id = $1 AND type = 'completed' AND task_id != '' ORDER BY seq`,
			vr.ScenarioRunID)
		if everr == nil {
			for evRows.Next() {
				var taskID, verdict string
				if evRows.Scan(&taskID, &verdict) == nil && verdict != "" {
					liveVerdicts[taskID] = models.CheckResult(verdict)
				}
			}
			evRows.Close()
		}
	}

	// Load step records ordered by insertion (= dispatch order).
	stepRows, err := h.db.Query(ctx,
		`SELECT task_id, encoding, exec_context, evasion, executor,
		        cmd_preview, risk_level, variant_hash
		   FROM variant_run_steps WHERE variant_run_id = $1 ORDER BY id`, vrID)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer stepRows.Close()

	var results []variant.Result
	summary := variant.Summary{}
	firstBypassSet := false

	for stepRows.Next() {
		var sr variant.StepRecord
		if err := stepRows.Scan(&sr.TaskID, &sr.Encoding, &sr.ExecContext, &sr.Evasion,
			&sr.Executor, &sr.CmdPreview, &sr.RiskLevel, &sr.VariantHash); err != nil {
			continue
		}
		res := variant.Result{
			TaskID:      sr.TaskID,
			Encoding:    sr.Encoding,
			ExecContext: sr.ExecContext,
			Evasion:     sr.Evasion,
			Executor:    sr.Executor,
			CmdPreview:  sr.CmdPreview,
			RiskLevel:   sr.RiskLevel,
			VariantHash: sr.VariantHash,
			Verdict:     "PENDING",
		}
		summary.Total++

		if sim, found := srMap[sr.TaskID]; found {
			res.Verdict = simResultToVerdict(sim.Result)
			res.Detail = sim.Details
			if !sim.ExecutedAt.IsZero() {
				t := sim.ExecutedAt
				res.ExecutedAt = &t
			}
			if sim.DetectionAlert != nil {
				res.DetectionSource = sim.DetectionAlert.Provider
			}
		} else if v, found := liveVerdicts[sr.TaskID]; found {
			res.Verdict = simResultToVerdict(v)
		}

		switch res.Verdict {
		case "PREVENTED":
			summary.Prevented++
		case "ALLOWED":
			summary.Allowed++
			if !firstBypassSet {
				summary.FirstBypass = sr.Encoding + "|" + sr.ExecContext + "|" + sr.Evasion
				summary.FirstBypassRisk = sr.RiskLevel
				firstBypassSet = true
			}
		case "ERROR":
			summary.Errored++
		default:
			summary.Pending++
		}
		results = append(results, res)
	}

	jsonOK(w, variant.RunDetail{Run: vr, Results: results, Summary: summary, StepsDone: stepsDone})
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

	type runRef struct{ techniqueID, baseType, baseID, scenarioRunID string }
	var runs []runRef
	for rows.Next() {
		var rr runRef
		if err := rows.Scan(&rr.techniqueID, &rr.baseType, &rr.baseID, &rr.scenarioRunID); err == nil {
			runs = append(runs, rr)
		}
	}

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
			rr.scenarioRunID).Scan(&resultsRaw)

		var simResults []models.SimulationResult
		json.Unmarshal(resultsRaw, &simResults)

		row := variant.CoverageRow{
			TechniqueID: rr.techniqueID,
			// The comprehensive ATT&CK TacticMap (same lookup every other
			// report/finding in this codebase uses), not payload_families --
			// that table only has rows for techniques a payload family was
			// actually configured for, and never falls back from a
			// sub-technique (e.g. T1074.001) to its parent, so it silently
			// left this column empty for anything outside that narrow set.
			Tactic:      models.LookupTactic(rr.techniqueID),
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

// GET /api/variants/stats
// Returns executed vs available variant counts for honest dashboard display.
func (h *Handler) GetVariantStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var executed, familyCount, techCount, artTechCount, artAtomicCount int
	h.db.QueryRow(ctx,
		`SELECT COALESCE(SUM(total_variants),0) FROM variant_runs WHERE status = 'completed'`,
	).Scan(&executed)
	h.db.QueryRow(ctx, `SELECT COUNT(*) FROM payload_families`).Scan(&familyCount)
	h.db.QueryRow(ctx, `SELECT COUNT(DISTINCT technique_id) FROM payload_families`).Scan(&techCount)
	h.db.QueryRow(ctx, `SELECT COUNT(DISTINCT technique_id) FROM art_atomic_tests`).Scan(&artTechCount)
	h.db.QueryRow(ctx, `SELECT COUNT(*) FROM art_atomic_tests`).Scan(&artAtomicCount)

	// ART-derived total: same formula used by /api/art/content/status so both
	// screens agree. Falls back to 0 on error — non-fatal.
	_, _, artVariants, _ := scenario.QueryVariantCount(ctx, h.db)

	// Caldera-derived total: every loaded ability × the same PowerShell
	// combinatorial count ART uses (abilities are always indexed with
	// Executor "powershell" -- see CalderaStore.NewCalderaStore). Safe on a
	// nil calderaStore (Count() returns 0).
	calderaAbilities := h.calderaStore.Count()
	calderaVariants := calderaAbilities * scenario.StepVariantCount("powershell")

	perFamily := variant.VariantsPerFamily(false)
	jsonOK(w, variant.Stats{
		ExecutedVariants:         executed,
		AvailableVariants:        artVariants + calderaVariants,
		ARTAvailableVariants:     artVariants,
		CalderaAvailableVariants: calderaVariants,
		CalderaAbilityCount:      calderaAbilities,
		ARTTechniqueCount:        artTechCount,
		ARTAtomicCount:           artAtomicCount,
		PayloadFamilyCount:       familyCount,
		PayloadFamilyVariants:    familyCount * perFamily,
		TechniquesWithFamilies:   techCount,
		VariantsPerFamily:        perFamily,
	})
}

// ── Payload Family CRUD ───────────────────────────────────────────────────────

// GET /api/payload-families
// List all payload families (all techniques).
func (h *Handler) GetPayloadFamilies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.db.Query(ctx,
		`SELECT id, technique_id, name, description, payload, purpose, risk_level, platform, executor, created_at
		   FROM payload_families ORDER BY technique_id, name`)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var families []variant.PayloadFamily
	for rows.Next() {
		var f variant.PayloadFamily
		if err := rows.Scan(&f.ID, &f.TechniqueID, &f.Name, &f.Description, &f.Payload,
			&f.Purpose, &f.RiskLevel, &f.Platform, &f.Executor, &f.CreatedAt); err == nil {
			families = append(families, f)
		}
	}
	jsonOK(w, families)
}

// GET /api/payload-families/:techniqueId
// List payload families for a specific technique.
func (h *Handler) GetTechniqueFamilies(w http.ResponseWriter, r *http.Request) {
	techID := chi.URLParam(r, "techniqueId")
	ctx := r.Context()
	rows, err := h.db.Query(ctx,
		`SELECT id, technique_id, name, description, payload, purpose, risk_level, platform, executor, created_at
		   FROM payload_families WHERE technique_id = $1 ORDER BY name`,
		strings.ToUpper(strings.TrimSpace(techID)))
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var families []variant.PayloadFamily
	for rows.Next() {
		var f variant.PayloadFamily
		if err := rows.Scan(&f.ID, &f.TechniqueID, &f.Name, &f.Description, &f.Payload,
			&f.Purpose, &f.RiskLevel, &f.Platform, &f.Executor, &f.CreatedAt); err == nil {
			families = append(families, f)
		}
	}
	jsonOK(w, families)
}

// POST /api/payload-families
// Create a new payload family. Admin only.
func (h *Handler) CreatePayloadFamily(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TechniqueID string `json:"techniqueId"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Payload     string `json:"payload"`
		Purpose     string `json:"purpose"`
		RiskLevel   string `json:"riskLevel"`
		Executor    string `json:"executor"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.TechniqueID == "" || req.Name == "" || req.Payload == "" {
		jsonError(w, "techniqueId, name, and payload are required", http.StatusBadRequest)
		return
	}
	if req.RiskLevel == "" {
		req.RiskLevel = variant.RiskSafe
	}
	if req.Executor == "" {
		req.Executor = "powershell"
	}

	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO payload_families (technique_id, name, description, payload, purpose, risk_level, executor)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		strings.ToUpper(strings.TrimSpace(req.TechniqueID)), req.Name, req.Description,
		req.Payload, coalesce(req.Purpose, "recon"), req.RiskLevel, req.Executor,
	).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "uq_payload_family") {
			jsonError(w, "a family with that name already exists for this technique", http.StatusConflict)
			return
		}
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "payload_family.create", req.TechniqueID,
		map[string]any{"id": id, "name": req.Name}, "ok")
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"id": id})
}

// DELETE /api/payload-families/:id
// Delete a payload family. Admin only.
func (h *Handler) DeletePayloadFamily(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tag, err := h.db.Exec(r.Context(), `DELETE FROM payload_families WHERE id = $1`, id)
	if err != nil || tag.RowsAffected() == 0 {
		jsonError(w, "family not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "payload_family.delete", id, nil, "ok")
	w.WriteHeader(http.StatusNoContent)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// resolveTemplates returns the templates to dispatch for a technique.
// When the caller provides an explicit command, it generates from that single script.
// Otherwise, it loads payload families from the DB; if none exist, falls back to the
// first ART step for the technique.
func (h *Handler) resolveTemplates(
	ctx context.Context,
	techniqueID, baseType, baseID, cmdOverride, execOverride string,
	includeAdvanced bool,
) (templates []variant.Template, resolvedBaseID string, err error) {

	// Explicit override: use exactly what the caller provided.
	if cmdOverride != "" && execOverride != "" {
		bid := coalesce(baseID, "custom")
		return variant.Generate(techniqueID, baseType, bid, cmdOverride, execOverride, includeAdvanced), bid, nil
	}

	// Auto-load payload families when no override is given.
	families, _ := h.loadPayloadFamilies(ctx, techniqueID)
	if len(families) > 0 {
		templates = variant.GenerateFromFamilies(techniqueID, baseType, families, includeAdvanced)
		return templates, techniqueID, nil
	}

	// Fall back to an ART atomic or Caldera ability lookup, per baseType.
	cmd, exec, bid, ferr := h.resolveBaseCommand(techniqueID, baseType, baseID, cmdOverride, execOverride)
	if ferr != nil {
		return nil, "", ferr
	}
	return variant.Generate(techniqueID, baseType, bid, cmd, exec, includeAdvanced), bid, nil
}

// loadPayloadFamilies loads all payload families for a technique from the DB.
func (h *Handler) loadPayloadFamilies(ctx context.Context, techniqueID string) ([]variant.PayloadFamily, error) {
	rows, err := h.db.Query(ctx,
		`SELECT id, technique_id, name, description, payload, purpose, risk_level, platform, executor, created_at
		   FROM payload_families WHERE technique_id = $1 ORDER BY name`,
		strings.ToUpper(strings.TrimSpace(techniqueID)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []variant.PayloadFamily
	for rows.Next() {
		var f variant.PayloadFamily
		if err := rows.Scan(&f.ID, &f.TechniqueID, &f.Name, &f.Description, &f.Payload,
			&f.Purpose, &f.RiskLevel, &f.Platform, &f.Executor, &f.CreatedAt); err == nil {
			out = append(out, f)
		}
	}
	return out, nil
}

// resolveBaseCommand is the single-step fallback used when no payload
// families exist -- looks up an ART atomic or a Caldera ability, per
// baseType, both pre-loaded stores indexed by technique ID (see ARTStore /
// scenario.CalderaStore). Either lookup picks the step named baseID if
// given, else the first match.
func (h *Handler) resolveBaseCommand(techniqueID, baseType, baseID, cmdOverride, execOverride string) (cmd, exec, resolvedBaseID string, err error) {
	if cmdOverride != "" && execOverride != "" {
		return cmdOverride, execOverride, coalesce(baseID, "custom"), nil
	}
	if baseType == variant.SourceCaldera {
		abilities := h.calderaStore.GetAbilities(techniqueID)
		if len(abilities) == 0 {
			return "", "", "", fmt.Errorf("no Caldera abilities found for technique %s", techniqueID)
		}
		step := abilities[0]
		for _, s := range abilities {
			if baseID != "" && s.Name == baseID {
				step = s
				break
			}
		}
		return step.Command, step.Executor, step.Name, nil
	}
	if h.artStore == nil {
		return "", "", "", fmt.Errorf("ART store not loaded")
	}
	steps := h.artStore.GetSteps(strings.ToUpper(strings.TrimSpace(techniqueID)))
	if len(steps) == 0 {
		return "", "", "", fmt.Errorf("no ART steps found for technique %s", techniqueID)
	}
	step := steps[0]
	for _, s := range steps {
		if baseID != "" && s.Name == baseID {
			step = s
			break
		}
	}
	return step.Command, step.Executor, step.Name, nil
}

// dispatchVariantRun creates DB records and dispatches via the WebSocket
// pipeline. sweepName/sweepLabel/sweepFinal are forwarded onto the outgoing
// ScenarioCommand -- empty/false for the ad-hoc (non-sweep) caller.
func (h *Handler) dispatchVariantRun(
	ctx context.Context,
	sweepID, agentID, techniqueID, baseType, baseID, executionMode string,
	templates []variant.Template,
	sweepName, sweepLabel string, sweepFinal bool,
) (scenarioRunID, variantRunID string, err error) {

	syntheticScenarioID := "__variant__" + strings.ToLower(techniqueID)
	runName := "Variant: " + techniqueID + " (" + baseID + ")"
	genVersion := variant.GeneratorVersion

	// sweep_id has a REFERENCES vex_sweeps(id) constraint -- an empty string
	// would violate it for every non-sweep dispatch, so "" must become a true
	// SQL NULL, not the literal empty string, via a nil *string.
	var sweepIDArg *string
	if sweepID != "" {
		sweepIDArg = &sweepID
	}

	err = h.db.QueryRow(ctx,
		`INSERT INTO scenario_runs
			(scenario_id, agent_id, name, status, results, steps_total, initiated_by, sweep_id)
		 VALUES ($1, $2, $3, 'running', '[]', $4, 'variant-executor', $5)
		 RETURNING id`,
		syntheticScenarioID, agentID, runName, len(templates), sweepIDArg,
	).Scan(&scenarioRunID)
	if err != nil {
		return "", "", fmt.Errorf("create scenario_run: %w", err)
	}

	err = h.db.QueryRow(ctx,
		`INSERT INTO variant_runs
			(agent_id, technique_id, base_type, base_id, scenario_run_id, total_variants,
			 status, execution_mode, generator_version)
		 VALUES ($1, $2, $3, $4, $5, $6, 'running', $7, $8)
		 RETURNING id`,
		agentID, techniqueID, baseType, baseID, scenarioRunID, len(templates),
		executionMode, genVersion,
	).Scan(&variantRunID)
	if err != nil {
		return "", "", fmt.Errorf("create variant_run: %w", err)
	}

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
				(variant_run_id, task_id, technique_id, encoding, exec_context, evasion,
				 executor, cmd_preview, risk_level, variant_hash)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			variantRunID, taskID, t.TechniqueID,
			t.Encoding, t.ExecContext, t.Evasion, t.Executor,
			cmdPreview(t.Command), t.RiskLevel, t.VariantHash,
		); insErr != nil {
			log.Printf("[variant] insert step record %s: %v", taskID, insErr)
		}
	}

	h.persistStepMeta(ctx, scenarioRunID, steps)

	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    models.MsgCommandScenario,
		AgentID: agentID,
		Data: scenario.ScenarioCommand{
			RunID:      scenarioRunID,
			ScenarioID: syntheticScenarioID,
			Name:       runName,
			Steps:      steps,
			Mode:       "posture",
			SweepID:    sweepID,
			SweepName:  sweepName,
			SweepLabel: sweepLabel,
			SweepFinal: sweepFinal,
		},
	})
	if !sent {
		h.db.Exec(ctx, `UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, scenarioRunID)
		h.db.Exec(ctx, `UPDATE variant_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, variantRunID)
		return "", "", vexsweep.ErrAgentOffline
	}

	log.Printf("[variant] dispatched %d variants for %s → agent %s (run %s / variant_run %s)",
		len(templates), techniqueID, agentID, scenarioRunID, variantRunID)
	return scenarioRunID, variantRunID, nil
}

// dispatchVariantForSweep is the vexsweep.DispatchFn implementation --
// resolves templates and dispatches exactly like RunVariants does for a
// single ad-hoc request, but returns the resolved variant count too so the
// Dispatcher can credit the sweep's real (not precomputed) total.
// techniqueIndex/totalTechniques label the dispatched run for the agent's
// local console and flag the sweep's last technique -- see
// scenario.ScenarioCommand's SweepName/SweepLabel/SweepFinal doc comment.
func (h *Handler) dispatchVariantForSweep(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (scenarioRunID, variantRunID string, totalVariants int, err error) {
	templates, baseID, err := h.resolveTemplates(ctx, techniqueID, baseType, "", "", "", includeAdvanced)
	if err != nil {
		return "", "", 0, err
	}
	if len(templates) == 0 {
		return "", "", 0, fmt.Errorf("no variants generated for %s", techniqueID)
	}
	sweepFinal := techniqueIndex == totalTechniques-1
	scenarioRunID, variantRunID, err = h.dispatchVariantRun(ctx, sweepID, agentID, techniqueID, baseType, baseID, mode, templates, "Variant Full Sweep", techniqueID, sweepFinal)
	if err != nil {
		return "", "", 0, err
	}
	return scenarioRunID, variantRunID, len(templates), nil
}

func simResultToVerdict(r models.CheckResult) string {
	switch r {
	case models.ResultPass, models.ResultBlocked:
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

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// upsertVariantFindingsForRun is called after SubmitScenarioResult saves results
// for a variant run (scenario_id starting with "__variant__"). It inserts a row
// into variant_findings for each ALLOWED (bypassed) result so the coverage view
// shows which specific combinations defeated the endpoint controls.
//
// Also implements adaptive mode: when the variant_run has execution_mode='adaptive'
// and at least one ALLOWED result arrives, the variant_run is marked completed.
func (h *Handler) upsertVariantFindingsForRun(ctx context.Context, scenarioRunID, scenarioID string, results []models.SimulationResult) {
	if !strings.HasPrefix(scenarioID, "__variant__") {
		return
	}

	// Look up the variant_run linked to this scenario_run.
	var vrID, techniqueID, executionMode string
	if err := h.db.QueryRow(ctx,
		`SELECT id, technique_id, execution_mode FROM variant_runs WHERE scenario_run_id = $1`,
		scenarioRunID,
	).Scan(&vrID, &techniqueID, &executionMode); err != nil {
		log.Printf("[variant] upsertFindings: no variant_run for scenario_run %s: %v", scenarioRunID, err)
		return
	}

	allowedCount := 0
	for _, res := range results {
		if res.Result != models.ResultFail {
			continue
		}
		allowedCount++
		taskID := res.ID // SimulationResult.ID is the task_id set at dispatch time

		// Look up the step dimensions by task_id.
		var enc, execCtx, evasion, riskLevel string
		if err := h.db.QueryRow(ctx,
			`SELECT encoding, exec_context, evasion, risk_level
			   FROM variant_run_steps
			  WHERE variant_run_id = $1 AND task_id = $2`,
			vrID, taskID,
		).Scan(&enc, &execCtx, &evasion, &riskLevel); err != nil {
			log.Printf("[variant] step not found for task %s: %v", taskID, err)
			continue
		}

		gap := variantGapSummary(techniqueID, enc, execCtx, evasion)
		rec := variantRecommendation(enc, execCtx, evasion)

		if _, err := h.db.Exec(ctx,
			`INSERT INTO variant_findings
				(variant_run_id, task_id, technique_id, encoding, exec_context, evasion,
				 risk_level, gap_summary, recommendation)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			 ON CONFLICT DO NOTHING`,
			vrID, taskID, techniqueID, enc, execCtx, evasion, riskLevel, gap, rec,
		); err != nil {
			log.Printf("[variant] insert finding for task %s: %v", taskID, err)
		}
	}

	// Adaptive mode: close the variant_run as soon as we see the first bypass.
	if executionMode == variant.ExecutionAdaptive && allowedCount > 0 {
		h.db.Exec(ctx,
			`UPDATE variant_runs SET status='completed', completed_at=NOW() WHERE id=$1 AND status='running'`,
			vrID)
		log.Printf("[variant] adaptive: first bypass found, closing variant_run %s", vrID)
	}
}

// variantGapSummary returns a one-sentence human-readable description of the bypass
// combination, suitable for the variant_findings.gap_summary column.
func variantGapSummary(techniqueID, enc, execCtx, evasion string) string {
	return fmt.Sprintf(
		"%s executed — %s encoding via %s context with %s evasion bypassed endpoint controls",
		techniqueID, enc, execCtx, evasion,
	)
}

// variantRecommendation returns a short remediation hint for the most actionable
// dimension of the bypass (encoding > exec_context > evasion, in priority order).
func variantRecommendation(enc, execCtx, evasion string) string {
	// Evasion-level recommendations (highest specificity).
	switch evasion {
	case variant.EvasionAMSIPatch:
		return "Enable AMSI audit logging; block PowerShell reflection on amsiInitFailed via ASR rule 'Block execution of potentially obfuscated scripts' (GUID 5BEB7EFE)."
	case variant.EvasionParentShift:
		return "Add EDR parent-child rule: alert when powershell.exe spawns from cmd.exe or wmic.exe. Enable 'Audit Process Creation' (Event 4688) with command-line capture."
	}

	// Encoding-level recommendations.
	switch enc {
	case variant.EncBase64:
		return "Enable PowerShell ScriptBlock logging (Event 4104). Consider ASR rule: Block execution of potentially obfuscated scripts (GUID 5BEB7EFE)."
	case variant.EncGzipB64:
		return "Enable AMSI inspection for in-memory decompression. Deploy PowerShell Constrained Language Mode to restrict arbitrary iex."
	case variant.EncCharCode:
		return "Deploy PowerShell ScriptBlock logging (Event 4104). Char-array iex invocations appear in script block logs even when obfuscated at the command level."
	}

	// Exec-context-level recommendations (plain encoding).
	switch execCtx {
	case variant.CtxWMI:
		return "Enable WMI activity auditing (Event 5857–5861). Block wmic.exe via AppLocker or WDAC if WMI process creation is not operationally required."
	case variant.CtxSchedTask:
		return "Enable Task Scheduler audit logging. Alert on schtasks.exe creating tasks with /sc once — a common BAS and malware indicator."
	case variant.CtxCmdPowershell:
		return "Add EDR alert for cmd.exe spawning powershell.exe with -Command flag. Enable PowerShell Module Logging to capture parameters."
	default:
		return "Enable PowerShell Module logging, ScriptBlock logging (Event 4104), and Execution Policy enforcement."
	}
}
