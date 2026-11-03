package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/detectgap"
)

// Deployed-rule tracking closes the loop on a detection gap: the customer records that they deployed a recommended
// Sigma rule, re-runs the scenario, and Audspect reports whether the gap is closed from the re-test run's own
// reviewed verifications. Recording a deployment proves nothing about detection; see detectgap.DeploymentStatus.

type deploymentItem struct {
	ID            string `json:"id"`
	TechniqueID   string `json:"techniqueId"`
	RuleID        string `json:"ruleId"`
	RuleTitle     string `json:"ruleTitle,omitempty"`
	RuleInLibrary bool   `json:"ruleInLibrary"`
	Backend       string `json:"backend"`
	BackendLabel  string `json:"backendLabel"`
	Note          string `json:"note"`
	DeployedBy    string `json:"deployedBy"`
	DeployedAt    string `json:"deployedAt"`
	RetestRunID   string `json:"retestRunId,omitempty"`
	Status        string `json:"status"`
	Detail        string `json:"detail"`
}

type deploymentRow struct {
	id, technique, rule, backend, note, by string
	at                                     time.Time
	retest                                 string
}

func (h *Handler) deploymentItem(row deploymentRow, status, detail string) deploymentItem {
	it := deploymentItem{ID: row.id, TechniqueID: row.technique, RuleID: row.rule, Backend: row.backend,
		BackendLabel: detectgap.BackendLabel(row.backend), Note: row.note, DeployedBy: row.by,
		DeployedAt: row.at.UTC().Format(time.RFC3339), RetestRunID: row.retest, Status: status, Detail: detail}
	if h.rules != nil {
		if r, ok := h.rules.RuleByID(row.rule); ok {
			it.RuleTitle, it.RuleInLibrary = r.Title, true
		}
	}
	return it
}

// CreateRuleDeployment records that a recommended rule was deployed for a detection gap in a run.
// POST /api/scenarios/runs/{runId}/detection-gaps/deployments {techniqueId, ruleId, backend, note}
//
// The technique must be a detection gap in that run today, the rule must be a library rule that targets it (the
// technique or its parent), and must have a translation for the SIEM named.
func (h *Handler) CreateRuleDeployment(w http.ResponseWriter, r *http.Request) {
	if h.verification == nil || h.rules == nil {
		jsonError(w, "detection gap tracking unavailable", http.StatusServiceUnavailable)
		return
	}
	runID := chi.URLParam(r, "runId")
	var body struct {
		TechniqueID string `json:"techniqueId"`
		RuleID      string `json:"ruleId"`
		Backend     string `json:"backend"`
		Note        string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.TechniqueID == "" || body.RuleID == "" || body.Backend == "" {
		jsonError(w, "techniqueId, ruleId and backend are required", http.StatusBadRequest)
		return
	}
	if len(body.Note) > 1000 {
		jsonError(w, "note is limited to 1000 characters", http.StatusBadRequest)
		return
	}
	_, _, _, results, err := h.loadRunForVerification(r.Context(), runID)
	if err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	current, err := h.verification.CurrentForRun(r.Context(), runID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	isGap := false
	for _, a := range detectgap.Assess(results, current) {
		if a.TechniqueID == body.TechniqueID && a.Status == detectgap.DetectionGap {
			isGap = true
		}
	}
	if !isGap {
		jsonError(w, "that technique is not a detection gap in this run", http.StatusConflict)
		return
	}
	rule, ok := h.rules.RuleByID(body.RuleID)
	if !ok {
		jsonError(w, "rule not found in the library", http.StatusNotFound)
		return
	}
	targets := false
	candidates, _ := h.rulesFor(body.TechniqueID)
	for _, c := range candidates {
		targets = targets || c.ID == rule.ID
	}
	if !targets {
		jsonError(w, "that rule does not target this technique", http.StatusUnprocessableEntity)
		return
	}
	hasBackend := false
	for _, t := range rule.Translations {
		hasBackend = hasBackend || t.Backend == body.Backend
	}
	if !hasBackend {
		jsonError(w, "that rule has no translation for the SIEM named", http.StatusUnprocessableEntity)
		return
	}

	row := deploymentRow{technique: body.TechniqueID, rule: rule.ID, backend: body.Backend, note: strings.TrimSpace(body.Note), by: actorFor(r)}
	if err := h.db.QueryRow(r.Context(),
		`INSERT INTO detection_rule_deployments (run_id, technique_id, rule_id, backend, note, deployed_by)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, deployed_at`,
		runID, row.technique, row.rule, row.backend, row.note, row.by).Scan(&row.id, &row.at); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "detection_gap.rule_deployed", row.id, map[string]any{"runId": runID, "techniqueId": row.technique, "ruleId": row.rule, "backend": row.backend}, "ok")
	status, detail := detectgap.DeploymentStatus(false, false, nil)
	respondStatus(w, h.deploymentItem(row, status, detail), http.StatusCreated)
}

// LinkDeploymentRetest links the run used to re-test a deployment. The run must be another run of the same
// scenario on the same agent that started after the deployment was recorded.
// POST /api/scenarios/runs/{runId}/detection-gaps/deployments/{deploymentId}/retest {retestRunId}
func (h *Handler) LinkDeploymentRetest(w http.ResponseWriter, r *http.Request) {
	runID, depID := chi.URLParam(r, "runId"), chi.URLParam(r, "deploymentId")
	var body struct {
		RetestRunID string `json:"retestRunId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RetestRunID == "" {
		jsonError(w, "retestRunId is required", http.StatusBadRequest)
		return
	}
	var deployedAt time.Time
	var originScenario, originAgent string
	if err := h.db.QueryRow(r.Context(),
		`SELECT d.deployed_at, sr.scenario_id, sr.agent_id
		   FROM detection_rule_deployments d JOIN scenario_runs sr ON sr.id = d.run_id
		  WHERE d.id = $1 AND d.run_id = $2`, depID, runID).Scan(&deployedAt, &originScenario, &originAgent); err != nil {
		jsonError(w, "deployment not found", http.StatusNotFound)
		return
	}
	if body.RetestRunID == runID {
		jsonError(w, "the re-test must be a different run from the one that found the gap", http.StatusBadRequest)
		return
	}
	var scenarioID, agentID string
	var startedAt time.Time
	if err := h.db.QueryRow(r.Context(), `SELECT scenario_id, agent_id, started_at FROM scenario_runs WHERE id = $1`, body.RetestRunID).
		Scan(&scenarioID, &agentID, &startedAt); err != nil {
		jsonError(w, "re-test run not found", http.StatusNotFound)
		return
	}
	if scenarioID != originScenario || agentID != originAgent {
		jsonError(w, "the re-test must be a run of the same scenario on the same agent", http.StatusUnprocessableEntity)
		return
	}
	if startedAt.Before(deployedAt) {
		jsonError(w, "that run started before the rule was deployed, so it cannot show the effect of the deployment", http.StatusUnprocessableEntity)
		return
	}
	if _, err := h.db.Exec(r.Context(),
		`UPDATE detection_rule_deployments SET retest_run_id = $1, retest_linked_at = NOW() WHERE id = $2`, body.RetestRunID, depID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "detection_gap.retest_linked", depID, map[string]any{"runId": runID, "retestRunId": body.RetestRunID}, "ok")
	respond(w, map[string]string{"id": depID, "retestRunId": body.RetestRunID})
}

// ListRuleDeployments lists a run's recorded deployments with where each stands, and the parameters the console
// needs to start a re-test (the run's scenario, agent and mode).
// GET /api/scenarios/runs/{runId}/detection-gaps/deployments
func (h *Handler) ListRuleDeployments(w http.ResponseWriter, r *http.Request) {
	if h.verification == nil {
		jsonError(w, "verification store unavailable", http.StatusServiceUnavailable)
		return
	}
	runID := chi.URLParam(r, "runId")
	var scenarioID, agentID, mode string
	if err := h.db.QueryRow(r.Context(), `SELECT scenario_id, agent_id, COALESCE(mode,'') FROM scenario_runs WHERE id = $1`, runID).
		Scan(&scenarioID, &agentID, &mode); err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	rows, err := h.db.Query(r.Context(),
		`SELECT id, technique_id, rule_id, backend, note, deployed_by, deployed_at, COALESCE(retest_run_id,'')
		   FROM detection_rule_deployments WHERE run_id = $1 ORDER BY deployed_at, id`, runID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var list []deploymentRow
	for rows.Next() {
		var d deploymentRow
		if err := rows.Scan(&d.id, &d.technique, &d.rule, &d.backend, &d.note, &d.by, &d.at, &d.retest); err != nil {
			rows.Close()
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		list = append(list, d)
	}
	rows.Close()

	retests := map[string]map[string]detectgap.Assessment{} // retest run -> technique -> assessment
	finished := map[string]bool{}
	items := []deploymentItem{}
	for _, d := range list {
		var retest *detectgap.Assessment
		if d.retest != "" {
			if _, seen := retests[d.retest]; !seen {
				retests[d.retest], finished[d.retest] = h.assessRetest(r.Context(), d.retest)
			}
			if a, ok := retests[d.retest][d.technique]; ok {
				retest = &a
			}
		}
		status, detail := detectgap.DeploymentStatus(d.retest != "", finished[d.retest], retest)
		items = append(items, h.deploymentItem(d, status, detail))
	}
	respond(w, map[string]any{
		"retest":      map[string]string{"scenarioId": scenarioID, "agentId": agentID, "mode": mode},
		"deployments": items,
	})
}

// assessRetest classifies a re-test run's techniques from its results and reviewed verifications. A run that cannot
// be loaded counts as not finished.
func (h *Handler) assessRetest(ctx context.Context, runID string) (map[string]detectgap.Assessment, bool) {
	var status string
	if err := h.db.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = $1`, runID).Scan(&status); err != nil {
		return nil, false
	}
	out := map[string]detectgap.Assessment{}
	_, _, _, results, err := h.loadRunForVerification(ctx, runID)
	if err != nil {
		return out, false
	}
	current, err := h.verification.CurrentForRun(ctx, runID)
	if err != nil {
		return out, false
	}
	for _, a := range detectgap.Assess(results, current) {
		out[a.TechniqueID] = a
	}
	return out, !runInProgress(status)
}

// runInProgress is true while a run can still produce results. A failed, partial or cancelled run is finished: its
// re-test says what it says (often that the technique was not re-tested), not "still running".
func runInProgress(status string) bool {
	switch status {
	case "running", "pending", "queued", "starting", "paused":
		return true
	}
	return false
}
