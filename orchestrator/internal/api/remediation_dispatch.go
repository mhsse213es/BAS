package api

import (
	"context"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
)

// findStepByCheckID searches every loaded scenario for a step with the
// given check_id, returning its Command/Executor/TimeoutSec. Used to
// re-run a finding's own posture check as remediation verification,
// without duplicating that check's command inside the remediation
// catalog -- the catalog only ever references check_id by name.
func (h *Handler) findStepByCheckID(checkID string) (scenario.Step, bool) {
	for _, sc := range h.engine.List() {
		for _, st := range sc.Steps {
			if st.CheckID == checkID {
				return st, true
			}
		}
	}
	return scenario.Step{}, false
}

// dispatchRemediationStep builds an ephemeral, never-persisted Scenario
// containing exactly one local/custom step, builds it into agent-ready
// ScenarioSteps via the existing scenario.BuildSteps pipeline, inserts a
// tracking scenario_runs row, and dispatches it to the agent over the
// existing MsgCommandScenario/SubmitScenarioResult pipeline -- the same
// mechanism TriggerScan already uses to dispatch "full-scan", just against
// an in-memory Scenario instead of one loaded from h.engine.
//
// scenarioIDPrefix becomes part of the scenario_runs.id's scenario_id
// value (e.g. "remediation-fix", "remediation-verify",
// "remediation-rollback", "remediation-rollback-verify") for human-
// readable scenario_runs browsing -- the continuation hook matches on the
// run's own id against remediation_requests' four run-id columns, not on
// this prefix, so it's not load-bearing for correctness.
func (h *Handler) dispatchRemediationStep(ctx context.Context, agentID, scenarioIDPrefix, remediationID, command, executor string, timeoutSec int) (runID string, sent bool, err error) {
	scenarioID := scenarioIDPrefix + ":" + remediationID

	var agentOS string
	h.db.QueryRow(ctx, `SELECT COALESCE(os_version,'windows') FROM agents WHERE agent_id=$1`, agentID).Scan(&agentOS)

	sc := &scenario.Scenario{
		ID:         scenarioID,
		Name:       scenarioIDPrefix,
		LocalCheck: true,
		Steps: []scenario.Step{{
			Name:       scenarioID,
			Framework:  "custom",
			Executor:   executor,
			Command:    command,
			TimeoutSec: timeoutSec,
		}},
	}
	steps, err := scenario.BuildSteps(sc, h.calderaURL, h.calderaKey, h.artStore, agentOS)
	if err != nil {
		return "", false, err
	}

	runID = newID()
	if _, err = h.db.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
		 VALUES ($1, $2, $3, $4, 'running', NOW())`,
		runID, sc.ID, agentID, sc.Name,
	); err != nil {
		return "", false, err
	}
	h.persistStepMeta(ctx, runID, steps)

	cmd := scenario.ScenarioCommand{RunID: runID, ScenarioID: sc.ID, Name: sc.Name, Steps: steps}
	sent = h.hub.SendToAgent(agentID, models.WSMessage{Type: models.MsgCommandScenario, AgentID: agentID, Data: cmd})
	if !sent {
		h.db.Exec(context.Background(), `UPDATE scenario_runs SET status='failed', completed_at=NOW() WHERE id=$1`, runID)
	}
	return runID, sent, nil
}

// latestCheckIsPassing reports whether the most recent result for checkID
// in allResults is a PASS -- used as the "already compliant" pre-flight
// check before dispatching a fix.
func latestCheckIsPassing(allResults []models.SimulationResult, checkID string) bool {
	var latest *models.SimulationResult
	for i := range allResults {
		r := &allResults[i]
		if r.CheckID != checkID {
			continue
		}
		if latest == nil || r.ExecutedAt.After(latest.ExecutedAt) {
			latest = r
		}
	}
	return latest != nil && latest.Result == models.ResultPass
}
