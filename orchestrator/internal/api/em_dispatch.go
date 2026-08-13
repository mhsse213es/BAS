package api

import (
	"context"
	"fmt"
	"log"
)

// dispatchEMLayer is the emsweep.DispatchFn implementation -- looks up the
// layer's scenario and dispatches it via the same dispatchRun core
// RunScenario, campaign fan-out, and scheduled assessments all share. Much
// simpler than vexsweep's dispatchVariantForSweep: an EM layer is one plain
// posture scenario, not an ART technique needing variant-template
// resolution.
func (h *Handler) dispatchEMLayer(ctx context.Context, sweepID, agentID, scenarioID string) (scenarioRunID string, err error) {
	sc, ok := h.engine.Get(scenarioID)
	if !ok {
		return "", fmt.Errorf("EM layer scenario %q not found", scenarioID)
	}
	runID, skip, err := h.dispatchRun(ctx, sc, agentID, dispatchOpts{Mode: "posture"})
	if err != nil {
		return "", err
	}
	if skip != "" {
		return "", fmt.Errorf("layer skipped: %s", skip)
	}
	if _, err := h.db.Exec(ctx, `UPDATE scenario_runs SET em_sweep_id = $1 WHERE id = $2`, sweepID, runID); err != nil {
		log.Printf("[emsweep] tag run %s with sweep %s: %v", runID, sweepID, err)
	}
	return runID, nil
}
