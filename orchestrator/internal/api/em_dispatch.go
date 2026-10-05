package api

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/audspect/bas/internal/emsweep"
)

// emLayerNumRe pulls the layer number out of a fixed-catalog EM scenario id
// (e.g. "em-01-control-validation" -> "01"). An extra scenario added via the
// Full Sweep picker won't match -- emSweepLayerLabel falls back to its own
// name for those, since it has no EM layer number.
var emLayerNumRe = regexp.MustCompile(`^em-(\d+)-`)

func emSweepLayerLabel(scenarioID, scenarioName string) string {
	if m := emLayerNumRe.FindStringSubmatch(scenarioID); m != nil {
		return "EM " + m[1]
	}
	if scenarioName != "" {
		return scenarioName
	}
	return scenarioID
}

// dispatchEMLayer is the emsweep.DispatchFn implementation -- looks up the
// layer's scenario and dispatches it via the same dispatchRun core
// RunScenario, campaign fan-out, and scheduled assessments all share. Much
// simpler than vexsweep's dispatchVariantForSweep: an EM layer is one plain
// posture scenario, not an ART technique needing variant-template
// resolution.
func (h *Handler) dispatchEMLayer(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (scenarioRunID string, err error) {
	if _, ok := h.engine.Get(scenarioID); !ok {
		return "", fmt.Errorf("EM layer scenario %q not found", scenarioID)
	}
	// Resolve once so the sweep label names the pinned version that runs. A
	// gate denial surfaces like any other skip: the dispatcher marks the
	// sweep failed with this text (em_sweeps.error, shown by the sweep API).
	ev, gerr := h.engine.ResolveExecutable(ctx, scenarioID)
	if gerr != nil {
		return "", fmt.Errorf("layer skipped: content not executable: %s", strings.TrimPrefix(gerr.Error(), "content not executable: "))
	}
	sc := ev.Scenario
	runID, skip, err := h.dispatchRun(ctx, sc, agentID, dispatchOpts{
		Resolved:   &ev,
		Mode:       "posture",
		SweepID:    sweepID,
		SweepName:  "EM Full Sweep",
		SweepLabel: emSweepLayerLabel(scenarioID, sc.Name),
		SweepFinal: layerIndex == totalLayers-1,
	})
	if err != nil {
		return "", err
	}
	if skip == "offline" {
		return "", emsweep.ErrAgentOffline
	}
	if skip != "" {
		return "", fmt.Errorf("layer skipped: %s", skip)
	}
	if _, err := h.db.Exec(ctx, `UPDATE scenario_runs SET em_sweep_id = $1 WHERE id = $2`, sweepID, runID); err != nil {
		log.Printf("[emsweep] tag run %s with sweep %s: %v", runID, sweepID, err)
	}
	return runID, nil
}
