package api

import (
	"context"
	"encoding/json"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
)

type DriftReport struct {
	RunID  string                      `json:"runId"`
	Status string                      `json:"status"` // checked | not_applicable | unversioned | unreadable
	Items  []contentregistry.DriftItem `json:"items,omitempty"`
}

// checkRunDrift rebuilds the run's pinned version under the current
// ART/Caldera catalogs (full version, no subset: the rebuild is a superset
// of any subset run) and compares resolved hashes by TaskID.
func (h *Handler) checkRunDrift(ctx context.Context, runID string) (DriftReport, error) {
	rc := h.runContent(ctx, runID)
	rep := DriftReport{RunID: runID}
	switch rc.Status {
	case contentregistry.RunSynthetic:
		rep.Status = "not_applicable"
		return rep, nil
	case contentregistry.RunUnversioned:
		rep.Status = "unversioned"
		return rep, nil
	case contentregistry.RunUnreadable:
		if rc.Transient {
			// Infrastructure failure, not a verdict on the content: surface
			// it as an error rather than a permanent "unreadable" status.
			return rep, rc.Err
		}
		rep.Status = "unreadable"
		return rep, nil
	}
	var metaRaw []byte
	if err := h.db.QueryRow(ctx, `SELECT step_meta FROM scenario_runs WHERE id = $1`, runID).Scan(&metaRaw); err != nil {
		return rep, err
	}
	hist := map[string]scenario.StepMeta{}
	_ = json.Unmarshal(metaRaw, &hist)
	platform := "windows"
	for _, m := range hist {
		if m.Platform != "" {
			platform = m.Platform
			break
		}
	}
	steps, _, err := scenario.BuildSteps(rc.Scenario, h.calderaURL, h.calderaKey, h.artStore, platform)
	if err != nil {
		return rep, err
	}
	rep.Status = "checked"
	rep.Items = contentregistry.CompareDrift(hist, scenario.ResolvedHashes(steps), h.componentVersions(ctx))
	return rep, nil
}
