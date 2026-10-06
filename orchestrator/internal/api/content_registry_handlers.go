package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
	"github.com/jackc/pgx/v5"
)

type DriftReport struct {
	RunID  string                      `json:"runId"`
	Status string                      `json:"status"` // checked | not_applicable | unversioned | unreadable
	Items  []contentregistry.DriftItem `json:"items,omitempty"`
	// Reason explains a checked report that could not compare (all
	// DRIFT_UNKNOWN, or no items at all).
	Reason string `json:"reason,omitempty"`
}

// checkRunDrift rebuilds the run's pinned version under the current
// ART/Caldera catalogs (full version, no subset: the rebuild is a superset
// of any subset run) and compares resolved hashes by TaskID. The rebuild
// platform is the recorded dispatch platform, never a guess.
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
	if len(metaRaw) > 0 {
		if err := json.Unmarshal(metaRaw, &hist); err != nil {
			return rep, fmt.Errorf("decode step_meta: %w", err)
		}
	}
	rep.Status = "checked"
	if len(hist) == 0 {
		rep.Reason = "no step metadata recorded"
		return rep, nil
	}
	unknown := func(reason string) DriftReport {
		rep.Reason = reason
		for id, m := range hist {
			rep.Items = append(rep.Items, contentregistry.DriftItem{TaskID: id, Status: "DRIFT_UNKNOWN",
				HistoricalVersion: m.ComponentVersion})
		}
		sort.Slice(rep.Items, func(i, j int) bool { return rep.Items[i].TaskID < rep.Items[j].TaskID })
		return rep
	}

	platforms := map[string]struct{}{}
	for _, m := range hist {
		// An unconfigured source must never read as drift.
		switch m.Component {
		case "caldera":
			if h.calderaURL == "" {
				return rep, errors.New("drift check: run has Caldera steps but Caldera is not configured")
			}
		case "art":
			if h.artStore == nil {
				return rep, errors.New("drift check: run has ART steps but the ART store is not configured")
			}
		}
		if m.Platform != "" {
			platforms[m.Platform] = struct{}{}
		}
	}
	var platform string
	switch len(platforms) {
	case 0:
		// Pre-stamping runs: fall back to the dispatching agent's OS.
		var osv string
		if err := h.db.QueryRow(ctx,
			`SELECT COALESCE(os_version,'') FROM agents WHERE agent_id = (SELECT agent_id FROM scenario_runs WHERE id = $1)`,
			runID).Scan(&osv); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return rep, err
		}
		platform = classifyAgentOS(osv)
		if platform == "" {
			return unknown("dispatch platform unknown"), nil
		}
	case 1:
		for p := range platforms {
			platform = p
		}
	default:
		return unknown("mixed dispatch platforms"), nil
	}
	steps, _, err := scenario.BuildSteps(rc.Scenario, h.calderaURL, h.calderaKey, h.artStore, platform)
	if err != nil {
		return rep, err
	}
	rep.Items = contentregistry.CompareDrift(hist, scenario.ResolvedHashes(steps), h.componentVersions(ctx))
	return rep, nil
}
