package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/jobs"
)

// scheduledAssessmentPayload is the Job.Payload shape for
// Type="scheduled_assessment". Mode is always "posture" or "telemetry" --
// lab mode is rejected at schedule-creation time (see
// CreateScheduledAssessment), so it can never reach this dispatch function.
type scheduledAssessmentPayload struct {
	ScenarioID string   `json:"scenarioId"`
	Mode       string   `json:"mode"`
	Techniques []string `json:"techniques,omitempty"`
	Steps      []int    `json:"steps,omitempty"`
}

// dispatchScheduledAssessmentTarget is injected into jobs.Dispatcher via
// SetDispatch (see WithJobsDispatcher). It reuses dispatchRun -- the exact
// per-agent dispatch core RunScenario and campaign fan-out already share --
// so a scheduled assessment's actual execution is indistinguishable from an
// interactive run. The one guard dispatchRun does NOT itself apply (it's
// only checked in RunScenario, its HTTP caller) is the scenario's live
// execution-window policy; replicated here so telemetry-mode scheduled runs
// respect it exactly like an interactive telemetry run would.
func (h *Handler) dispatchScheduledAssessmentTarget(ctx context.Context, job jobs.Job, target jobs.JobTarget) (refID string, err error) {
	var payload scheduledAssessmentPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return "", err
	}
	// Resolve the executable version once, before any side effect, and judge
	// every policy check against the pinned bytes that will run -- never a
	// newer on-disk DRAFT. A denial carries the "content not executable: "
	// text so the jobs failure + notification path reports it verbatim.
	ev, gerr := h.engine.ResolveExecutable(ctx, payload.ScenarioID)
	if gerr != nil {
		var ne *contentregistry.ErrNotExecutable
		if errors.As(gerr, &ne) && ne.Reason == "not registered" {
			if _, onDisk := h.engine.Get(payload.ScenarioID); !onDisk {
				return "", errors.New("scenario not found")
			}
		}
		return "", errors.New("content not executable: " + strings.TrimPrefix(gerr.Error(), "content not executable: "))
	}
	sc := ev.Scenario
	for _, idx := range payload.Steps {
		if idx < 0 || idx >= len(sc.Steps) {
			return "", fmt.Errorf("step index %d out of range — scenario has %d step(s)", idx, len(sc.Steps))
		}
	}

	live := payload.Mode == "telemetry"
	if live && !sc.Executable {
		return "", errors.New("scenario does not support live execution — run it in posture mode")
	}
	if live && sc.LivePolicy != nil && sc.LivePolicy.ExecutionWindow != "" {
		within, werr := withinWindow(sc.LivePolicy.ExecutionWindow, time.Now())
		if werr != nil {
			return "", fmt.Errorf("invalid execution_window in scenario policy: %w", werr)
		}
		if !within {
			return "", errors.New("outside the approved execution window for live execution")
		}
	}

	createdBy := job.CreatedBy
	runID, skip, dispatchErr := h.dispatchRun(ctx, sc, target.AgentID, dispatchOpts{
		Mode: payload.Mode, ConfirmLive: live, Techniques: payload.Techniques, Steps: payload.Steps,
		InitiatedBy: &createdBy, RunLabel: "Scheduled: " + sc.Name,
		Resolved: &ev,
	})
	if dispatchErr != nil {
		return "", dispatchErr
	}
	if skip != "" {
		return "", errors.New(skip)
	}
	return runID, nil
}

// scheduledAssessmentTargetStatus is injected into jobs.Dispatcher via
// SetStatus. It polls the scenario_runs row created for this target
// (refID) -- same poll-by-refID shape as batchRemediationTargetStatus.
func (h *Handler) scheduledAssessmentTargetStatus(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool) {
	var status string
	if err := h.db.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id=$1`, refID).Scan(&status); err != nil {
		return jobs.TargetStateFailed, "scenario run not found: " + err.Error(), true
	}
	switch status {
	case "completed":
		return jobs.TargetStateCompleted, "", true
	case "failed", "partial":
		return jobs.TargetStateFailed, "", true
	default: // "running"
		return jobs.TargetStateDispatched, "", false
	}
}
