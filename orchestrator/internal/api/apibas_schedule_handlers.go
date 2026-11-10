package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	apibasjobs "github.com/audspect/bas/internal/apibas/jobs"
	"github.com/audspect/bas/internal/apibas/binding"
	"github.com/audspect/bas/internal/apibas/openapi"
	"github.com/audspect/bas/internal/apibas/runnerproto"
	"github.com/audspect/bas/internal/db"
)

// buildBoundPlanError carries the HTTP status and message a failed plan build maps to, so the manual run and the scheduler refuse
// stored test data for the same reasons.
type buildBoundPlanError struct {
	Status int
	Msg    string
}

func (e *buildBoundPlanError) Error() string { return e.Msg }

// buildBoundPlan reads a target's stored test data and newest inventory and returns the plan a bound job runs. It refuses test data
// that was checked against an older inventory than the newest. With includeWrites false, write scenarios in the stored data are
// left out: the copy of the spec used here has allow_writes cleared, and the stored spec is not changed.
func (h *Handler) buildBoundPlan(ctx context.Context, targetID string, includeWrites bool) (runnerproto.BoundPlan, error) {
	stored, err := db.GetAPIBASBinding(ctx, h.db, targetID)
	if errors.Is(err, db.ErrAPIBASBindingNotFound) {
		return runnerproto.BoundPlan{}, &buildBoundPlanError{http.StatusNotFound, "no test data stored for this target"}
	}
	if err != nil {
		return runnerproto.BoundPlan{}, &buildBoundPlanError{http.StatusInternalServerError, "could not read the test data"}
	}
	spec, err := decodeBindingSpec(stored.Spec)
	if err != nil {
		return runnerproto.BoundPlan{}, &buildBoundPlanError{http.StatusInternalServerError, "the stored test data is unreadable"}
	}
	rec, err := db.GetAPIBASInventory(ctx, h.db, targetID, 0)
	if errors.Is(err, db.ErrAPIBASInventoryNotFound) {
		return runnerproto.BoundPlan{}, &buildBoundPlanError{http.StatusNotFound, "no inventory for this target"}
	}
	if err != nil {
		return runnerproto.BoundPlan{}, &buildBoundPlanError{http.StatusInternalServerError, "could not read the inventory"}
	}
	if rec.Version != stored.ValidatedInventory {
		return runnerproto.BoundPlan{}, &buildBoundPlanError{http.StatusConflict, "the test data was checked against an older inventory; save it again first"}
	}
	var inv openapi.Inventory
	if err := json.Unmarshal(rec.Body, &inv); err != nil {
		return runnerproto.BoundPlan{}, &buildBoundPlanError{http.StatusInternalServerError, "the stored inventory is unreadable"}
	}
	if !includeWrites {
		spec = withoutWrites(spec)
	}
	return runnerproto.BoundPlan{InventoryVersion: rec.Version, Inventory: inv, Spec: spec}, nil
}

// withoutWrites returns a copy of the spec that attempts no write: objects that carry a write block and every mass-assignment check
// are left out, and allow_writes is cleared. Clearing allow_writes alone would make the spec invalid, because a write block needs it.
func withoutWrites(spec binding.Spec) binding.Spec {
	out := spec
	out.AllowWrites = false
	out.Objects = make([]binding.ObjectSpec, 0, len(spec.Objects))
	for _, ob := range spec.Objects {
		if ob.Write == nil {
			out.Objects = append(out.Objects, ob)
		}
	}
	out.MassAssignments = nil
	return out
}

// apibasScheduleBody is what a caller chooses when scheduling a target's stored test data.
type apibasScheduleBody struct {
	// EveryHours is the interval between runs, 1 to 720. The first run is one interval from now.
	EveryHours int `json:"every_hours"`
	// At, Timezone and Days schedule a time of day instead of an interval: At is "HH:MM" (24 hour), Timezone an IANA name (default
	// UTC), Days a list of sun..sat (default every day). Give either every_hours or at, not both. The first run is the next time the
	// clock reaches At.
	At       string   `json:"at"`
	Timezone string   `json:"timezone"`
	Days     []string `json:"days"`
	// IncludeWrites lets scheduled runs include the write scenarios in the stored test data. Off by default: a write that succeeds
	// changes the customer's object, and nobody is watching a scheduled run.
	IncludeWrites bool `json:"include_writes"`
	// Enabled defaults to true. A schedule that paused itself after repeated failures is resumed by saving it again.
	Enabled *bool `json:"enabled"`
}

type apibasScheduleView struct {
	TargetID            string     `json:"target_id"`
	EveryHours          int        `json:"every_hours,omitempty"`
	At                  string     `json:"at,omitempty"`
	Timezone            string     `json:"timezone,omitempty"`
	Days                []string   `json:"days,omitempty"`
	IncludeWrites       bool       `json:"include_writes"`
	Enabled             bool       `json:"enabled"`
	NextRunAt           time.Time  `json:"next_run_at"`
	CreatedBy           string     `json:"created_by"`
	LastRunAt           *time.Time `json:"last_run_at,omitempty"`
	LastJobID           string     `json:"last_job_id,omitempty"`
	LastResult          string     `json:"last_result,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	// PausedForFailures is true when the schedule turned itself off after repeated failures to queue its job.
	PausedForFailures bool `json:"paused_for_failures,omitempty"`
}

func scheduleView(s db.APIBASSchedule) apibasScheduleView {
	every := s.EveryHours
	var days []string
	if s.AtTime != "" {
		every = 0
		if s.Days != "" {
			days = strings.Split(s.Days, ",")
		}
	}
	return apibasScheduleView{
		TargetID: s.TargetID, EveryHours: every, At: s.AtTime, Timezone: s.Timezone, Days: days, IncludeWrites: s.IncludeWrites, Enabled: s.Enabled, NextRunAt: s.NextRunAt,
		CreatedBy: s.CreatedBy, LastRunAt: s.LastRunAt, LastJobID: s.LastJobID, LastResult: s.LastResult,
		ConsecutiveFailures: s.ConsecutiveFailures, PausedForFailures: !s.Enabled && s.ConsecutiveFailures >= db.APIBASScheduleMaxFailures,
	}
}

// SaveAPIBASSchedule creates or replaces a target's schedule. PUT /api/apibas/targets/{id}/schedule
//
// Only lab and staging targets can be scheduled: a production run needs a fresh approval by a second person each time, which a
// schedule cannot give. The target needs stored test data. Including writes needs the target to register allowed paths, as a manual
// write run does.
func (h *Handler) SaveAPIBASSchedule(w http.ResponseWriter, r *http.Request) {
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var body apibasScheduleBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	every, first, days := body.EveryHours, time.Time{}, ""
	if body.At != "" {
		if body.EveryHours != 0 {
			jsonError(w, "give either every_hours or at, not both", http.StatusBadRequest)
			return
		}
		if body.Timezone == "" {
			body.Timezone = "UTC"
		}
		var derr error
		if days, derr = db.NormalizeClockDays(body.Days); derr != nil {
			jsonError(w, derr.Error(), http.StatusBadRequest)
			return
		}
		var cerr error
		if first, cerr = db.NextClockRun(now, body.At, body.Timezone, days); cerr != nil {
			jsonError(w, cerr.Error(), http.StatusBadRequest)
			return
		}
		every = 24
	} else {
		if body.Timezone != "" || len(body.Days) > 0 {
			jsonError(w, "timezone and days go with at", http.StatusBadRequest)
			return
		}
		if body.EveryHours < 1 || body.EveryHours > 720 {
			jsonError(w, "every_hours must be between 1 and 720, or give at", http.StatusBadRequest)
			return
		}
		first = now.Add(time.Duration(body.EveryHours) * time.Hour)
	}
	id := chi.URLParam(r, "id")
	t, err := db.GetAPIBASTarget(r.Context(), h.db, id)
	if errors.Is(err, db.ErrAPIBASTargetNotFound) {
		jsonError(w, "target not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not read target", http.StatusInternalServerError)
		return
	}
	if t.Environment != "lab" && t.Environment != "staging" {
		jsonError(w, "only lab and staging targets can be scheduled; a production run needs its own approval each time", http.StatusBadRequest)
		return
	}
	if _, err := db.GetAPIBASBinding(r.Context(), h.db, id); errors.Is(err, db.ErrAPIBASBindingNotFound) {
		jsonError(w, "store test data for this target before scheduling it", http.StatusConflict)
		return
	} else if err != nil {
		jsonError(w, "could not read the test data", http.StatusInternalServerError)
		return
	}
	if body.IncludeWrites && len(t.AllowedPaths) == 0 {
		jsonError(w, "including writes needs the target to register allowed paths", http.StatusBadRequest)
		return
	}
	enabled := body.Enabled == nil || *body.Enabled
	saved, err := db.PutAPIBASSchedule(r.Context(), h.db, db.APIBASSchedule{
		TargetID: id, EveryHours: every, IncludeWrites: body.IncludeWrites, Enabled: enabled,
		NextRunAt: first, CreatedBy: actor, AtTime: body.At, Timezone: body.Timezone, Days: days,
	})
	if errors.Is(err, db.ErrAPIBASTargetNotFound) {
		jsonError(w, "target not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not store the schedule", http.StatusInternalServerError)
		return
	}
	if aerr := h.auditDurable(r.Context(), actor, "apibas.schedule.set", "apibas-target:"+id, map[string]any{
		"every_hours": scheduleView(saved).EveryHours, "at": saved.AtTime, "timezone": saved.Timezone, "days": saved.Days,
		"include_writes": saved.IncludeWrites, "enabled": saved.Enabled,
	}, "success"); aerr != nil {
		jsonError(w, "the schedule was stored but its audit record could not be written", http.StatusInternalServerError)
		return
	}
	apibasRespond(w, http.StatusOK, scheduleView(saved))
}

// GetAPIBASSchedule returns a target's schedule. GET /api/apibas/targets/{id}/schedule
func (h *Handler) GetAPIBASSchedule(w http.ResponseWriter, r *http.Request) {
	s, err := db.GetAPIBASSchedule(r.Context(), h.db, chi.URLParam(r, "id"))
	if errors.Is(err, db.ErrAPIBASScheduleNotFound) {
		jsonError(w, "no schedule for this target", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not read the schedule", http.StatusInternalServerError)
		return
	}
	respond(w, scheduleView(s))
}

// DeleteAPIBASSchedule removes a target's schedule. DELETE /api/apibas/targets/{id}/schedule
func (h *Handler) DeleteAPIBASSchedule(w http.ResponseWriter, r *http.Request) {
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	existed, err := db.DeleteAPIBASSchedule(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, "could not remove the schedule", http.StatusInternalServerError)
		return
	}
	if !existed {
		jsonError(w, "no schedule for this target", http.StatusNotFound)
		return
	}
	if aerr := h.auditDurable(r.Context(), actor, "apibas.schedule.delete", "apibas-target:"+id, map[string]any{}, "success"); aerr != nil {
		jsonError(w, "the schedule was removed but its audit record could not be written", http.StatusInternalServerError)
		return
	}
	apibasRespond(w, http.StatusOK, map[string]any{"removed": true})
}

// RunDueAPIBASSchedules claims the schedules due at now and queues one job for each. It returns how many it claimed.
func (h *Handler) RunDueAPIBASSchedules(ctx context.Context, now time.Time) (int, error) {
	due, err := db.ClaimDueAPIBASSchedules(ctx, h.db, now, 20)
	if err != nil {
		return 0, err
	}
	for _, s := range due {
		h.runScheduled(ctx, s)
	}
	return len(due), nil
}

// runScheduled queues and starts the job for one claimed schedule, then records what happened. The job goes through the same
// submission checks as a manual run (enabled target, permitted environment, registered host and credentials, path scope, one active
// job per target), and is audited as submitted by the person who created the schedule, marked scheduled.
func (h *Handler) runScheduled(ctx context.Context, s db.APIBASSchedule) {
	fail := func(result string) {
		_ = db.RecordAPIBASScheduleResult(ctx, h.db, s.TargetID, "", truncateResult(result), true)
	}
	if h.apibasJobs == nil {
		fail("job execution is not configured on this server")
		return
	}
	actor := "schedule:" + s.CreatedBy
	plan, err := h.buildBoundPlan(ctx, s.TargetID, s.IncludeWrites)
	if err != nil {
		fail("not run: " + err.Error())
		return
	}
	key := fmt.Sprintf("sched-%s-%d", s.TargetID, s.DueAt.Unix())
	job, created, err := h.apibasJobs.SubmitForTarget(ctx, apibasjobs.TargetRequest{Key: key, RequestedBy: actor, TargetID: s.TargetID, Bound: &plan})
	if errors.Is(err, db.ErrAPIBASTargetBusy) {
		// Another assessment is running on the target. That is not a fault of the schedule: skip this run and try at the next interval.
		_ = db.RecordAPIBASScheduleResult(ctx, h.db, s.TargetID, "", "skipped: another assessment was running on the target", false)
		return
	}
	if err != nil {
		fail("not run: " + err.Error())
		return
	}
	if !created {
		_ = db.RecordAPIBASScheduleResult(ctx, h.db, s.TargetID, job.ID, "this run was already queued", false)
		return
	}
	if aerr := h.auditDurable(ctx, actor, "apibas.job.submit", "apibas-job:"+job.ID, map[string]any{
		"target_id": job.TargetID, "environment": job.Environment, "base_url": job.TargetBaseURL, "scenario_ids": job.ScenarioIDs,
		"fixture": job.Fixture, "job_key": job.JobKey, "scheduled": true, "every_hours": s.EveryHours, "include_writes": s.IncludeWrites,
	}, "success"); aerr != nil {
		bg := context.WithoutCancel(ctx)
		if ok, _ := db.StartAPIBASJob(bg, h.db, job.ID); ok {
			_ = db.FinishAPIBASJob(bg, h.db, job.ID, "failed", "audit record could not be written", nil)
		}
		fail("not run: the audit record could not be written")
		return
	}
	jobID := job.ID
	h.apibasAsync(func() { h.runAPIBASJob(actor, jobID) })
	_ = db.RecordAPIBASScheduleResult(ctx, h.db, s.TargetID, job.ID, "queued", false)
}

func truncateResult(s string) string {
	if len(s) > 300 {
		return s[:300]
	}
	return s
}

// StartAPIBASScheduler runs due schedules every interval until ctx ends. A tick that finds nothing due does nothing.
func (h *Handler) StartAPIBASScheduler(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				_, _ = h.RunDueAPIBASSchedules(ctx, now.UTC())
			}
		}
	}()
}
