package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
)

// scheduledTarget registers a lab target with an inventory and stored test data, ready to schedule.
func scheduledTarget(t *testing.T, h http.Handler, id string) {
	t.Helper()
	if rec := postAs(t, h, "/api/apibas/targets", boundTargetBody(id, "shop/alice", "shop/bob"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register %s: %d %s", id, rec.Code, rec.Body.String())
	}
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/"+id+"/inventory", specBytes(t), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import %s: %d", id, rec.Code)
	}
	if rec := putAs(t, h, "/api/apibas/targets/"+id+"/binding", bindSpecWith("shop/alice", "shop/bob"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK {
		t.Fatalf("save binding %s: %d %s", id, rec.Code, rec.Body.String())
	}
}

// makeDue makes the schedule due. Each call uses a different time in the past, as real runs do, because the job key is derived from
// the time a run was due.
var dueOffset int

func makeDue(t *testing.T, id string) {
	t.Helper()
	dueOffset++
	if _, err := sharedDB.Pool.Exec(context.Background(), `UPDATE apibas_schedules SET next_run_at = NOW() - make_interval(mins => $2) WHERE target_id = $1`, id, dueOffset); err != nil {
		t.Fatal(err)
	}
}

func TestAPIBASScheduleSaveRules(t *testing.T) {
	hd := jobsHandler(t, true)
	h := jobsRouter(hd)
	path := func(id string) string { return "/api/apibas/targets/" + id + "/schedule" }

	// No target, no test data.
	if rec := putAs(t, h, path("nope"), map[string]any{"every_hours": 24}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown target: %d, want 404", rec.Code)
	}
	if rec := postAs(t, h, "/api/apibas/targets", boundTargetBody("sch-1", "shop/alice", "shop/bob"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d", rec.Code)
	}
	if rec := putAs(t, h, path("sch-1"), map[string]any{"every_hours": 24}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusConflict {
		t.Errorf("no stored test data: %d, want 409", rec.Code)
	}
	scheduledTarget(t, h, "sch-2")

	// Validation.
	for name, body := range map[string]any{
		"zero hours": map[string]any{"every_hours": 0}, "too many hours": map[string]any{"every_hours": 721},
		"missing hours": map[string]any{}, "unknown field": map[string]any{"every_hours": 24, "run_as": "root"},
		"writes without allowed paths": map[string]any{"every_hours": 24, "include_writes": true},
	} {
		if rec := putAs(t, h, path("sch-2"), body, auth.RoleAdmin, "admin1"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rec.Code)
		}
	}
	// A production target cannot be scheduled: its runs need a fresh second-person approval each time.
	if rec := postAs(t, h, "/api/apibas/targets", targetBody("sch-prod", "production"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register production: %d %s", rec.Code, rec.Body.String())
	}
	if rec := putAs(t, h, path("sch-prod"), map[string]any{"every_hours": 24}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "production") {
		t.Errorf("production schedule: %d %s", rec.Code, rec.Body.String())
	}

	// Authorization: only a target manager changes a schedule; a viewer of runs reads it.
	if rec := putAs(t, h, path("sch-2"), map[string]any{"every_hours": 24}, auth.RoleViewer, "v1"); rec.Code != http.StatusForbidden {
		t.Errorf("viewer save: %d, want 403", rec.Code)
	}
	if rec := putAs(t, h, path("sch-2"), map[string]any{"every_hours": 24}, auth.RoleAnalyst, "a1"); rec.Code != http.StatusForbidden {
		t.Errorf("analyst save: %d, want 403", rec.Code)
	}
	if rec := getAsUser(t, h, path("sch-2"), auth.RoleAnalyst, "a1"); rec.Code != http.StatusNotFound {
		t.Errorf("read before save: %d, want 404", rec.Code)
	}

	// Save, read, replace, remove.
	before := time.Now()
	rec := putAs(t, h, path("sch-2"), map[string]any{"every_hours": 6}, auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	got := decode(t, rec)
	next, _ := time.Parse(time.RFC3339Nano, got["next_run_at"].(string))
	if got["every_hours"] != float64(6) || got["include_writes"] != false || got["enabled"] != true || got["created_by"] != "admin1" ||
		next.Before(before.Add(6*time.Hour-time.Minute)) || next.After(time.Now().Add(6*time.Hour+time.Minute)) {
		t.Errorf("saved schedule: %v", got)
	}
	if rec := getAsUser(t, h, path("sch-2"), auth.RoleAnalyst, "a1"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"every_hours":6`) {
		t.Errorf("read: %d %s", rec.Code, rec.Body.String())
	}
	if rec := putAs(t, h, path("sch-2"), map[string]any{"every_hours": 12, "enabled": false}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK || decode(t, rec)["enabled"] != false {
		t.Errorf("replace: %d %s", rec.Code, rec.Body.String())
	}
	if rec := sendRaw(t, h, http.MethodDelete, path("sch-2"), "", auth.RoleAnalyst, "a1"); rec.Code != http.StatusForbidden {
		t.Errorf("analyst delete: %d, want 403", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodDelete, path("sch-2"), "", auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK {
		t.Errorf("delete: %d", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodDelete, path("sch-2"), "", auth.RoleAdmin, "admin1"); rec.Code != http.StatusNotFound {
		t.Errorf("second delete: %d, want 404", rec.Code)
	}
}

func TestAPIBASScheduledRunQueuesOneJobPerDueRun(t *testing.T) {
	hd := jobsHandler(t, true)
	h := jobsRouter(hd)
	ctx := context.Background()
	scheduledTarget(t, h, "sch-run")
	if rec := putAs(t, h, "/api/apibas/targets/sch-run/schedule", map[string]any{"every_hours": 1}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK {
		t.Fatalf("save: %d", rec.Code)
	}

	// Not due yet: nothing runs.
	if n, err := hd.RunDueAPIBASSchedules(ctx, time.Now().UTC()); err != nil || n != 0 {
		t.Fatalf("not due: %d %v", n, err)
	}
	makeDue(t, "sch-run")
	if n, err := hd.RunDueAPIBASSchedules(ctx, time.Now().UTC()); err != nil || n != 1 {
		t.Fatalf("due: %d %v", n, err)
	}
	s, err := db.GetAPIBASSchedule(ctx, sharedDB.Pool, "sch-run")
	if err != nil {
		t.Fatal(err)
	}
	if s.LastResult != "queued" || s.LastJobID == "" || s.ConsecutiveFailures != 0 || !s.Enabled {
		t.Fatalf("after a due run: %+v", s)
	}
	if s.NextRunAt.Before(time.Now().Add(55*time.Minute)) || s.NextRunAt.After(time.Now().Add(65*time.Minute)) {
		t.Errorf("next run is %s, want about an hour from now (a missed run is run once, not made up)", s.NextRunAt)
	}
	job, err := db.GetAPIBASJob(ctx, sharedDB.Pool, s.LastJobID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(job.JobKey, "sched-sch-run-") || job.RequestedBy != "schedule:admin1" || !strings.HasPrefix(job.Fixture, "bound:") || job.Status != "queued" {
		t.Errorf("scheduled job: key %q requested_by %q fixture %q status %q", job.JobKey, job.RequestedBy, job.Fixture, job.Status)
	}
	if _, err := db.GetAPIBASJobPlan(ctx, sharedDB.Pool, job.ID); err != nil {
		t.Errorf("the plan was not stored with the scheduled job: %v", err)
	}
	// Claiming again at the same moment finds nothing: one run, one job.
	if n, _ := hd.RunDueAPIBASSchedules(ctx, time.Now().UTC()); n != 0 {
		t.Errorf("a claimed run was claimed again: %d", n)
	}

	// The previous job is still queued, so the next due run is skipped: not a fault of the schedule.
	makeDue(t, "sch-run")
	if n, _ := hd.RunDueAPIBASSchedules(ctx, time.Now().UTC()); n != 1 {
		t.Fatalf("second due run: %d", n)
	}
	s, _ = db.GetAPIBASSchedule(ctx, sharedDB.Pool, "sch-run")
	if !strings.HasPrefix(s.LastResult, "skipped:") || s.ConsecutiveFailures != 0 || !s.Enabled {
		t.Errorf("busy target: %+v", s)
	}
}

func TestAPIBASScheduleStaleDataPausesAfterRepeatedFailuresAndResumes(t *testing.T) {
	hd := jobsHandler(t, true)
	h := jobsRouter(hd)
	ctx := context.Background()
	scheduledTarget(t, h, "sch-stale")
	if rec := putAs(t, h, "/api/apibas/targets/sch-stale/schedule", map[string]any{"every_hours": 1}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK {
		t.Fatalf("save: %d", rec.Code)
	}
	// A newer inventory makes the stored test data stale, so a due run cannot be queued.
	changed := strings.Replace(specBytes(t), "/v2/catalog", "/v2/catalogue", 1)
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/sch-stale/inventory", changed, auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("second import: %d", rec.Code)
	}
	for i := 1; i <= db.APIBASScheduleMaxFailures; i++ {
		makeDue(t, "sch-stale")
		if n, _ := hd.RunDueAPIBASSchedules(ctx, time.Now().UTC()); n != 1 {
			t.Fatalf("run %d: claimed %d", i, n)
		}
		s, _ := db.GetAPIBASSchedule(ctx, sharedDB.Pool, "sch-stale")
		if !strings.HasPrefix(s.LastResult, "not run:") || !strings.Contains(s.LastResult, "older inventory") || s.ConsecutiveFailures != i {
			t.Fatalf("run %d: %+v", i, s)
		}
		if wantEnabled := i < db.APIBASScheduleMaxFailures; s.Enabled != wantEnabled {
			t.Fatalf("run %d: enabled=%v, want %v", i, s.Enabled, wantEnabled)
		}
	}
	// Paused: a due time passes and nothing is claimed.
	makeDue(t, "sch-stale")
	if n, _ := hd.RunDueAPIBASSchedules(ctx, time.Now().UTC()); n != 0 {
		t.Errorf("a paused schedule ran: %d", n)
	}
	view := getAsUser(t, h, "/api/apibas/targets/sch-stale/schedule", auth.RoleAnalyst, "a1").Body.String()
	if !strings.Contains(view, `"paused_for_failures":true`) {
		t.Errorf("a paused schedule does not say so: %s", view)
	}
	// Saving the schedule again resumes it and clears the count.
	if rec := putAs(t, h, "/api/apibas/targets/sch-stale/schedule", map[string]any{"every_hours": 1}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK {
		t.Fatalf("resume: %d", rec.Code)
	}
	s, _ := db.GetAPIBASSchedule(ctx, sharedDB.Pool, "sch-stale")
	if !s.Enabled || s.ConsecutiveFailures != 0 {
		t.Errorf("after resume: %+v", s)
	}
}

func TestAPIBASScheduledRunLeavesOutWritesUnlessAsked(t *testing.T) {
	hd := jobsHandler(t, true)
	h := jobsRouter(hd)
	ctx := context.Background()
	if rec := postAs(t, h, "/api/apibas/targets", boundTargetBody("sch-w", "shop/alice", "shop/bob"), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d", rec.Code)
	}
	if rec := sendRaw(t, h, http.MethodPost, "/api/apibas/targets/sch-w/inventory", specBytes(t), auth.RoleAdmin, "admin1"); rec.Code != http.StatusCreated {
		t.Fatalf("import: %d", rec.Code)
	}
	spec := bindSpecWith("shop/alice", "shop/bob")
	spec["allow_writes"] = true
	if rec := putAs(t, h, "/api/apibas/targets/sch-w/binding", spec, auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK {
		t.Fatalf("save binding: %d %s", rec.Code, rec.Body.String())
	}
	without, err := hd.buildBoundPlan(ctx, "sch-w", false)
	if err != nil || without.Spec.AllowWrites {
		t.Errorf("a scheduled run without writes kept allow_writes: %+v %v", without.Spec.AllowWrites, err)
	}
	with, err := hd.buildBoundPlan(ctx, "sch-w", true)
	if err != nil || !with.Spec.AllowWrites {
		t.Errorf("a manual run lost allow_writes: %+v %v", with.Spec.AllowWrites, err)
	}
	// The stored data is not changed by building a plan without writes.
	stored, err := db.GetAPIBASBinding(ctx, sharedDB.Pool, "sch-w")
	var storedSpec map[string]any
	if err != nil || json.Unmarshal(stored.Spec, &storedSpec) != nil || storedSpec["allow_writes"] != true {
		t.Errorf("the stored spec was changed: %s %v", stored.Spec, err)
	}
}
