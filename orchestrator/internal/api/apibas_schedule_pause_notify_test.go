package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/notifications"
)

func pauseEvents(bc *captureBroadcaster, target string) []notifications.Event {
	var out []notifications.Event
	for _, e := range bc.events() {
		if e.Type == notifications.EventAPIBASSchedulePaused && e.TargetID == target {
			out = append(out, e)
		}
	}
	return out
}

func TestAPIBASSchedulePauseIsNotifiedOnceWithTheReason(t *testing.T) {
	hd := jobsHandler(t, true)
	bc := &captureBroadcaster{}
	hd.notifications = notifications.NewService(notifications.NewStore(sharedDB.Pool), bc)
	h := jobsRouter(hd)
	ctx := context.Background()
	scheduledTarget(t, h, "pn-1")
	if rec := putAs(t, h, "/api/apibas/targets/pn-1/schedule", map[string]any{"every_hours": 1}, auth.RoleAdmin, "admin1"); rec.Code != 200 {
		t.Fatalf("save: %d", rec.Code)
	}
	changed := strings.Replace(specBytes(t), "/v2/catalog", "/v2/catalogue", 1)
	if rec := sendRaw(t, h, "POST", "/api/apibas/targets/pn-1/inventory", changed, auth.RoleAdmin, "admin1"); rec.Code != 201 {
		t.Fatalf("second import: %d", rec.Code)
	}
	for i := 1; i <= db.APIBASScheduleMaxFailures; i++ {
		makeDue(t, "pn-1")
		_, _ = hd.RunDueAPIBASSchedules(ctx, time.Now().UTC())
		got := pauseEvents(bc, "pn-1")
		if i < db.APIBASScheduleMaxFailures && len(got) != 0 {
			t.Fatalf("run %d: a pause was announced before the schedule paused", i)
		}
	}
	got := pauseEvents(bc, "pn-1")
	if len(got) != 1 {
		t.Fatalf("%d pause notifications, want 1", len(got))
	}
	e := got[0]
	if e.Severity != notifications.SeverityError || e.Metadata["consecutive_failures"] != db.APIBASScheduleMaxFailures || !strings.Contains(e.Message, "older inventory") || !strings.Contains(e.Message, "pn-1") {
		t.Errorf("event: severity %s metadata %v message %q", e.Severity, e.Metadata, e.Message)
	}
	// A paused schedule is not claimed, so it cannot announce itself again.
	makeDue(t, "pn-1")
	_, _ = hd.RunDueAPIBASSchedules(ctx, time.Now().UTC())
	if n := len(pauseEvents(bc, "pn-1")); n != 1 {
		t.Errorf("%d pause notifications after a further tick, want still 1", n)
	}
	// Persisted, not only pushed.
	deadline := time.Now().Add(2 * time.Second)
	var stored int
	for time.Now().Before(deadline) {
		_ = sharedDB.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE target_id = 'pn-1' AND type = 'apibas_schedule_paused'`).Scan(&stored)
		if stored == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if stored != 1 {
		t.Errorf("%d stored, want 1", stored)
	}
	// Resuming and failing again announces again: it is one notice per pause.
	if rec := putAs(t, h, "/api/apibas/targets/pn-1/schedule", map[string]any{"every_hours": 1}, auth.RoleAdmin, "admin1"); rec.Code != 200 {
		t.Fatalf("resume: %d", rec.Code)
	}
	for i := 1; i <= db.APIBASScheduleMaxFailures; i++ {
		makeDue(t, "pn-1")
		_, _ = hd.RunDueAPIBASSchedules(ctx, time.Now().UTC())
	}
	if n := len(pauseEvents(bc, "pn-1")); n != 2 {
		t.Errorf("%d pause notifications after a second pause, want 2", n)
	}
}

func TestAPIBASUnreadableClockPauseIsNotified(t *testing.T) {
	hd := jobsHandler(t, true)
	bc := &captureBroadcaster{}
	hd.notifications = notifications.NewService(notifications.NewStore(sharedDB.Pool), bc)
	h := jobsRouter(hd)
	ctx := context.Background()
	scheduledTarget(t, h, "pn-clk")
	if rec := putAs(t, h, "/api/apibas/targets/pn-clk/schedule", map[string]any{"at": "03:15"}, auth.RoleAdmin, "admin1"); rec.Code != 200 {
		t.Fatalf("save: %d", rec.Code)
	}
	if _, err := sharedDB.Pool.Exec(ctx, `UPDATE apibas_schedules SET timezone = 'Nowhere/Land' WHERE target_id = 'pn-clk'`); err != nil {
		t.Fatal(err)
	}
	makeDue(t, "pn-clk")
	_, _ = hd.RunDueAPIBASSchedules(ctx, time.Now().UTC())
	got := pauseEvents(bc, "pn-clk")
	if len(got) != 1 || got[0].Metadata["consecutive_failures"] != 0 || !strings.Contains(got[0].Message, "paused") {
		t.Fatalf("clock pause notifications: %+v", got)
	}
}

// With no notification service the pause still happens and nothing panics.
func TestAPIBASSchedulePauseWithoutNotificationServiceStillPauses(t *testing.T) {
	hd := jobsHandler(t, true)
	hd.notifications = nil
	h := jobsRouter(hd)
	ctx := context.Background()
	scheduledTarget(t, h, "pn-none")
	if rec := putAs(t, h, "/api/apibas/targets/pn-none/schedule", map[string]any{"at": "03:15"}, auth.RoleAdmin, "admin1"); rec.Code != 200 {
		t.Fatalf("save: %d", rec.Code)
	}
	_, _ = sharedDB.Pool.Exec(ctx, `UPDATE apibas_schedules SET timezone = 'Nowhere/Land' WHERE target_id = 'pn-none'`)
	makeDue(t, "pn-none")
	_, _ = hd.RunDueAPIBASSchedules(ctx, time.Now().UTC())
	if s, _ := db.GetAPIBASSchedule(ctx, sharedDB.Pool, "pn-none"); s.Enabled {
		t.Error("the schedule did not pause")
	}
}

// Only the call that turns the schedule off reports a pause; a later failure on an already paused schedule does not.
func TestRecordScheduleOutcomeReportsOnlyTheCallThatPauses(t *testing.T) {
	hd := jobsHandler(t, true)
	h := jobsRouter(hd)
	ctx := context.Background()
	scheduledTarget(t, h, "pn-store")
	if rec := putAs(t, h, "/api/apibas/targets/pn-store/schedule", map[string]any{"every_hours": 1}, auth.RoleAdmin, "admin1"); rec.Code != 200 {
		t.Fatalf("save: %d", rec.Code)
	}
	for i := 1; i <= db.APIBASScheduleMaxFailures+2; i++ {
		paused, err := db.RecordAPIBASScheduleOutcome(ctx, sharedDB.Pool, "pn-store", "", "boom", true)
		if err != nil {
			t.Fatal(err)
		}
		if want := i == db.APIBASScheduleMaxFailures; paused != want {
			t.Errorf("failure %d: paused=%v, want %v", i, paused, want)
		}
	}
	// A schedule removed mid-run is not an error and not a pause.
	if _, err := db.DeleteAPIBASSchedule(ctx, sharedDB.Pool, "pn-store"); err != nil {
		t.Fatal(err)
	}
	if paused, err := db.RecordAPIBASScheduleOutcome(ctx, sharedDB.Pool, "pn-store", "", "boom", true); err != nil || paused {
		t.Errorf("removed schedule: paused=%v err=%v", paused, err)
	}
}
