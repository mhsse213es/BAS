package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
)

func TestAPIBASTimeOfDayScheduleRules(t *testing.T) {
	h := jobsRouter(jobsHandler(t, true))
	scheduledTarget(t, h, "clk-1")
	path := "/api/apibas/targets/clk-1/schedule"
	for name, body := range map[string]map[string]any{
		"both interval and time":  {"every_hours": 6, "at": "02:30"},
		"bad time":                {"at": "2:30"},
		"time out of range":       {"at": "25:00"},
		"unknown timezone":        {"at": "02:30", "timezone": "Mars/Base"},
		"path-like timezone":      {"at": "02:30", "timezone": "../etc/passwd"},
		"bad day":                 {"at": "02:30", "days": []string{"monday"}},
		"timezone without time":   {"every_hours": 6, "timezone": "UTC"},
		"days without time":       {"every_hours": 6, "days": []string{"mon"}},
		"neither interval nor at": {},
	} {
		if rec := putAs(t, h, path, body, auth.RoleAdmin, "admin1"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}

	rec := putAs(t, h, path, map[string]any{"at": "02:30", "timezone": "Asia/Kolkata", "days": []string{"fri", "mon"}}, auth.RoleAdmin, "admin1")
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	got := decode(t, rec)
	if got["at"] != "02:30" || got["timezone"] != "Asia/Kolkata" || got["every_hours"] != nil {
		t.Errorf("view: %v", got)
	}
	if d, _ := got["days"].([]any); len(d) != 2 || d[0] != "mon" || d[1] != "fri" {
		t.Errorf("days: %v, want [mon fri]", got["days"])
	}
	// The first run is the next Monday or Friday 02:30 in India, in the future and within a week.
	next, err := time.Parse(time.RFC3339, got["next_run_at"].(string))
	if err != nil || !next.After(time.Now()) || next.After(time.Now().Add(8*24*time.Hour)) {
		t.Fatalf("next run %v (%v)", got["next_run_at"], err)
	}
	if loc, _ := time.LoadLocation("Asia/Kolkata"); next.In(loc).Format("15:04") != "02:30" || (next.In(loc).Weekday() != time.Monday && next.In(loc).Weekday() != time.Friday) {
		t.Errorf("next run %s is not 02:30 on a Monday or Friday in India", next.In(loc))
	}
	// Replacing it with an interval clears the clock settings.
	rec = putAs(t, h, path, map[string]any{"every_hours": 6}, auth.RoleAdmin, "admin1")
	got = decode(t, rec)
	if rec.Code != http.StatusOK || got["every_hours"] != float64(6) || got["at"] != nil || got["timezone"] != nil {
		t.Errorf("back to an interval: %d %v", rec.Code, got)
	}
}

func TestAPIBASTimeOfDayRunAdvancesToTheNextOccurrence(t *testing.T) {
	hd := jobsHandler(t, true)
	h := jobsRouter(hd)
	ctx := context.Background()
	scheduledTarget(t, h, "clk-run")
	if rec := putAs(t, h, "/api/apibas/targets/clk-run/schedule", map[string]any{"at": "03:15", "timezone": "UTC"}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK {
		t.Fatalf("save: %d", rec.Code)
	}
	makeDue(t, "clk-run")
	if n, err := hd.RunDueAPIBASSchedules(ctx, time.Now().UTC()); err != nil || n != 1 {
		t.Fatalf("due: %d %v", n, err)
	}
	s, err := db.GetAPIBASSchedule(ctx, sharedDB.Pool, "clk-run")
	if err != nil {
		t.Fatal(err)
	}
	if s.LastResult != "queued" || !s.Enabled {
		t.Fatalf("after a due run: %+v", s)
	}
	if s.NextRunAt.UTC().Format("15:04:05") != "03:15:00" || !s.NextRunAt.After(time.Now()) || s.NextRunAt.After(time.Now().Add(25*time.Hour)) {
		t.Errorf("next run %s, want the next 03:15 UTC within a day", s.NextRunAt)
	}
	// Claimed once: a second claim at the same moment finds nothing.
	if n, _ := hd.RunDueAPIBASSchedules(ctx, time.Now().UTC()); n != 0 {
		t.Errorf("a claimed run was claimed again: %d", n)
	}
}

// A schedule whose stored clock settings cannot be read is paused with a reason, not run at a guessed time.
func TestAPIBASUnreadableClockSchedulePausesInsteadOfRunning(t *testing.T) {
	hd := jobsHandler(t, true)
	h := jobsRouter(hd)
	ctx := context.Background()
	scheduledTarget(t, h, "clk-bad")
	if rec := putAs(t, h, "/api/apibas/targets/clk-bad/schedule", map[string]any{"at": "03:15"}, auth.RoleAdmin, "admin1"); rec.Code != http.StatusOK {
		t.Fatalf("save: %d", rec.Code)
	}
	if _, err := sharedDB.Pool.Exec(ctx, `UPDATE apibas_schedules SET timezone = 'Nowhere/Land' WHERE target_id = 'clk-bad'`); err != nil {
		t.Fatal(err)
	}
	makeDue(t, "clk-bad")
	if n, err := hd.RunDueAPIBASSchedules(ctx, time.Now().UTC()); err != nil || n != 0 {
		t.Fatalf("claimed %d (%v), want 0", n, err)
	}
	s, _ := db.GetAPIBASSchedule(ctx, sharedDB.Pool, "clk-bad")
	if s.Enabled || !strings.HasPrefix(s.LastResult, "paused:") || s.LastJobID != "" {
		t.Errorf("unreadable schedule: %+v", s)
	}
}
