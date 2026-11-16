package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A due occurrence inside a change-freeze window produces no job. The occurrence is recorded as handled, so the
// schedule does not fire late when the window ends; the next occurrence runs as normal.
func TestSpawnDueSchedules_OccurrenceInsideBlackoutSpawnsNoJob(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		now := time.Now().UTC()

		frozen, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"freeze-agent"},
			RecurrenceType: "once", RunAt: ptrTime(now.Add(-time.Minute)), Timezone: "UTC",
			Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		window, err := store.CreateBlackout(ctx, Blackout{
			Name: "RBI reporting", Kind: "once",
			StartsAt: ptrTime(now.Add(-time.Hour)), EndsAt: ptrTime(now.Add(time.Hour)), CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateBlackout: %v", err)
		}

		d := NewDispatcher(store)
		d.spawnDueSchedules(ctx)

		got, err := store.GetSchedule(ctx, frozen.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.LastOccurrenceAt == nil {
			t.Fatal("the blocked occurrence was not recorded as handled; it would fire late when the window ends")
		}
		if got.LastSpawnedJobID != "" {
			t.Errorf("LastSpawnedJobID = %q, want empty: a blackout must spawn no job", got.LastSpawnedJobID)
		}

		// With the window gone, a schedule whose occurrence is due now spawns a job as normal.
		if _, err := store.pool.Exec(ctx, `DELETE FROM scheduled_blackouts WHERE id = $1`, window.ID); err != nil {
			t.Fatalf("delete window: %v", err)
		}
		open, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"open-agent"},
			RecurrenceType: "once", RunAt: ptrTime(now.Add(-time.Minute)), Timezone: "UTC",
			Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		d.spawnDueSchedules(ctx)
		after, err := store.GetSchedule(ctx, open.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if after.LastSpawnedJobID == "" {
			t.Error("with no window in force, the due occurrence should have spawned a job")
		}
	})
}

func ptrTime(t time.Time) *time.Time { return &t }

// The day filters survive a round trip through the database, and the stored window still honours them.
func TestBlackoutStore_DayFiltersRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.CreateBlackout(ctx, Blackout{
			Name: "Month end", Kind: "daily", TimeFrom: "00:00", TimeTo: "24:00", Timezone: "UTC",
			Weekdays: " mon, tue ", MonthDays: "-2,-1,1", CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateBlackout: %v", err)
		}
		list, err := store.ListBlackouts(ctx)
		if err != nil || len(list) != 1 {
			t.Fatalf("ListBlackouts = %d windows, %v", len(list), err)
		}
		got := list[0]
		if got.ID != created.ID || got.Weekdays != "mon, tue" || got.MonthDays != "-2,-1,1" || got.TimeTo != "24:00" {
			t.Fatalf("stored window = %+v, lost its filters or end time", got)
		}
		// Monday 2026-11-30 is the last day of November and a Monday: both filters match.
		if !got.Covers(time.Date(2026, 11, 30, 12, 0, 0, 0, time.UTC)) {
			t.Error("the stored window should cover Monday the 30th")
		}
		// Tuesday 2026-12-01 is the 1st and a Tuesday: covered. Wednesday 2026-12-02 is neither.
		if !got.Covers(time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)) || got.Covers(time.Date(2026, 12, 2, 12, 0, 0, 0, time.UTC)) {
			t.Error("the stored window should cover Tuesday the 1st and not Wednesday the 2nd")
		}
		if _, err := store.CreateBlackout(ctx, Blackout{Name: "bad", Kind: "daily", TimeFrom: "00:00", TimeTo: "24:00",
			Timezone: "UTC", Weekdays: "funday"}); !errors.Is(err, ErrInvalidBlackout) {
			t.Fatalf("a bad weekday was stored: err = %v", err)
		}
	})
}
