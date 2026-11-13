package jobs

import (
	"context"
	"encoding/json"
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
