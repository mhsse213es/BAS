package db_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

func TestAPIBASScheduleStore(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		inventoryTarget(t, pool, "sch-store")
		now := time.Now().UTC()

		if _, err := db.GetAPIBASSchedule(ctx, pool, "sch-store"); !errors.Is(err, db.ErrAPIBASScheduleNotFound) {
			t.Fatalf("before any schedule: %v", err)
		}
		if _, err := db.PutAPIBASSchedule(ctx, pool, db.APIBASSchedule{TargetID: "no-such", EveryHours: 1, Enabled: true, NextRunAt: now, CreatedBy: "u"}); !errors.Is(err, db.ErrAPIBASTargetNotFound) {
			t.Errorf("schedule for an unknown target: %v", err)
		}
		// The interval is bounded by the table, not only by the handler.
		if _, err := db.PutAPIBASSchedule(ctx, pool, db.APIBASSchedule{TargetID: "sch-store", EveryHours: 0, Enabled: true, NextRunAt: now, CreatedBy: "u"}); err == nil {
			t.Error("an interval of zero hours was stored")
		}
		if _, err := db.PutAPIBASSchedule(ctx, pool, db.APIBASSchedule{TargetID: "sch-store", EveryHours: 721, Enabled: true, NextRunAt: now, CreatedBy: "u"}); err == nil {
			t.Error("an interval over 720 hours was stored")
		}

		// Not due: not claimed. Due: claimed once with its due time, and the next run moves out by the interval.
		if _, err := db.PutAPIBASSchedule(ctx, pool, db.APIBASSchedule{TargetID: "sch-store", EveryHours: 2, Enabled: true, NextRunAt: now.Add(time.Hour), CreatedBy: "u"}); err != nil {
			t.Fatal(err)
		}
		if got, err := db.ClaimDueAPIBASSchedules(ctx, pool, now, 10); err != nil || len(got) != 0 {
			t.Fatalf("claim before due: %d %v", len(got), err)
		}
		due := now.Add(-3 * time.Hour).Truncate(time.Microsecond)
		if _, err := db.PutAPIBASSchedule(ctx, pool, db.APIBASSchedule{TargetID: "sch-store", EveryHours: 2, Enabled: true, NextRunAt: due, CreatedBy: "u"}); err != nil {
			t.Fatal(err)
		}
		got, err := db.ClaimDueAPIBASSchedules(ctx, pool, now, 10)
		if err != nil || len(got) != 1 {
			t.Fatalf("claim when due: %d %v", len(got), err)
		}
		if !got[0].DueAt.Equal(due) || got[0].NextRunAt.Before(now.Add(2*time.Hour-time.Second)) || got[0].NextRunAt.After(now.Add(2*time.Hour+time.Second)) {
			t.Errorf("claimed schedule: due %s next %s", got[0].DueAt, got[0].NextRunAt)
		}
		if again, _ := db.ClaimDueAPIBASSchedules(ctx, pool, now, 10); len(again) != 0 {
			t.Errorf("the same run was claimed twice")
		}

		// A disabled schedule is never claimed.
		if _, err := db.PutAPIBASSchedule(ctx, pool, db.APIBASSchedule{TargetID: "sch-store", EveryHours: 2, Enabled: false, NextRunAt: due, CreatedBy: "u"}); err != nil {
			t.Fatal(err)
		}
		if got, _ := db.ClaimDueAPIBASSchedules(ctx, pool, now, 10); len(got) != 0 {
			t.Errorf("a disabled schedule was claimed")
		}

		// Failures count up and pause the schedule; a success resets the count; saving again resumes.
		if _, err := db.PutAPIBASSchedule(ctx, pool, db.APIBASSchedule{TargetID: "sch-store", EveryHours: 2, Enabled: true, NextRunAt: now, CreatedBy: "u"}); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= db.APIBASScheduleMaxFailures; i++ {
			if err := db.RecordAPIBASScheduleResult(ctx, pool, "sch-store", "", "boom", true); err != nil {
				t.Fatal(err)
			}
			s, _ := db.GetAPIBASSchedule(ctx, pool, "sch-store")
			if s.ConsecutiveFailures != i || s.Enabled != (i < db.APIBASScheduleMaxFailures) {
				t.Fatalf("after %d failures: %+v", i, s)
			}
		}
		saved, err := db.PutAPIBASSchedule(ctx, pool, db.APIBASSchedule{TargetID: "sch-store", EveryHours: 2, Enabled: true, NextRunAt: now, CreatedBy: "u"})
		if err != nil || !saved.Enabled || saved.ConsecutiveFailures != 0 {
			t.Fatalf("resume: %+v %v", saved, err)
		}
		_ = db.RecordAPIBASScheduleResult(ctx, pool, "sch-store", "", "boom", true)
		_ = db.RecordAPIBASScheduleResult(ctx, pool, "sch-store", "job-1", "queued", false)
		if s, _ := db.GetAPIBASSchedule(ctx, pool, "sch-store"); s.ConsecutiveFailures != 0 || s.LastJobID != "job-1" || s.LastResult != "queued" {
			t.Errorf("after a success: %+v", s)
		}

		// Deleting the target deletes its schedule.
		if ok, err := db.DeleteAPIBASSchedule(ctx, pool, "sch-store"); err != nil || !ok {
			t.Errorf("delete: %v %v", ok, err)
		}
		if ok, _ := db.DeleteAPIBASSchedule(ctx, pool, "sch-store"); ok {
			t.Error("a second delete found a schedule")
		}
	})
}

func TestAPIBASScheduleClaimsAreExclusiveAcrossCallers(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		ids := []string{"sch-c1", "sch-c2", "sch-c3", "sch-c4", "sch-c5", "sch-c6"}
		now := time.Now().UTC()
		for _, id := range ids {
			inventoryTarget(t, pool, id)
			if _, err := db.PutAPIBASSchedule(ctx, pool, db.APIBASSchedule{TargetID: id, EveryHours: 1, Enabled: true, NextRunAt: now.Add(-time.Minute), CreatedBy: "u"}); err != nil {
				t.Fatal(err)
			}
		}
		var mu sync.Mutex
		claimed := map[string]int{}
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := db.ClaimDueAPIBASSchedules(ctx, pool, now, 3)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				for _, s := range got {
					claimed[s.TargetID]++
				}
				mu.Unlock()
			}()
		}
		wg.Wait()
		for id, n := range claimed {
			if n != 1 {
				t.Errorf("%s was claimed %d times", id, n)
			}
		}
		if len(claimed) == 0 {
			t.Error("nothing was claimed")
		}
	})
}
