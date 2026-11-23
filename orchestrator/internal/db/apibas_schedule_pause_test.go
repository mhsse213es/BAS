package db_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

// A schedule whose clock settings cannot be read is paused instead of run. When such a schedule sits in the middle of the
// due list, the others must still be claimed and advanced: pausing one schedule must not skip its neighbour or index past
// the end of the shortened list.
func TestAPIBASScheduleClaimPausesUnreadableClocksWithoutLosingTheOthers(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		now := time.Now().UTC()
		days, err := db.NormalizeClockDays(nil)
		if err != nil {
			t.Fatal(err)
		}
		// Claimed in next_run_at order: bad, good, bad, good.
		order := []struct {
			id  string
			bad bool
		}{{"pz-bad1", true}, {"pz-good1", false}, {"pz-bad2", true}, {"pz-good2", false}}
		for i, o := range order {
			inventoryTarget(t, pool, o.id)
			rec := db.APIBASSchedule{TargetID: o.id, EveryHours: 2, Enabled: true, CreatedBy: "u",
				NextRunAt: now.Add(-time.Duration(4-i) * time.Hour).Truncate(time.Microsecond)}
			if o.bad {
				rec.EveryHours, rec.AtTime, rec.Timezone, rec.Days = 24, "03:15", "UTC", days
			}
			if _, err := db.PutAPIBASSchedule(ctx, pool, rec); err != nil {
				t.Fatal(err)
			}
			if o.bad {
				if _, err := pool.Exec(ctx, `UPDATE apibas_schedules SET timezone = 'Nowhere/Land' WHERE target_id = $1`, o.id); err != nil {
					t.Fatal(err)
				}
			}
		}

		due, paused, err := db.ClaimDueAPIBASSchedulesReportingPauses(ctx, pool, now, 10)
		if err != nil {
			t.Fatal(err)
		}
		ids := func(s []db.APIBASSchedule) []string {
			var out []string
			for _, r := range s {
				out = append(out, r.TargetID)
			}
			return out
		}
		if got := strings.Join(ids(due), ","); got != "pz-good1,pz-good2" {
			t.Errorf("claimed to run = %q, want both readable schedules: pz-good1,pz-good2", got)
		}
		if got := strings.Join(ids(paused), ","); got != "pz-bad1,pz-bad2" {
			t.Errorf("paused = %q, want both unreadable schedules: pz-bad1,pz-bad2", got)
		}
		for _, r := range due {
			if r.NextRunAt.Before(now.Add(2*time.Hour-time.Second)) || r.NextRunAt.After(now.Add(2*time.Hour+time.Second)) {
				t.Errorf("%s was claimed but not advanced: next run %s", r.TargetID, r.NextRunAt)
			}
		}
		for _, id := range []string{"pz-bad1", "pz-bad2"} {
			s, err := db.GetAPIBASSchedule(ctx, pool, id)
			if err != nil {
				t.Fatal(err)
			}
			if s.Enabled || !strings.HasPrefix(s.LastResult, "paused:") {
				t.Errorf("%s was not paused: %+v", id, s)
			}
		}
	})
}
