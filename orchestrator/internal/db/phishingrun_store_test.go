package db_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/phishingrun"
)

func TestPhishingRunSchema_Idempotent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for i := 0; i < 2; i++ {
			if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
				t.Fatalf("ensure #%d: %v", i+1, err)
			}
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name='phishing_runs'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("phishing_runs table missing (n=%d err=%v)", n, err)
		}
	})
}

func TestInsertGetUpdateListPhishingRun_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
			t.Fatalf("ensure schema: %v", err)
		}

		run := &phishingrun.PhishingRun{ID: "run-1", ScenarioID: "PH-DET-002", Status: phishingrun.StatusPending, StartedAt: time.Now()}
		if err := db.InsertPhishingRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetPhishingRun(ctx, pool, "run-1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != phishingrun.StatusPending {
			t.Errorf("Status = %q, want pending", got.Status)
		}

		result, _ := json.Marshal(map[string]string{"ok": "true"})
		if err := db.UpdatePhishingRunStatus(ctx, pool, "run-1", phishingrun.StatusCompleted, result, ""); err != nil {
			t.Fatalf("update: %v", err)
		}
		got, err = db.GetPhishingRun(ctx, pool, "run-1")
		if err != nil {
			t.Fatalf("get after update: %v", err)
		}
		if got.Status != phishingrun.StatusCompleted || got.CompletedAt == nil {
			t.Errorf("got = %+v, want StatusCompleted with CompletedAt set", got)
		}

		runs, err := db.ListPhishingRuns(ctx, pool, 10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(runs) != 1 || runs[0].ID != "run-1" {
			t.Errorf("runs = %+v, want exactly run-1", runs)
		}
	})
}

func TestGetPhishingRun_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
			t.Fatalf("ensure schema: %v", err)
		}
		_, err := db.GetPhishingRun(ctx, pool, "missing")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("err = %v, want wrapped pgx.ErrNoRows", err)
		}
	})
}
