package testutil

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A session that holds an exclusive lock on a table must not hang the next TRUNCATE. The truncate must return an error
// within the bound, name the blocker, and terminate it, so that a later truncate on the same table succeeds.
func TestTruncateNow_TerminatesABlockingSession(t *testing.T) {
	d := MustSharedTestDB()
	ctx := context.Background()
	if _, err := d.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS truncate_probe (id int)`); err != nil {
		t.Fatal(err)
	}

	blocker, err := d.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE truncate_probe IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	err = truncateNow(d.Pool, []string{"truncate_probe"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a truncate blocked by another session must report an error")
	}
	if elapsed > truncateWaitLimit+30*time.Second {
		t.Fatalf("the truncate hung for %s; it should return near %s", elapsed, truncateWaitLimit)
	}
	if !strings.Contains(err.Error(), "terminated") || !strings.Contains(err.Error(), "pid=") {
		t.Errorf("the error must name the blocking session and say it was terminated: %v", err)
	}

	// The blocker's transaction was ended, so the table is free and the next truncate succeeds.
	if err := truncateNow(d.Pool, []string{"truncate_probe"}); err != nil {
		t.Errorf("once the blocker is gone the truncate must succeed: %v", err)
	}
	// The pool still works.
	var one int
	if err := d.Pool.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Errorf("the pool must remain usable after the blocker is terminated: %v", err)
	}
}
