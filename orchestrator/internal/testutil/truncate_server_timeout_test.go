package testutil

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The server's lock_timeout and truncateNow's own timer are both 30s, so which one fires first depends on scheduling.
// When the server wins, the TRUNCATE comes back with a lock-timeout error. That must be handled exactly like the client
// timer: name the blocker, terminate it, and leave the table free for the next truncate. This test makes the server's
// timer fire first on purpose, by giving the truncating pool a 2s lock_timeout.
func TestTruncateNow_ServerLockTimeoutAlsoTerminatesTheBlocker(t *testing.T) {
	d := MustSharedTestDB()
	ctx := context.Background()
	if _, err := d.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS truncate_probe_srv (id int)`); err != nil {
		t.Fatal(err)
	}

	cfg := d.Pool.Config().Copy()
	cfg.ConnConfig.RuntimeParams["lock_timeout"] = "2s"
	fast, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer fast.Close()

	blocker, err := d.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE truncate_probe_srv IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	err = truncateNow(fast, []string{"truncate_probe_srv"})
	if err == nil {
		t.Fatal("a truncate blocked by another session must report an error")
	}
	if elapsed := time.Since(start); elapsed > truncateWaitLimit/2 {
		t.Fatalf("took %s: the server's 2s lock_timeout should have ended the wait, not the 30s client timer", elapsed)
	}
	if !strings.Contains(err.Error(), "terminated") || !strings.Contains(err.Error(), "pid=") {
		t.Errorf("the error must name the blocking session and say it was terminated: %v", err)
	}
	if err := truncateNow(fast, []string{"truncate_probe_srv"}); err != nil {
		t.Errorf("once the blocker is gone the truncate must succeed: %v", err)
	}
}
