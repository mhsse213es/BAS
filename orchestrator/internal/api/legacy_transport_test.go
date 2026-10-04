package api

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// waitForAsyncWrite polls for up to 2s for a row matching whereClause to
// appear in table -- recordLegacyUsage writes in a goroutine (matching
// auditLogAs's existing fire-and-forget pattern), so its effect isn't
// guaranteed visible the instant the calling function returns.
func waitForAsyncWrite(t *testing.T, pool *pgxpool.Pool, table, whereClause string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var exists bool
		err := pool.QueryRow(context.Background(),
			"SELECT EXISTS(SELECT 1 FROM "+table+" WHERE "+whereClause+")",
		).Scan(&exists)
		if err == nil && exists {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for a row matching %q in %s", whereClause, table)
}

func TestRecordLegacyUsage_AttributedUpsertsOnePerAgentPerDay(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		ctx := context.Background()
		day := time.Now().UTC().Truncate(24 * time.Hour)
		first := day.Add(10 * time.Hour)
		second := day.Add(14 * time.Hour)

		h.recordLegacyUsage(ctx, "agent-1", "/api/heartbeat", first)
		h.recordLegacyUsage(ctx, "agent-1", "/api/heartbeat", second)
		// Wait for the SECOND write's exact timestamp, not just "a row
		// exists" -- the first write's fire-and-forget goroutine can still
		// be in flight when the second's lands, and asserting immediately
		// after only the row's existence raced the first write's value 2 of
		// 6 local runs.
		waitForAsyncWrite(t, pool, "legacy_transport_log",
			"agent_id = 'agent-1' AND last_seen_at = '"+second.UTC().Format(time.RFC3339Nano)+"'::timestamptz")

		var count int
		var lastSeen time.Time
		err := pool.QueryRow(ctx,
			`SELECT COUNT(*), MAX(last_seen_at) FROM legacy_transport_log WHERE agent_id = 'agent-1'`,
		).Scan(&count, &lastSeen)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if count != 1 {
			t.Fatalf("expected exactly 1 row for agent-1's day (upsert, not insert-per-call), got %d", count)
		}
		if !lastSeen.Equal(second) {
			t.Errorf("expected last_seen_at to be the later of the two writes (%v), got %v", second, lastSeen)
		}
	})
}

func TestRecordLegacyUsage_OutOfOrderWriteNeverMovesTimeBackwards(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		ctx := context.Background()
		day := time.Now().UTC().Truncate(24 * time.Hour)
		later := day.Add(14 * time.Hour)
		earlier := day.Add(10 * time.Hour) // arrives AFTER 'later' due to network jitter, not test ordering

		h.recordLegacyUsage(ctx, "agent-2", "/api/heartbeat", later)
		waitForAsyncWrite(t, pool, "legacy_transport_log", "agent_id = 'agent-2'")
		h.recordLegacyUsage(ctx, "agent-2", "/api/heartbeat", earlier) // the delayed, older-timestamped request
		waitForAsyncWrite(t, pool, "legacy_transport_log", "agent_id = 'agent-2'")

		var lastSeen time.Time
		if err := pool.QueryRow(ctx,
			`SELECT last_seen_at FROM legacy_transport_log WHERE agent_id = 'agent-2'`,
		).Scan(&lastSeen); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !lastSeen.Equal(later) {
			t.Errorf("an out-of-order (delayed) write moved last_seen_at backwards to %v -- expected it to stay at %v (GREATEST() should have rejected the older value)", lastSeen, later)
		}
	})
}

func TestRecordLegacyUsage_WriteFailureIsLogged(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// A closed pool makes h.db.Exec fail deterministically and
		// immediately, without needing to break the schema or race a real
		// timeout -- proves the previously fully-discarded write error is
		// now surfaced via slog rather than vanishing silently, which
		// matters because a silently-lost write is an undercount the
		// retirement-eligibility decision depends on.
		closedPool, err := pgxpool.New(context.Background(), pool.Config().ConnString())
		if err != nil {
			t.Fatalf("open pool: %v", err)
		}
		closedPool.Close()

		// recordLegacyUsage logs from its own goroutine, so the buffer is
		// written and read concurrently.
		var logBuf lockedBuffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, nil)))
		defer slog.SetDefault(prev)

		h := &Handler{db: closedPool}
		h.recordLegacyUsage(context.Background(), "agent-fail", "/api/heartbeat", time.Now())

		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && !strings.Contains(logBuf.String(), "legacy usage write failed") {
			time.Sleep(20 * time.Millisecond)
		}
		if !strings.Contains(logBuf.String(), "legacy usage write failed") {
			t.Errorf("expected a logged error for the failed write, got log output: %s", logBuf.String())
		}
	})
}

func TestRecordLegacyUsage_UnattributedIncrementsCount(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		ctx := context.Background()
		day := time.Now().UTC().Truncate(24 * time.Hour)

		h.recordLegacyUsage(ctx, "", "/api/heartbeat", day.Add(9*time.Hour))
		waitForAsyncWrite(t, pool, "legacy_transport_unattributed", "day = '"+day.Format("2006-01-02")+"'")
		h.recordLegacyUsage(ctx, "", "/ws/agent", day.Add(11*time.Hour))
		waitForAsyncWrite(t, pool, "legacy_transport_unattributed", "request_count = 2")

		var count int
		if err := pool.QueryRow(ctx,
			`SELECT request_count FROM legacy_transport_unattributed WHERE day = $1`, day,
		).Scan(&count); err != nil {
			t.Fatalf("query: %v", err)
		}
		if count != 2 {
			t.Errorf("expected request_count 2 after two unattributed writes on the same day, got %d", count)
		}
	})
}

type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
