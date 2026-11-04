package testutil

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// truncateWaitLimit bounds how long one TRUNCATE may wait for locks. A TRUNCATE
// takes an exclusive lock, so any session still holding that table (a leaked
// transaction, an open result set, a live connection from an earlier test)
// blocks it.
const truncateWaitLimit = 30 * time.Second

// truncateTables empties the named tables. It fails the test with the report from truncateNow.
func truncateTables(t *testing.T, pool *pgxpool.Pool, names []string) {
	t.Helper()
	if err := truncateNow(pool, names); err != nil {
		t.Fatalf("%v", err)
	}
}

// truncateNow runs one TRUNCATE and returns an error instead of failing a test, so the blocking behaviour can be tested.
//
// The TRUNCATE gets its own connection. When it cannot get its locks within truncateWaitLimit, the report names the
// sessions holding them, and every other session on the test database is terminated. That releases the locks, so the
// TRUNCATE can finish or fail on its own. The caller still gets an error: a blocked truncate is a leak in an earlier
// test and must be visible, not silently absorbed.
func truncateNow(pool *pgxpool.Pool, names []string) error {
	if len(names) == 0 {
		return nil
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = `"` + n + `"`
	}
	list := strings.Join(quoted, ", ")

	conn, err := pool.Acquire(context.Background())
	if err != nil {
		return fmt.Errorf("testutil: truncate %s: no connection from the pool: %v\n%s", list, err, sessionReport(pool))
	}
	truncatePID := conn.Conn().PgConn().PID()
	done := make(chan error, 1)
	go func() {
		_, err := conn.Exec(context.Background(), `TRUNCATE TABLE `+list+` CASCADE`)
		conn.Release()
		done <- err
	}()
	timer := time.NewTimer(truncateWaitLimit)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("testutil: truncate %s: %v\n%s", list, err, sessionReport(pool))
		}
		return nil
	case <-timer.C:
		// Capture who is blocking before anything is terminated.
		report := sessionReport(pool)
		ended, termErr := terminateOtherSessions(pool, truncatePID)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
		detail := fmt.Sprintf("%d blocking session(s) were terminated", ended)
		if termErr != nil {
			detail = "terminating the blocking sessions failed: " + termErr.Error()
		}
		return fmt.Errorf("testutil: truncate %s waited more than %s for a lock; %s\n%s",
			list, truncateWaitLimit, detail, report)
	}
}

// terminateOtherSessions ends every session on the test database except the given one and this one. It returns how many
// it ended.
func terminateOtherSessions(pool *pgxpool.Pool, keepPID uint32) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var n int
	err := pool.QueryRow(ctx, `
		SELECT count(pg_terminate_backend(pid))::int FROM pg_stat_activity
		WHERE datname = current_database() AND pid <> pg_backend_pid() AND pid <> $1`, int64(keepPID)).Scan(&n)
	return n, err
}

// sessionReport lists the other sessions connected to the test database. It is
// best effort: a failure to read the report is included in its text rather than
// hiding the original truncate error.
func sessionReport(pool *pgxpool.Pool) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx, `
		SELECT pid, state, COALESCE(wait_event_type, ''), COALESCE(left(query, 200), ''),
		       COALESCE(backend_start::text, ''), COALESCE(xact_start::text, '')
		FROM pg_stat_activity
		WHERE datname = current_database() AND pid <> pg_backend_pid()
		ORDER BY backend_start`)
	if err != nil {
		return "session report unavailable: " + err.Error()
	}
	defer rows.Close()
	out := "other sessions on test database:\n"
	for rows.Next() {
		var pid int
		var state, waitType, query, started, xactStarted string
		if err := rows.Scan(&pid, &state, &waitType, &query, &started, &xactStarted); err != nil {
			return out + "scan error: " + err.Error()
		}
		out += "  pid=" + strconv.Itoa(pid) + " state=" + state + " wait=" + waitType +
			" started=" + started + " xact_started=" + xactStarted + "\n    query: " + query + "\n"
	}
	return out
}
