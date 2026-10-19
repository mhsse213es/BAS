package testutil

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// truncateWaitLimit bounds how long one TRUNCATE may wait for locks. A TRUNCATE
// takes an exclusive lock, so any session still holding that table (a leaked
// transaction, an open result set, a live connection from an earlier test)
// blocks it. Without a bound the whole test binary hangs until its own timeout
// and reports nothing about the cause.
const truncateWaitLimit = 30 * time.Second

// truncateTable empties one table. When the TRUNCATE cannot get its lock within
// truncateWaitLimit, the test fails and the report names the sessions that are
// still connected, with their state and last statement, so the leaking test can
// be found from the failure.
//
// The context alone does not bound the wait: a pgx simple-protocol read can keep
// running past its deadline (observed in full-suite runs, where the goroutine sat
// in ResultReader.Close and the context never ended the call). The statement
// therefore runs in its own goroutine, and this test stops waiting for it after
// truncateWaitLimit. A stuck goroutine is left behind for the rest of the
// binary; the failure names the table so the test that hit it is visible.
func truncateTable(t *testing.T, pool *pgxpool.Pool, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), truncateWaitLimit)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := pool.Exec(ctx, `TRUNCATE TABLE "`+name+`" CASCADE`)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("testutil: truncate %s: %v\n%s", name, err, sessionReport(pool))
		}
	case <-time.After(truncateWaitLimit + 5*time.Second):
		t.Fatalf("testutil: truncate %s did not return within %s; the TRUNCATE is stuck in the driver, not waiting on a lock", name, truncateWaitLimit)
	}
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

