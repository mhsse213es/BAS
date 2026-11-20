package mysqlaudit

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/audspect/bas/internal/dbsim"
)

var reRunID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// authMarker builds the run-specific marker. The run ID is restricted to letters,
// digits and hyphens so it can never close the SQL comment or break the audit match.
func authMarker(runID string) (string, error) {
	if !reRunID.MatchString(runID) {
		return "", fmt.Errorf("run id %q must be 1-64 letters, digits or hyphens", runID)
	}
	return "dbsim:auth-" + runID, nil
}

// RunAuthEvent is test 03 on the lab MySQL. It logs in as the harness account on one
// connection, runs a marker-tagged query on that same connection, then reads the
// audit trail back independently. Grades: SKIPPED when the audit plugin is not
// active; ERROR when the audit file cannot be read or parsed; otherwise the
// AuthEventVerdict. Test 03 creates no fixtures, so there is nothing to clean up.
func RunAuthEvent(ctx context.Context, cfg LabConfig, runID string) (dbsim.RunResult, string, error) {
	marker, err := authMarker(runID)
	if err != nil {
		return dbsim.ResultError, "", err
	}
	dsn, err := DSNFromFile(cfg.PasswordFile, cfg.Addr)
	if err != nil {
		return dbsim.ResultError, "", err
	}
	q, err := OpenSQLQuerier(dsn)
	if err != nil {
		return dbsim.ResultError, "", err
	}
	defer q.DB.Close()

	rows, err := q.Query(ctx, "SHOW PLUGINS")
	if err != nil {
		return dbsim.ResultError, "", fmt.Errorf("plugin check: %w", err)
	}
	if !PluginActive(rows) {
		return dbsim.ResultSkipped, "audit_log plugin is not active: authentication audit coverage cannot be tested", nil
	}

	// Audit timestamps are database time, on the same host. Allow 2s of clock skew.
	since := time.Now().UTC().Add(-2 * time.Second)
	if err := authOperation(ctx, dsn, marker); err != nil {
		return dbsim.ResultError, "", err
	}

	// SYNCHRONOUS logging means the record is on disk before the query returns, but a
	// short bounded wait guards against a slower file system.
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		recs, err := readRecords(cfg.AuditFile)
		if err == nil {
			res, why := AuthEventVerdict(recs, marker, HarnessUser, since)
			if res == dbsim.ResultPass {
				return res, why, nil
			}
			if attempt == 9 {
				return res, why, nil
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return dbsim.ResultError, "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return dbsim.ResultError, "", fmt.Errorf("audit file unreadable: %w", lastErr)
}

// authOperation logs in once and runs the marked query on that same connection.
func authOperation(ctx context.Context, dsn, marker string) error {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("harness login: %w", err)
	}
	defer conn.Close()
	if err := conn.PingContext(ctx); err != nil {
		return fmt.Errorf("harness login: %w", err)
	}
	var id string
	if err := conn.QueryRowContext(ctx, "SELECT /* "+marker+" */ CONNECTION_ID()").Scan(&id); err != nil {
		return fmt.Errorf("marked query: %w", err)
	}
	return nil
}

func readRecords(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseRecords(f)
}
