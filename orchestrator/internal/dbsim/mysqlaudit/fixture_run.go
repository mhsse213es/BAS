package mysqlaudit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/audspect/bas/internal/dbsim"
)

// fixtureDB opens the dbsim_fixture account from its own password file.
func fixtureDB(cfg LabConfig) (*sql.DB, error) {
	dsn, err := dsnFromFileFor(cfg.FixturePasswordFile, cfg.Addr, FixtureUser)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// runFixture is the shared flow for tests 05-08: plugin check, marked operations as
// the fixture account, a cleanup check, then an independent audit readback.
// SKIPPED when audit_log is not active. ERROR when an operation is refused or the
// cleanup cannot be verified. Otherwise MarkedQueryVerdict decides.
func runFixture(ctx context.Context, cfg LabConfig, marker string, ops []string, want []string, verify func(context.Context) error) (dbsim.RunResult, string, error) {
	harness, err := harnessQuerier(cfg)
	if err != nil {
		return dbsim.ResultError, "", err
	}
	defer harness.DB.Close()
	rows, err := harness.Query(ctx, "SHOW PLUGINS")
	if err != nil {
		return dbsim.ResultError, "", fmt.Errorf("plugin check: %w", err)
	}
	if !PluginActive(rows) {
		return dbsim.ResultSkipped, "audit_log plugin is not active: this audit coverage cannot be tested", nil
	}

	db, err := fixtureDB(cfg)
	if err != nil {
		return dbsim.ResultError, "", err
	}
	defer db.Close()

	since := time.Now().UTC().Add(-2 * time.Second)
	for _, op := range ops {
		if _, err := db.ExecContext(ctx, "/* "+marker+" */ "+op); err != nil {
			return dbsim.ResultError, "", fmt.Errorf("operation refused, no verdict: %s: %w", op, err)
		}
	}
	if verify != nil {
		if err := verify(ctx); err != nil {
			return dbsim.ResultError, "", fmt.Errorf("cleanup not verified: %w", err)
		}
	}
	return awaitVerdict(ctx, cfg.AuditFile, func(recs []Record) (dbsim.RunResult, string) {
		return MarkedQueryVerdict(recs, marker, FixtureUser, since, want)
	})
}

// awaitVerdict reads the audit file, retrying briefly, until the verdict passes or the
// budget ends. An unreadable file is ERROR, never PASS.
func awaitVerdict(ctx context.Context, path string, check func([]Record) (dbsim.RunResult, string)) (dbsim.RunResult, string, error) {
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		f, err := os.Open(path)
		if err == nil {
			recs, perr := ParseRecords(f)
			f.Close()
			if perr == nil {
				res, why := check(recs)
				if res == dbsim.ResultPass || attempt == 9 {
					return res, why, nil
				}
			} else {
				lastErr = perr
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

// harnessQuerier opens the harness account (no grants) for the plugin check.
func harnessQuerier(cfg LabConfig) (*SQLQuerier, error) {
	dsn, err := DSNFromFile(cfg.PasswordFile, cfg.Addr)
	if err != nil {
		return nil, err
	}
	return OpenSQLQuerier(dsn)
}

// refusedAs reports whether err is MySQL error number n.
func refusedAs(err error, n uint16) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && me.Number == n
}
