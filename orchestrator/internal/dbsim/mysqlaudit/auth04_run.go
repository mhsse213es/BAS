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

// RunFailedLogin is test 04 on the lab MySQL. It attempts one login as a made-up
// account with a wrong password. The attempt must be refused with MySQL error 1045,
// otherwise the run is ERROR. The audit trail is then read back independently.
func RunFailedLogin(ctx context.Context, cfg LabConfig, runID string) (dbsim.RunResult, string, error) {
	name, err := failedLoginName(runID)
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
		return dbsim.ResultSkipped, "audit_log plugin is not active: failed-login audit coverage cannot be tested", nil
	}

	since := time.Now().UTC().Add(-2 * time.Second)
	if err := refusedLogin(ctx, cfg.Addr, name); err != nil {
		return dbsim.ResultError, "", err
	}

	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		f, err := os.Open(cfg.AuditFile)
		if err == nil {
			recs, perr := ParseRecords(f)
			f.Close()
			if perr == nil {
				res, why := FailedLoginVerdict(recs, name, since)
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

// refusedLogin attempts a connect that must be refused with error 1045.
func refusedLogin(ctx context.Context, addr, name string) error {
	cfg := mysql.NewConfig()
	cfg.User = name
	cfg.Passwd = "not-a-real-password"
	cfg.Net = "tcp"
	cfg.Addr = addr
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err == nil {
		return fmt.Errorf("the attempt for %s succeeded; test 04 requires a refused login", name)
	} else {
		var me *mysql.MySQLError
		if !errors.As(err, &me) || me.Number != 1045 {
			return fmt.Errorf("expected access denied (1045) for %s, got: %w", name, err)
		}
	}
	return nil
}
