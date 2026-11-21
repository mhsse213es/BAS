package mysqlaudit

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/audspect/bas/internal/dbsim"
)

const fixtureSchema = "dbsim_audit_fixture"

// RunPrivilegedFlush is test 05: a harmless privileged operation (FLUSH STATUS needs
// global RELOAD, granted to the fixture account for this test only) must be audited.
func RunPrivilegedFlush(ctx context.Context, cfg LabConfig, runID string) (dbsim.RunResult, string, error) {
	marker, err := fixtureMarker(runID)
	if err != nil {
		return dbsim.ResultError, "", err
	}
	return runFixture(ctx, cfg, marker, []string{"FLUSH STATUS"}, []string{"FLUSH STATUS"}, nil)
}

// RunGrantRevoke is test 06: a controlled grant and revoke of SELECT on the synthetic
// table, to the harness account. Cleanup is verified by a harness login that must be
// refused reading the table after the revoke.
func RunGrantRevoke(ctx context.Context, cfg LabConfig, runID string) (dbsim.RunResult, string, error) {
	marker, err := fixtureMarker(runID)
	if err != nil {
		return dbsim.ResultError, "", err
	}
	ops := []string{
		"GRANT SELECT ON " + fixtureSchema + ".sensitive_synth TO '" + HarnessUser + "'@'%'",
		"REVOKE SELECT ON " + fixtureSchema + ".sensitive_synth FROM '" + HarnessUser + "'@'%'",
	}
	verify := func(ctx context.Context) error { return harnessCannotRead(ctx, cfg, fixtureSchema+".sensitive_synth") }
	return runFixture(ctx, cfg, marker, ops, []string{"GRANT SELECT", "REVOKE SELECT"}, verify)
}

// RunSensitiveRead is test 07: the fixture account reads the synthetic sensitive table.
func RunSensitiveRead(ctx context.Context, cfg LabConfig, runID string) (dbsim.RunResult, string, error) {
	marker, err := fixtureMarker(runID)
	if err != nil {
		return dbsim.ResultError, "", err
	}
	return runFixture(ctx, cfg, marker, []string{"SELECT label FROM " + fixtureSchema + ".sensitive_synth"}, []string{"sensitive_synth"}, nil)
}

// RunDDL is test 08: create and drop a disposable table in the fixture schema.
// Cleanup is verified by the table's absence from information_schema.
func RunDDL(ctx context.Context, cfg LabConfig, runID string) (dbsim.RunResult, string, error) {
	marker, err := fixtureMarker(runID)
	if err != nil {
		return dbsim.ResultError, "", err
	}
	table := fixtureSchema + ".ddl_" + runID
	ops := []string{"CREATE TABLE " + table + " (id INT)", "DROP TABLE " + table}
	verify := func(ctx context.Context) error { return tableAbsent(ctx, cfg, "ddl_"+runID) }
	return runFixture(ctx, cfg, marker, ops, []string{"CREATE TABLE", "DROP TABLE"}, verify)
}

// harnessCannotRead logs in as the harness account and requires error 1142 reading table.
func harnessCannotRead(ctx context.Context, cfg LabConfig, table string) error {
	dsn, err := DSNFromFile(cfg.PasswordFile, cfg.Addr)
	if err != nil {
		return err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	var n int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n)
	if err == nil {
		return fmt.Errorf("harness account can still read %s: the revoke did not take effect", table)
	}
	if !refusedAs(err, 1142) {
		return fmt.Errorf("expected SELECT denied (1142) for the harness account, got: %w", err)
	}
	return nil
}

// tableAbsent confirms a table is gone from the fixture schema.
func tableAbsent(ctx context.Context, cfg LabConfig, name string) error {
	db, err := fixtureDB(cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	var n int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = ?", fixtureSchema, name).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("table %s still exists after DROP", name)
	}
	return nil
}
