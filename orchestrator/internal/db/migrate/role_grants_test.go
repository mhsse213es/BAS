package migrate_test

// Ported from internal/db/app_role_test.go (pre-H1 db.EnsureAppRole). The
// per-boot password-sync test was dropped on purpose: migrate never resets
// bas_app's password implicitly (see TestRole_WrongConfiguredPassword...).

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db/migrate"
	"github.com/audspect/bas/internal/db/pgtest"
)

const appPW = "app-pw-testing-only"

// provisioned returns an admin conn and a bas_app conn on a migrated database.
func provisioned(t *testing.T) (admin, app *pgx.Conn, dsn string) {
	t.Helper()
	dsn = roleDSN(t)
	if _, err := migrate.Up(context.Background(), dsn, migrate.Options{AppPassword: appPW}); err != nil {
		t.Fatal(err)
	}
	admin = connectAs(t, dsn, "bas_user", "bas_user")
	return admin, connectAs(t, dsn, "bas_app", appPW), dsn
}

func TestRoleGrants_NonSuperuserNoBypassRLSOwnsNothing(t *testing.T) {
	ctx := context.Background()
	admin, _, _ := provisioned(t)
	var super, bypass bool
	if err := admin.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'bas_app'`).Scan(&super, &bypass); err != nil {
		t.Fatal(err)
	}
	if super || bypass {
		t.Fatalf("bas_app super=%v bypassrls=%v", super, bypass)
	}
	var owned int
	admin.QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE tableowner = 'bas_app'`).Scan(&owned)
	if owned != 0 {
		t.Fatalf("bas_app owns %d tables", owned)
	}
}

func TestRoleGrants_DMLOnExistingTable(t *testing.T) {
	ctx := context.Background()
	_, app, _ := provisioned(t)
	for _, q := range []string{
		`INSERT INTO tenants (id, name, slug, status) VALUES ('dml-test', 'DML Test', 'dml-test', 'active')`,
		`SELECT name FROM tenants WHERE id = 'dml-test'`,
		`UPDATE tenants SET name = 'Updated' WHERE id = 'dml-test'`,
		`DELETE FROM tenants WHERE id = 'dml-test'`,
	} {
		if _, err := app.Exec(ctx, q); err != nil {
			t.Fatalf("bas_app %q: %v", q, err)
		}
	}
}

func TestRoleGrants_SequenceUsage(t *testing.T) {
	_, app, _ := provisioned(t)
	// agent_op_logs.id is bigserial: table INSERT alone does not grant the sequence.
	if _, err := app.Exec(context.Background(), `INSERT INTO agent_op_logs (agent_id, message) VALUES ('seq-test-agent', 'hello')`); err != nil {
		t.Fatalf("bas_app INSERT into bigserial table: %v", err)
	}
}

func TestRoleGrants_AuditLogsAppendOnly(t *testing.T) {
	ctx := context.Background()
	_, app, _ := provisioned(t)
	if _, err := app.Exec(ctx, `INSERT INTO audit_logs (action, resource) VALUES ('test.action', 'test.resource')`); err != nil {
		t.Fatalf("bas_app INSERT on audit_logs: %v", err)
	}
	if _, err := app.Exec(ctx, `UPDATE audit_logs SET action = 'changed' WHERE action = 'test.action'`); err == nil {
		t.Fatal("bas_app UPDATE on audit_logs allowed")
	}
	if _, err := app.Exec(ctx, `DELETE FROM audit_logs WHERE action = 'test.action'`); err == nil {
		t.Fatal("bas_app DELETE on audit_logs allowed")
	}
}

func TestRoleGrants_CoverAllPublicTables(t *testing.T) {
	ctx := context.Background()
	admin, _, _ := provisioned(t)
	// MATERIALIZED: stops has_table_privilege() running on non-public relations.
	rows, err := admin.Query(ctx, `
		WITH pub_tables AS MATERIALIZED (
			SELECT table_name FROM information_schema.tables
			WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
		)
		SELECT table_name FROM pub_tables
		WHERE NOT has_table_privilege('bas_app', 'public.' || quote_ident(table_name), 'SELECT')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var missing []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		missing = append(missing, n)
	}
	if len(missing) > 0 {
		t.Fatalf("bas_app missing SELECT on: %v", missing)
	}
}

func TestRoleGrants_DefaultPrivilegesCoverFutureTables(t *testing.T) {
	ctx := context.Background()
	admin, app, _ := provisioned(t)
	// Created by the schema owner AFTER the role step: only ALTER DEFAULT
	// PRIVILEGES (not the one-time blanket GRANT) can cover it.
	pgtest.Exec(t, admin, `CREATE TABLE future_table_test (id text PRIMARY KEY, val text)`)
	if _, err := app.Exec(ctx, `INSERT INTO future_table_test (id, val) VALUES ('x', 'y')`); err != nil {
		t.Fatalf("bas_app INSERT into a later table: %v", err)
	}
}
