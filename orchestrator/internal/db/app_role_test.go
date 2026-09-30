package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

const testAppPassword = "app-pw-testing-only"

// appConnectedPool returns a pool connected as bas_app. Callers must have
// already called db.EnsureAppRole(ctx, admin, testAppPassword) first.
func appConnectedPool(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	cfg := admin.Config().Copy()
	cfg.ConnConfig.User = "bas_app"
	cfg.ConnConfig.Password = testAppPassword
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("bas_app pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestEnsureAppRole_CreatesNonSuperuserNoBypassRLS(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := db.EnsureAppRole(context.Background(), pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		var rolsuper, rolbypassrls bool
		if err := pool.QueryRow(context.Background(),
			`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'bas_app'`,
		).Scan(&rolsuper, &rolbypassrls); err != nil {
			t.Fatalf("read bas_app attrs: %v", err)
		}
		if rolsuper || rolbypassrls {
			t.Fatalf("bas_app should be NOSUPERUSER/NOBYPASSRLS, got super=%v bypassrls=%v", rolsuper, rolbypassrls)
		}
	})
}

func TestEnsureAppRole_IdempotentOnRetry(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("first EnsureAppRole: %v", err)
		}
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("second EnsureAppRole (idempotent) errored: %v", err)
		}
	})
}

func TestEnsureAppRole_PasswordSyncsOnRepeatedCalls(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, "first-password"); err != nil {
			t.Fatalf("first EnsureAppRole: %v", err)
		}
		if err := db.EnsureAppRole(ctx, pool, "second-password"); err != nil {
			t.Fatalf("second EnsureAppRole: %v", err)
		}

		cfg := pool.Config().Copy()
		cfg.ConnConfig.User = "bas_app"
		cfg.ConnConfig.Password = "second-password"
		p, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("connect with rotated password: %v", err)
		}
		defer p.Close()
		if err := p.Ping(ctx); err != nil {
			t.Fatalf("ping with rotated password: %v", err)
		}
	})
}

func TestEnsureAppRole_OwnsNoTables(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := db.EnsureAppRole(context.Background(), pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM pg_tables WHERE tableowner = 'bas_app'`,
		).Scan(&count); err != nil {
			t.Fatalf("count owned tables: %v", err)
		}
		if count != 0 {
			t.Fatalf("bas_app should own zero tables, owns %d", count)
		}
	})
}

func TestEnsureAppRole_GrantsDMLOnExistingTable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		app := appConnectedPool(t, pool)

		if _, err := app.Exec(ctx,
			`INSERT INTO tenants (id, name, slug, status) VALUES ('dml-test','DML Test','dml-test','active')
			 ON CONFLICT (id) DO NOTHING`); err != nil {
			t.Fatalf("bas_app INSERT on tenants: %v", err)
		}
		var name string
		if err := app.QueryRow(ctx, `SELECT name FROM tenants WHERE id = 'dml-test'`).Scan(&name); err != nil {
			t.Fatalf("bas_app SELECT on tenants: %v", err)
		}
		if _, err := app.Exec(ctx, `UPDATE tenants SET name = 'Updated' WHERE id = 'dml-test'`); err != nil {
			t.Fatalf("bas_app UPDATE on tenants: %v", err)
		}
		if _, err := app.Exec(ctx, `DELETE FROM tenants WHERE id = 'dml-test'`); err != nil {
			t.Fatalf("bas_app DELETE on tenants: %v", err)
		}
	})
}

func TestEnsureAppRole_GrantsSequenceUsage(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		app := appConnectedPool(t, pool)

		// agent_op_logs.id is bigserial -- table-level INSERT alone does not
		// grant use of the backing sequence (verified empirically during
		// design). This proves the separate sequence grant actually works.
		if _, err := app.Exec(ctx,
			`INSERT INTO agent_op_logs (agent_id, message) VALUES ('seq-test-agent', 'hello')`); err != nil {
			t.Fatalf("bas_app INSERT into bigserial-keyed table: %v", err)
		}
	})
}

func TestEnsureAppRole_AuditLogsUpdateDeleteRevoked(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		app := appConnectedPool(t, pool)

		if _, err := app.Exec(ctx,
			`INSERT INTO audit_logs (action, resource) VALUES ('test.action', 'test.resource')`); err != nil {
			t.Fatalf("bas_app INSERT on audit_logs should succeed: %v", err)
		}
		if _, err := app.Exec(ctx, `UPDATE audit_logs SET action = 'changed' WHERE action = 'test.action'`); err == nil {
			t.Fatal("bas_app UPDATE on audit_logs should be rejected, succeeded instead")
		}
		if _, err := app.Exec(ctx, `DELETE FROM audit_logs WHERE action = 'test.action'`); err == nil {
			t.Fatal("bas_app DELETE on audit_logs should be rejected, succeeded instead")
		}
	})
}

func TestEnsureAppRole_DefaultPrivilegesCoverFutureTables(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}

		// A table created by the admin role AFTER EnsureAppRole already ran --
		// proves ALTER DEFAULT PRIVILEGES, not just the one-time blanket
		// GRANT, is what covers it.
		if _, err := pool.Exec(ctx,
			`CREATE TABLE IF NOT EXISTS future_table_test (id text PRIMARY KEY, val text)`); err != nil {
			t.Fatalf("create future_table_test: %v", err)
		}

		app := appConnectedPool(t, pool)
		if _, err := app.Exec(ctx,
			`INSERT INTO future_table_test (id, val) VALUES ('x','y')`); err != nil {
			t.Fatalf("bas_app INSERT into a table created after EnsureAppRole: %v", err)
		}
	})
}
