package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

const testPurgePassword = "purge-pw-testing-only"

// purgerConnectedPool returns a pool connected as bas_audit_purger. Callers must have already called
// db.EnsurePurgeRole(ctx, admin, testPurgePassword).
func purgerConnectedPool(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	cfg := admin.Config().Copy()
	cfg.ConnConfig.User = "bas_audit_purger"
	cfg.ConnConfig.Password = testPurgePassword
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("bas_audit_purger pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

// The purge role is granted SELECT and DELETE on audit_logs and nothing else.
func TestEnsurePurgeRole_GrantsOnlyAuditSelectAndDelete(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsurePurgeRole(ctx, pool, testPurgePassword); err != nil {
			t.Fatalf("EnsurePurgeRole: %v", err)
		}
		rows, err := pool.Query(ctx, `SELECT table_name, privilege_type FROM information_schema.role_table_grants
			WHERE grantee = 'bas_audit_purger' ORDER BY table_name, privilege_type`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		got := map[string]bool{}
		for rows.Next() {
			var tbl, priv string
			if err := rows.Scan(&tbl, &priv); err != nil {
				t.Fatal(err)
			}
			got[tbl+":"+priv] = true
		}
		want := map[string]bool{"audit_logs:SELECT": true, "audit_logs:DELETE": true}
		for k := range got {
			if !want[k] {
				t.Errorf("purge role has unexpected grant %s", k)
			}
		}
		for k := range want {
			if !got[k] {
				t.Errorf("purge role is missing grant %s", k)
			}
		}
	})
}

// bas_app keeps its restriction: it cannot delete audit records.
func TestPermissionIsolation_AppRoleCannotDeleteAuditRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO audit_logs (action) VALUES ('isolation-test')`); err != nil {
			t.Fatal(err)
		}
		app := appConnectedPool(t, pool)
		if _, err := app.Exec(ctx, `DELETE FROM audit_logs`); err == nil {
			t.Fatal("bas_app deleted audit rows; it must not be able to")
		}
	})
}

// The purge role deletes audit rows, and cannot update them or touch other tables.
func TestPermissionIsolation_PurgeRoleDeletesAuditRowsOnly(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsurePurgeRole(ctx, pool, testPurgePassword); err != nil {
			t.Fatalf("EnsurePurgeRole: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO audit_logs (action) VALUES ('purge-isolation-test')`); err != nil {
			t.Fatal(err)
		}
		p := purgerConnectedPool(t, pool)
		if _, err := p.Exec(ctx, `UPDATE audit_logs SET action = 'changed'`); err == nil {
			t.Error("purge role updated audit rows; it must not be able to")
		}
		if _, err := p.Exec(ctx, `DELETE FROM scenarios WHERE false`); err == nil {
			t.Error("purge role touched a table other than audit_logs")
		}
		if _, err := p.Exec(ctx, `DELETE FROM audit_logs WHERE action = 'purge-isolation-test'`); err != nil {
			t.Errorf("purge role could not delete an audit row: %v", err)
		}
	})
}
