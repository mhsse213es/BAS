package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	if code != 0 {
		panic("tests failed")
	}
}

// setupProbeTable creates a purpose-built, RLS-enabled fixture table for
// proving WithTenant in isolation — never a real production table, so this
// test can never affect any other package's Docker-backed tests.
// FORCE ROW LEVEL SECURITY is included because it's what production tables
// will need: the orchestrator's DB role owns the tables EnsureSchema creates,
// and a table's owner bypasses RLS unless FORCE is set.
func setupProbeTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	mustExec(t, pool, `CREATE TABLE IF NOT EXISTS tenant_isolation_probe (
		id        text PRIMARY KEY DEFAULT gen_random_uuid()::text,
		tenant_id text NOT NULL,
		label     text NOT NULL
	)`)
	mustExec(t, pool, `ALTER TABLE tenant_isolation_probe ENABLE ROW LEVEL SECURITY`)
	mustExec(t, pool, `ALTER TABLE tenant_isolation_probe FORCE ROW LEVEL SECURITY`)
	mustExec(t, pool, `DROP POLICY IF EXISTS tenant_isolation ON tenant_isolation_probe`)
	mustExec(t, pool, `CREATE POLICY tenant_isolation ON tenant_isolation_probe
		USING (
			tenant_id = current_setting('app.tenant_id', true)
			OR current_setting('app.is_platform_admin', true) = 'true'
		)`)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS tenant_isolation_probe`)
	})
}

// probePool returns a pool connected as a non-superuser role subject to RLS.
// The harness's own pool connects as the container's bootstrap user, which
// Postgres makes a SUPERUSER — and superusers bypass row security entirely
// (as do BYPASSRLS roles; table owners do too unless FORCE ROW LEVEL
// SECURITY is set). Proving isolation through the superuser pool would be
// vacuous — the first run of this suite caught exactly that. This is also
// the production requirement in miniature: the orchestrator must connect as
// a non-superuser role for RLS to enforce anything at all.
func probePool(t *testing.T, pool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	mustExec(t, pool, `DO $$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rls_probe_user') THEN
			CREATE ROLE rls_probe_user LOGIN PASSWORD 'rls_probe_pw' NOSUPERUSER NOBYPASSRLS;
		END IF;
	END $$`)
	mustExec(t, pool, `GRANT USAGE ON SCHEMA public TO rls_probe_user`)
	mustExec(t, pool, `GRANT SELECT, INSERT ON tenant_isolation_probe TO rls_probe_user`)

	cfg := pool.Config().Copy()
	cfg.ConnConfig.User = "rls_probe_user"
	cfg.ConnConfig.Password = "rls_probe_pw"
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("probe pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func TestWithTenant_IsolatesRowsBetweenTenants(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		setupProbeTable(t, pool)
		probe := probePool(t, pool)
		ctx := context.Background()

		// Seed one row per tenant, each written under its own WithTenant scope
		// (proving writes are scoped too, not just reads — the policy's USING
		// clause doubles as the WITH CHECK for INSERTs).
		if err := db.WithTenant(ctx, probe, "tenant-a", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO tenant_isolation_probe (tenant_id, label) VALUES ('tenant-a', 'a-row')`)
			return err
		}); err != nil {
			t.Fatalf("seed tenant-a: %v", err)
		}
		if err := db.WithTenant(ctx, probe, "tenant-b", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO tenant_isolation_probe (tenant_id, label) VALUES ('tenant-b', 'b-row')`)
			return err
		}); err != nil {
			t.Fatalf("seed tenant-b: %v", err)
		}

		// Tenant A's session must not see tenant B's row, even via a query
		// with no WHERE tenant_id clause at all — the whole point of RLS.
		var gotLabels []string
		err := db.WithTenant(ctx, probe, "tenant-a", false, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT label FROM tenant_isolation_probe`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var label string
				if err := rows.Scan(&label); err != nil {
					return err
				}
				gotLabels = append(gotLabels, label)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatalf("query as tenant-a: %v", err)
		}
		if len(gotLabels) != 1 || gotLabels[0] != "a-row" {
			t.Fatalf("tenant-a saw %v, want exactly [a-row]", gotLabels)
		}
	})
}

func TestWithTenant_PlatformAdminSeesEveryTenant(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		setupProbeTable(t, pool)
		probe := probePool(t, pool)
		ctx := context.Background()

		if err := db.WithTenant(ctx, probe, "tenant-a", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO tenant_isolation_probe (tenant_id, label) VALUES ('tenant-a', 'a-row')`)
			return err
		}); err != nil {
			t.Fatalf("seed tenant-a: %v", err)
		}
		if err := db.WithTenant(ctx, probe, "tenant-b", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO tenant_isolation_probe (tenant_id, label) VALUES ('tenant-b', 'b-row')`)
			return err
		}); err != nil {
			t.Fatalf("seed tenant-b: %v", err)
		}

		var count int
		// isPlatformAdmin=true, tenantID irrelevant (empty) — the RLS policy's
		// OR-bypass clause must grant visibility into every tenant's rows,
		// through the same non-superuser role (NOT via superuser privilege).
		err := db.WithTenant(ctx, probe, "", true, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM tenant_isolation_probe`).Scan(&count)
		})
		if err != nil {
			t.Fatalf("query as platform-admin: %v", err)
		}
		if count != 2 {
			t.Fatalf("platform-admin saw %d rows, want 2", count)
		}
	})
}

func TestWithTenant_SetLocalDoesNotLeakAcrossTransactions(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		setupProbeTable(t, pool)
		probe := probePool(t, pool)
		ctx := context.Background()

		if err := db.WithTenant(ctx, probe, "tenant-a", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO tenant_isolation_probe (tenant_id, label) VALUES ('tenant-a', 'a-row')`)
			return err
		}); err != nil {
			t.Fatalf("seed as tenant-a: %v", err)
		}

		// Run many sequential WithTenant calls with alternating tenant context
		// on the same pool (which reuses connections) — set_config(..., true)
		// is transaction-scoped, so none of these should ever see the other
		// tenant's row.
		for i := range 10 {
			tenant := "tenant-a"
			if i%2 == 1 {
				tenant = "tenant-b"
			}
			var count int
			err := db.WithTenant(ctx, probe, tenant, false, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM tenant_isolation_probe`).Scan(&count)
			})
			if err != nil {
				t.Fatalf("iteration %d (%s): %v", i, tenant, err)
			}
			want := 0
			if tenant == "tenant-a" {
				want = 1
			}
			if count != want {
				t.Fatalf("iteration %d (%s): count = %d, want %d — SET LOCAL leaked across a pooled connection", i, tenant, count, want)
			}
		}
	})
}
