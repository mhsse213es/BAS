package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

// hardenProbePool creates a disposable LOGIN SUPERUSER role and returns a pool
// connected as it, so HardenRuntimeRole demotes THAT role, never the shared
// test container's own connection (which would break every sibling test).
// Mirrors tenant_test.go's probePool discipline.
func hardenProbePool(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	mustExec(t, admin, `DO $$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'harden_probe') THEN
			CREATE ROLE harden_probe LOGIN SUPERUSER PASSWORD 'harden_pw';
		END IF;
	END $$`)
	t.Cleanup(func() {
		// bas_breakglass is created by HardenRuntimeRole; drop both so the
		// shared container stays clean for other tests.
		_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS bas_breakglass`)
		_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS harden_probe`)
	})

	cfg := admin.Config().Copy()
	cfg.ConnConfig.User = "harden_probe"
	cfg.ConnConfig.Password = "harden_pw"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("harden probe pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestHardenRuntimeRole_DemotesAndCreatesBreakGlass(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		probe := hardenProbePool(t, pool)
		ctx := context.Background()

		if err := db.HardenRuntimeRole(ctx, probe, "break-glass-secret"); err != nil {
			t.Fatalf("HardenRuntimeRole: %v", err)
		}

		var rolsuper, rolbypassrls bool
		if err := pool.QueryRow(ctx,
			`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'harden_probe'`).Scan(&rolsuper, &rolbypassrls); err != nil {
			t.Fatalf("read harden_probe attrs: %v", err)
		}
		if rolsuper || rolbypassrls {
			t.Fatalf("harden_probe should be NOSUPERUSER/NOBYPASSRLS, got super=%v bypassrls=%v", rolsuper, rolbypassrls)
		}

		var bgSuper bool
		if err := pool.QueryRow(ctx,
			`SELECT rolsuper FROM pg_roles WHERE rolname = 'bas_breakglass'`).Scan(&bgSuper); err != nil {
			t.Fatalf("read bas_breakglass: %v", err)
		}
		if !bgSuper {
			t.Fatal("bas_breakglass should exist as a superuser")
		}

		// Idempotent: a second call on the already-demoted role is a clean no-op
		// (and must NOT error trying to manage break-glass without privilege).
		if err := db.HardenRuntimeRole(ctx, probe, "break-glass-secret"); err != nil {
			t.Fatalf("second HardenRuntimeRole (idempotent) errored: %v", err)
		}
		if err := pool.QueryRow(ctx,
			`SELECT rolsuper FROM pg_roles WHERE rolname = 'harden_probe'`).Scan(&rolsuper); err != nil {
			t.Fatalf("re-read harden_probe: %v", err)
		}
		if rolsuper {
			t.Fatal("harden_probe was re-promoted — not idempotent")
		}
	})
}

func TestHardenRuntimeRole_NoopWhenPasswordEmpty(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		// Empty password on the harness pool must be a pure no-op — it must NOT
		// demote the shared container's connecting superuser.
		if err := db.HardenRuntimeRole(ctx, pool, ""); err != nil {
			t.Fatalf("empty-password HardenRuntimeRole should be nil, got %v", err)
		}
		var rolsuper bool
		if err := pool.QueryRow(ctx,
			`SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&rolsuper); err != nil {
			t.Fatalf("read current_user: %v", err)
		}
		if !rolsuper {
			t.Fatal("empty-password call must not demote the connecting role")
		}
	})
}
