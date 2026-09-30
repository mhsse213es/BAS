package main

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

func TestAssertRuntimeIdentity_FailsForSuperuser(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	if err := assertRuntimeIdentity(context.Background(), tdb.Pool); err == nil {
		t.Fatal("expected an error for a superuser connection, got nil")
	}
}

func TestAssertRuntimeIdentity_PassesForNonPrivilegedRole(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	if _, err := tdb.Pool.Exec(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'identity_probe_ok') THEN
			CREATE ROLE identity_probe_ok LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'x';
		END IF;
	END $$`); err != nil {
		t.Fatalf("create identity_probe_ok: %v", err)
	}
	t.Cleanup(func() { _, _ = tdb.Pool.Exec(ctx, `DROP ROLE IF EXISTS identity_probe_ok`) })

	cfg := tdb.Pool.Config().Copy()
	cfg.ConnConfig.User = "identity_probe_ok"
	cfg.ConnConfig.Password = "x"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect as identity_probe_ok: %v", err)
	}
	defer p.Close()

	if err := assertRuntimeIdentity(ctx, p); err != nil {
		t.Fatalf("expected nil for a non-privileged role, got: %v", err)
	}
}

func TestAssertRuntimeIdentity_FailsForBypassRLSRole(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	if _, err := tdb.Pool.Exec(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'identity_probe_bypass') THEN
			CREATE ROLE identity_probe_bypass LOGIN NOSUPERUSER BYPASSRLS PASSWORD 'x';
		END IF;
	END $$`); err != nil {
		t.Fatalf("create identity_probe_bypass: %v", err)
	}
	t.Cleanup(func() { _, _ = tdb.Pool.Exec(ctx, `DROP ROLE IF EXISTS identity_probe_bypass`) })

	cfg := tdb.Pool.Config().Copy()
	cfg.ConnConfig.User = "identity_probe_bypass"
	cfg.ConnConfig.Password = "x"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect as identity_probe_bypass: %v", err)
	}
	defer p.Close()

	if err := assertRuntimeIdentity(ctx, p); err == nil {
		t.Fatal("expected an error for a BYPASSRLS role, got nil")
	}
}
