package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// appRole is the orchestrator's runtime PostgreSQL identity -- created
// NOSUPERUSER/NOBYPASSRLS and granted no ownership, so RLS enforcement
// (activated in a later phase, not this one) can actually apply to it. See
// docs/superpowers/specs/2026-09-30-runtime-role-separation-design.md.
const appRole = "bas_app"

// EnsureAppRole provisions the bas_app runtime role: creates it if absent
// (idempotent), syncs its password every call (so a rotated
// BAS_APP_DB_PASSWORD takes effect on the next restart), and grants it
// exactly the DML privileges normal application traffic needs -- never
// ownership, never DDL. Must be called from the bootstrap connection (a
// superuser/schema-owner role, e.g. bas_user), after every Ensure*Schema
// call has created every table bas_app needs granted.
func EnsureAppRole(ctx context.Context, pool *pgxpool.Pool, appPassword string) error {
	if appPassword == "" {
		return fmt.Errorf("EnsureAppRole: appPassword must not be empty")
	}

	if _, err := pool.Exec(ctx, `DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '`+appRole+`') THEN
				CREATE ROLE `+appRole+` LOGIN NOSUPERUSER NOBYPASSRLS;
			END IF;
		END $$`); err != nil {
		return fmt.Errorf("create bas_app role: %w", err)
	}

	// Password kept in sync every boot -- format(%I, %L) escapes
	// server-side, since CREATE/ALTER ROLE take no bind parameters
	// (same pattern the retired harden.go used for bas_breakglass).
	var alterStmt string
	if err := pool.QueryRow(ctx,
		`SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text)`,
		appRole, appPassword).Scan(&alterStmt); err != nil {
		return fmt.Errorf("build bas_app password stmt: %w", err)
	}
	if _, err := pool.Exec(ctx, alterStmt); err != nil {
		return fmt.Errorf("set bas_app password: %w", err)
	}

	// GRANT CONNECT needs a literal database name -- current_database()
	// keeps this correct under both bas_platform (production) and the test
	// harness's bas_test, without hardcoding either.
	var grantConnectStmt string
	if err := pool.QueryRow(ctx,
		`SELECT format('GRANT CONNECT ON DATABASE %I TO `+appRole+`', current_database())`,
	).Scan(&grantConnectStmt); err != nil {
		return fmt.Errorf("build grant connect stmt: %w", err)
	}
	if _, err := pool.Exec(ctx, grantConnectStmt); err != nil {
		return fmt.Errorf("grant connect: %w", err)
	}

	grants := []string{
		`GRANT USAGE ON SCHEMA public TO ` + appRole,

		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + appRole,
		// No "FOR ROLE bas_user" clause: omitted, ALTER DEFAULT PRIVILEGES
		// defaults to the CURRENT session's role, which keeps this correct
		// whether the bootstrap connection is bas_user (production) or
		// bas_test (this package's own test harness) -- no literal role
		// name to keep in sync between the two.
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public
			GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ` + appRole,

		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ` + appRole,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public
			GRANT USAGE, SELECT ON SEQUENCES TO ` + appRole,

		// audit_logs is documented as "immutable, append-only" (postgres.go)
		// -- carve out UPDATE/DELETE at the DB layer for defense-in-depth,
		// not just app-code discipline. Must run AFTER the blanket grant
		// above (a REVOKE before the matching GRANT would have nothing to
		// narrow).
		`REVOKE UPDATE, DELETE ON audit_logs FROM ` + appRole,
	}
	for _, stmt := range grants {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("grant provisioning (%q): %w", stmt, err)
		}
	}

	return nil
}
