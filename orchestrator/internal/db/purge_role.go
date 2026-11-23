package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

const purgeRole = "bas_audit_purger"

// EnsurePurgeRole creates the role that deletes audit rows during a purge. It is not the application role:
// it is not a superuser, owns nothing, and holds SELECT and DELETE on audit_logs only. The application role keeps
// its restriction (no DELETE on audit_logs). Purge credentials are kept separate from application credentials.
func EnsurePurgeRole(ctx context.Context, pool *pgxpool.Pool, purgePassword string) error {
	if purgePassword == "" {
		return fmt.Errorf("EnsurePurgeRole: purgePassword must not be empty")
	}
	if _, err := pool.Exec(ctx, `DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '`+purgeRole+`') THEN
				CREATE ROLE `+purgeRole+` LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
			END IF;
		END $$`); err != nil {
		return fmt.Errorf("create %s role: %w", purgeRole, err)
	}

	var alterStmt string
	if err := pool.QueryRow(ctx,
		`SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text)`,
		purgeRole, purgePassword).Scan(&alterStmt); err != nil {
		return fmt.Errorf("build %s password stmt: %w", purgeRole, err)
	}
	if _, err := pool.Exec(ctx, alterStmt); err != nil {
		return fmt.Errorf("set %s password: %w", purgeRole, err)
	}

	var connectStmt string
	if err := pool.QueryRow(ctx,
		`SELECT format('GRANT CONNECT ON DATABASE %I TO `+purgeRole+`', current_database())`,
	).Scan(&connectStmt); err != nil {
		return fmt.Errorf("build connect stmt: %w", err)
	}
	stmts := []string{
		connectStmt,
		// Start from no table privileges, so nothing left over from an earlier grant survives.
		`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ` + purgeRole,
		`GRANT USAGE ON SCHEMA public TO ` + purgeRole,
		`GRANT SELECT, DELETE ON audit_logs TO ` + purgeRole,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("%s grant: %w", purgeRole, err)
		}
	}
	return nil
}
