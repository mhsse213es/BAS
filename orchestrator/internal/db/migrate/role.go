package migrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// AppRole is the orchestrator's runtime identity: NOSUPERUSER, NOBYPASSRLS,
// DML only, never an owner (runtime role separation, 2026-09-30).
const AppRole = "bas_app"

// ErrAppPasswordMismatch: the configured password does not log in as bas_app.
// migrate never resets the password implicitly; rotation is explicit.
var ErrAppPasswordMismatch = errors.New("bas_app password does not match BAS_APP_DB_PASSWORD -- run: install.sh --rotate-db-app-password")

// ensureRole creates bas_app when absent (setting appPassword), re-applies its
// grants, then proves appPassword logs in. It never changes an existing
// role's password.
func ensureRole(ctx context.Context, conn *pgx.Conn, appPassword, adminDSN string) (created bool, err error) {
	if appPassword == "" {
		return false, errors.New("bas_app password is empty (BAS_APP_DB_PASSWORD)")
	}
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, AppRole).Scan(&exists); err != nil {
		return false, err
	}
	if !exists {
		if _, err := conn.Exec(ctx, `CREATE ROLE `+AppRole+` LOGIN NOSUPERUSER NOBYPASSRLS`); err != nil {
			return false, fmt.Errorf("create bas_app role: %w", err)
		}
		if err := setPassword(ctx, conn, appPassword); err != nil {
			return false, err
		}
		created = true
	}
	if err := grantApp(ctx, conn); err != nil {
		return created, err
	}
	return created, verifyAppLogin(ctx, adminDSN, appPassword)
}

// setPassword uses format(%I, %L) because ALTER ROLE takes no bind parameters.
func setPassword(ctx context.Context, conn *pgx.Conn, password string) error {
	var stmt string
	if err := conn.QueryRow(ctx, `SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text)`,
		AppRole, password).Scan(&stmt); err != nil {
		return fmt.Errorf("build bas_app password stmt: %w", err)
	}
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("set bas_app password: %w", err)
	}
	return nil
}

// grantApp is the grant block of the pre-H1 db.EnsureAppRole, unchanged.
func grantApp(ctx context.Context, conn *pgx.Conn) error {
	var grantConnectStmt string
	if err := conn.QueryRow(ctx,
		`SELECT format('GRANT CONNECT ON DATABASE %I TO `+AppRole+`', current_database())`,
	).Scan(&grantConnectStmt); err != nil {
		return fmt.Errorf("build grant connect stmt: %w", err)
	}
	if _, err := conn.Exec(ctx, grantConnectStmt); err != nil {
		return fmt.Errorf("grant connect: %w", err)
	}
	grants := []string{
		`GRANT USAGE ON SCHEMA public TO ` + AppRole,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + AppRole,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public
			GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ` + AppRole,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ` + AppRole,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public
			GRANT USAGE, SELECT ON SEQUENCES TO ` + AppRole,
		// audit_logs is append-only; must follow the blanket grant above.
		`REVOKE UPDATE, DELETE ON audit_logs FROM ` + AppRole,
	}
	for _, stmt := range grants {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("grant provisioning (%q): %w", stmt, err)
		}
	}
	return nil
}

// verifyAppLogin connects as bas_app with password to adminDSN's database.
func verifyAppLogin(ctx context.Context, adminDSN, password string) error {
	cfg, err := pgx.ParseConfig(adminDSN)
	if err != nil {
		return err
	}
	cfg.User, cfg.Password = AppRole, password
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "28P01" {
			return ErrAppPasswordMismatch
		}
		return fmt.Errorf("connect as bas_app: %w", err)
	}
	defer c.Close(context.Background())
	return c.Ping(ctx)
}

// RotateAppPassword sets bas_app's password (install.sh
// --rotate-db-app-password) and proves the new one logs in.
func RotateAppPassword(ctx context.Context, adminDSN, newPassword string) error {
	if newPassword == "" {
		return errors.New("new bas_app password is empty")
	}
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(context.Background())
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, AppRole).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errors.New("bas_app does not exist -- run: orchestrator migrate up")
	}
	if err := setPassword(ctx, conn, newPassword); err != nil {
		return err
	}
	return verifyAppLogin(ctx, adminDSN, newPassword)
}
