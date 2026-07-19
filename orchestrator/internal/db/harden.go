package db

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// breakGlassRole is the emergency superuser created before the runtime role is
// demoted, so a superuser always remains to re-promote it if needed:
//
//	ALTER ROLE bas_user SUPERUSER;   -- run as bas_breakglass
const breakGlassRole = "bas_breakglass"

// HardenRuntimeRole demotes the current database role to NOSUPERUSER/NOBYPASSRLS
// so Row-Level Security can enforce against it, after first ensuring a
// break-glass superuser (breakGlassRole) exists for recovery.
//
// It is a no-op when breakGlassPassword is empty (hardening not opted into) and
// idempotent across restarts: once the runtime role is already non-superuser it
// can no longer manage the break-glass role anyway, so a repeat run short-
// circuits before touching anything.
//
// It MUST be called after all superuser-requiring schema setup (EnsureSchema),
// because ALTER ROLE ... NOSUPERUSER drops this session's superuser privileges.
func HardenRuntimeRole(ctx context.Context, pool *pgxpool.Pool, breakGlassPassword string) error {
	if breakGlassPassword == "" {
		log.Println("[db] role hardening inactive (BAS_DB_BREAKGLASS_PASSWORD unset) — runtime role unchanged")
		return nil
	}

	// Short-circuit if already hardened. This MUST come first: a demoted
	// (non-superuser) role cannot CREATE or ALTER the break-glass superuser, so
	// attempting those on a second run would error. Checking rolsuper up front
	// is what makes repeat runs clean no-ops.
	var isSuper bool
	if err := pool.QueryRow(ctx,
		`SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&isSuper); err != nil {
		return fmt.Errorf("check current_user superuser: %w", err)
	}
	if !isSuper {
		log.Println("[db] runtime role already NOSUPERUSER — hardening is a no-op")
		return nil
	}

	// Still a superuser → ensure the break-glass recovery superuser, then demote.

	// 1. Create the break-glass role if absent.
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)`, breakGlassRole).Scan(&exists); err != nil {
		return fmt.Errorf("check break-glass role: %w", err)
	}
	if !exists {
		if _, err := pool.Exec(ctx, `CREATE ROLE `+breakGlassRole+` LOGIN SUPERUSER`); err != nil {
			return fmt.Errorf("create break-glass role: %w", err)
		}
		log.Printf("[db] created break-glass superuser %q for RLS recovery", breakGlassRole)
	}

	// 2. Set its password from the env value, kept in sync each hardened boot.
	//    format(%I, %L) escapes the identifier and literal server-side —
	//    CREATE/ALTER ROLE take no bind parameters, so this is the safe path.
	var alterStmt string
	if err := pool.QueryRow(ctx,
		`SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text)`,
		breakGlassRole, breakGlassPassword).Scan(&alterStmt); err != nil {
		return fmt.Errorf("build break-glass password stmt: %w", err)
	}
	if _, err := pool.Exec(ctx, alterStmt); err != nil {
		return fmt.Errorf("set break-glass password: %w", err)
	}

	// 3. Demote the current (runtime) role — the last superuser-requiring step.
	//    CURRENT_USER is resolved server-side; no role name is interpolated.
	if _, err := pool.Exec(ctx, `ALTER ROLE CURRENT_USER NOSUPERUSER NOBYPASSRLS`); err != nil {
		return fmt.Errorf("demote runtime role: %w", err)
	}
	log.Println("[db] runtime role demoted to NOSUPERUSER/NOBYPASSRLS — RLS can now enforce once enabled")
	return nil
}
