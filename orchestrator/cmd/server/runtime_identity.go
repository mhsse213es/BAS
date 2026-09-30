package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// assertRuntimeIdentity fails loudly if the runtime DB connection turns out
// to be privileged -- a future deployment/configuration mistake pointing
// DATABASE_URL back at a superuser or BYPASSRLS role must never pass
// silently, since RLS enforcement (a later phase) depends on this being
// false. See docs/superpowers/specs/2026-09-30-runtime-role-separation-design.md.
func assertRuntimeIdentity(ctx context.Context, pool *pgxpool.Pool) error {
	var rolsuper, rolbypassrls bool
	if err := pool.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&rolsuper, &rolbypassrls); err != nil {
		return fmt.Errorf("query current_user attributes: %w", err)
	}
	if rolsuper || rolbypassrls {
		return fmt.Errorf("runtime DB connection is privileged (rolsuper=%v rolbypassrls=%v) -- refusing to start on a bypassing identity", rolsuper, rolbypassrls)
	}
	return nil
}
