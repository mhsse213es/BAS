// tenant.go provides the transaction-scoping seam every tenant-aware query
// must go through. Session-scoping uses Postgres's set_config() rather than a
// raw `SET LOCAL ... = $1` (which is not valid SQL — SET does not accept bind
// parameters) or string concatenation (which would be an injection risk). See
// docs/superpowers/specs/2026-07-18-phase7-multi-tenancy-design.md.
package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithTenant runs fn inside a transaction whose Postgres session variables
// (app.tenant_id, app.is_platform_admin) are set for Row-Level Security
// policies to key off. Both variables are set via set_config(..., true) —
// the `true` third argument makes them LOCAL, i.e. scoped to this
// transaction only, so they can never leak into a pooled connection's next,
// unrelated use.
func WithTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, isPlatformAdmin bool, fn func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
		return err
	}
	adminFlag := "false"
	if isPlatformAdmin {
		adminFlag = "true"
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.is_platform_admin', $1, true)`, adminFlag); err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
