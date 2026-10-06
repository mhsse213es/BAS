// Package legacy is the frozen pre-H1 boot-time schema chain. It is called only
// by migrate adoption to bring a pre-H1 install up to 000001_baseline. Never
// edit: schema changes are new migrations (internal/db/migrations/README.md).
package legacy

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB is satisfied by *pgxpool.Pool and pgx.Tx (Begin on a Tx is a savepoint).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// EnsureAll runs the chain in the order cmd/server/main.go used before H1.
func EnsureAll(ctx context.Context, db DB) error {
	for _, f := range []func(context.Context, DB) error{
		EnsureSchema, EnsureContentSchema, EnsureIOCSchema, EnsureIOCEnrichmentSchema,
		EnsureAgentGroupSchema, EnsureAgentUninstallSchema, EnsureExerciseSchema,
		EnsureContentRegistrySchema, EnsureThreatIdentitySchema,
	} {
		if err := f(ctx, db); err != nil {
			return err
		}
	}
	return nil
}
