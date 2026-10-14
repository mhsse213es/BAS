package tcv

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the subset of pgx shared by *pgxpool.Pool and pgx.Tx, letting
// clocks.go/coverage.go's write functions run inside a caller's own
// transaction (contentregistry folds these into Transition/
// AttachVendorSignature/createVersion/LinkThreat) or standalone (the
// connector scheduler has no surrounding transaction for a clock start).
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store is the read side: Metrics (metrics.go). Writes go through the
// package-level functions in clocks.go/coverage.go instead, so a caller
// that already has a transaction open never needs a second connection.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }
