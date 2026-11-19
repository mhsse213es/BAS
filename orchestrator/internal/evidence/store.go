package evidence

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/tcv"
)

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// RecordPipelineEvent appends one TCV SLA ledger event (write-once,
// log-and-continue via tcv.RecordPipelineEvent). It lives here so the
// generator -- which reaches the DB only through its evidence store -- can
// emit pipeline events without a separate pool handle; the ledger is
// observability of the same family as generation attempts. tcv imports no
// evidence types, so this dependency is acyclic.
func (s *Store) RecordPipelineEvent(ctx context.Context, e tcv.Event) error {
	return tcv.RecordPipelineEvent(ctx, s.pool, e)
}

// Querier is the subset of pgx shared by *pgxpool.Pool and pgx.Tx, letting
// projection.go's recomputeThreatTechniques run against either.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
