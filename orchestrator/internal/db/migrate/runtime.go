package migrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db/migrations"
	"github.com/audspect/bas/internal/db/seed"
)

var (
	ErrSchemaMissing = errors.New("database has no migration record")
	ErrSchemaDirty   = errors.New("database schema is dirty")
	ErrSchemaBehind  = errors.New("database schema is older than this release")
	ErrSchemaAhead   = errors.New("database schema is newer than this release")
	ErrSeedBehind    = errors.New("reference data is older than this release")
)

// CheckRuntime is the server's startup check (H1 spec 4.4). It issues only
// SELECTs and is safe as bas_app; any mismatch is fatal for the caller.
func CheckRuntime(ctx context.Context, q seed.Querier) error {
	latest, err := migrations.Latest()
	if err != nil {
		return err
	}
	wantSeed, err := seed.Version()
	if err != nil {
		return err
	}
	var has bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&has); err != nil {
		return fmt.Errorf("schema check: %w", err)
	}
	if !has {
		return fmt.Errorf("%w (fresh or pre-H1 database) -- run: install.sh --upgrade", ErrSchemaMissing)
	}
	var version int64
	var dirty bool
	err = q.QueryRow(ctx, `SELECT version, dirty FROM public.schema_migrations LIMIT 1`).Scan(&version, &dirty)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w -- run: install.sh --upgrade", ErrSchemaMissing)
	}
	if err != nil {
		return fmt.Errorf("schema check: %w", err)
	}
	switch {
	case dirty:
		return fmt.Errorf("%w at version %d -- run: install.sh --rollback", ErrSchemaDirty, version)
	case uint(version) < latest:
		return fmt.Errorf("%w (database %d, release %d) -- run: install.sh --upgrade", ErrSchemaBehind, version, latest)
	case uint(version) > latest:
		return fmt.Errorf("%w (database %d, release %d) -- run the matching release or: install.sh --rollback", ErrSchemaAhead, version, latest)
	}
	cur, err := seed.Current(ctx, q)
	if err != nil {
		return fmt.Errorf("reference data check: %w", err)
	}
	if cur < wantSeed {
		return fmt.Errorf("%w (database %d, release %d) -- run: install.sh --upgrade", ErrSeedBehind, cur, wantSeed)
	}
	return nil
}
