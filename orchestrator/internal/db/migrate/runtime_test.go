package migrate_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db/migrate"
	"github.com/audspect/bas/internal/db/pgtest"
)

func TestCheckRuntime(t *testing.T) { // H1-T7, Review Focus 5
	ctx := context.Background()
	dsn := pgtest.NewDatabase(t)
	pool := pgtest.PoolFor(t, dsn)
	if err := migrate.CheckRuntime(ctx, pool); !errors.Is(err, migrate.ErrSchemaMissing) {
		t.Fatalf("empty: %v", err)
	}
	up(t, dsn, noRole)
	if err := migrate.CheckRuntime(ctx, pool); err != nil {
		t.Fatalf("current: %v", err)
	}
	pgtest.Exec(t, pool, `UPDATE reference_data_version SET version = 0`)
	if err := migrate.CheckRuntime(ctx, pool); !errors.Is(err, migrate.ErrSeedBehind) || !strings.Contains(err.Error(), "install.sh --upgrade") {
		t.Fatalf("seed behind: %v", err)
	}
	pgtest.Exec(t, pool, `UPDATE reference_data_version SET version = 1`)
	pgtest.Exec(t, pool, `UPDATE schema_migrations SET version = version - 1`)
	if err := migrate.CheckRuntime(ctx, pool); !errors.Is(err, migrate.ErrSchemaBehind) || !strings.Contains(err.Error(), "install.sh --upgrade") {
		t.Fatalf("behind: %v", err)
	}
	pgtest.Exec(t, pool, `UPDATE schema_migrations SET version = 999`)
	if err := migrate.CheckRuntime(ctx, pool); !errors.Is(err, migrate.ErrSchemaAhead) || !strings.Contains(err.Error(), "install.sh --rollback") {
		t.Fatalf("ahead: %v", err)
	}
	pgtest.Exec(t, pool, `UPDATE schema_migrations SET version = 3, dirty = true`)
	if err := migrate.CheckRuntime(ctx, pool); !errors.Is(err, migrate.ErrSchemaDirty) {
		t.Fatalf("dirty: %v", err)
	}
	// A pre-H1 install (tables, no schema_migrations) is "missing" too.
	dsn2 := pgtest.NewDatabase(t)
	pool2 := pgtest.PoolFor(t, dsn2)
	pgtest.Exec(t, pool2, `CREATE TABLE tenants (id text)`)
	if err := migrate.CheckRuntime(ctx, pool2); !errors.Is(err, migrate.ErrSchemaMissing) || !strings.Contains(err.Error(), "install.sh --upgrade") {
		t.Fatalf("pre-H1: %v", err)
	}
}

type recorder struct {
	mu  sync.Mutex
	sql []string
}

func (r *recorder) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	r.mu.Lock()
	r.sql = append(r.sql, d.SQL)
	r.mu.Unlock()
	return ctx
}

func (r *recorder) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestCheckRuntime_IssuesOnlySelects(t *testing.T) { // H1-T7
	ctx := context.Background()
	dsn := pgtest.NewDatabase(t)
	up(t, dsn, noRole)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	cfg.ConnConfig.Tracer = rec
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := migrate.CheckRuntime(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if len(rec.sql) == 0 {
		t.Fatal("no statements recorded")
	}
	for _, s := range rec.sql {
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(s)), "SELECT") {
			t.Errorf("non-SELECT at startup: %q", s)
		}
	}
}
