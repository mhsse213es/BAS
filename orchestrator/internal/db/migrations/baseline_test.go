package migrations_test

import (
	"context"
	"os"
	"testing"

	"github.com/audspect/bas/internal/db/legacy"
	"github.com/audspect/bas/internal/db/migrations"
	"github.com/audspect/bas/internal/db/pgtest"
	"github.com/audspect/bas/internal/db/schemacheck"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Run(m)) }

// fingerprint(empty + 000001) must equal fingerprint(empty + legacy chain);
// runs in CI until internal/db/legacy is deleted (H1 spec 4.5).
func TestBaselineEqualsLegacyChain(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewPool(t)
	if err := legacy.EnsureAll(ctx, pool); err != nil {
		t.Fatal(err)
	}
	up, err := migrations.FS.ReadFile("000001_baseline.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	pgtest.Exec(t, pool, `CREATE SCHEMA h1_fp`)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL search_path TO h1_fp, public`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(up)); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	want, err := schemacheck.Take(ctx, tx, "public")
	if err != nil {
		t.Fatal(err)
	}
	got, err := schemacheck.Take(ctx, tx, "h1_fp")
	if err != nil {
		t.Fatal(err)
	}
	if len(want) < 300 {
		t.Fatalf("legacy fingerprint suspiciously small: %d objects", len(want))
	}
	if m, d, e := schemacheck.Diff(want, got); len(m)+len(d)+len(e) > 0 {
		t.Fatalf("baseline differs from legacy chain:\nmissing %v\ndifferent %v\nextra %v", m, d, e)
	}
}

func TestBaselineDownThenUp(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewPool(t)
	up, err := migrations.FS.ReadFile("000001_baseline.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := migrations.FS.ReadFile("000001_baseline.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i, sql := range []string{string(up), string(down), string(up)} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE schemaname = 'public'`).Scan(&n); err != nil || n < 60 {
		t.Fatalf("tables after up/down/up = %d, %v", n, err)
	}
}

func TestLatest(t *testing.T) {
	if v, err := migrations.Latest(); err != nil || v < 1 {
		t.Fatalf("Latest = %d, %v", v, err)
	}
}
