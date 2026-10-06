package seed_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db/legacy"
	"github.com/audspect/bas/internal/db/migrations"
	"github.com/audspect/bas/internal/db/pgtest"
	"github.com/audspect/bas/internal/db/seed"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Run(m)) }

// migratedPool applies every embedded migration by plain Exec (migrate itself
// arrives later in H1).
func migratedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := pgtest.NewPool(t)
	for _, f := range []string{"000001_baseline.up.sql", "000002_reference_data_version.up.sql"} {
		sql, err := migrations.FS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		pgtest.Exec(t, pool, string(sql))
	}
	return pool
}

func apply(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := seed.Apply(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, pool *pgxpool.Pool, sql string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func TestApply_IdempotentAndVersioned(t *testing.T) {
	ctx := context.Background()
	pool := migratedPool(t)
	if v, err := seed.Current(ctx, pool); err != nil || v != 0 {
		t.Fatalf("Current before = %d, %v", v, err)
	}
	apply(t, pool)
	families := count(t, pool, `SELECT count(*) FROM payload_families`)
	apply(t, pool)
	want, err := seed.Version()
	if err != nil || want < 1 {
		t.Fatalf("Version = %d, %v", want, err)
	}
	if got, err := seed.Current(ctx, pool); err != nil || got != want {
		t.Fatalf("Current = %d, %v; want %d", got, err, want)
	}
	if n := count(t, pool, `SELECT count(*) FROM tenants WHERE id = 'default'`); n != 1 {
		t.Fatalf("default tenant rows = %d", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM sla_policy`); n != 4 {
		t.Fatalf("sla_policy rows = %d", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM payload_families`); n != families || n == 0 {
		t.Fatalf("payload_families rows = %d after second apply, %d after first", n, families)
	}
}

// Operators may rename/suspend the default tenant, edit SLA durations and
// delete seeded payload families through the API; a later migrate up must
// never undo that (H1 spec 3, "never overwrite customer-controlled state").
func TestApply_NeverOverwritesOperatorState(t *testing.T) {
	pool := migratedPool(t)
	apply(t, pool)
	pgtest.Exec(t, pool, `UPDATE tenants SET name = 'Acme Bank', status = 'suspended' WHERE id = 'default';
		UPDATE sla_policy SET duration_hours = 12 WHERE severity = 'Critical';
		DELETE FROM payload_families WHERE technique_id = 'T1059.001' AND name = 'Recon - Identity';`)
	apply(t, pool)
	if n := count(t, pool, `SELECT count(*) FROM tenants WHERE id = 'default' AND name = 'Acme Bank' AND status = 'suspended'`); n != 1 {
		t.Fatal("tenant edit was overwritten")
	}
	if n := count(t, pool, `SELECT duration_hours FROM sla_policy WHERE severity = 'Critical'`); n != 12 {
		t.Fatalf("sla edit overwritten: %d", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM payload_families WHERE technique_id = 'T1059.001' AND name = 'Recon - Identity'`); n != 0 {
		t.Fatal("deleted payload family was resurrected")
	}
}

// Seed 0001 must produce exactly the rows the legacy boot chain wrote.
func TestApply_MatchesLegacySeedRows(t *testing.T) {
	ctx := context.Background()
	legacyPool := pgtest.NewPool(t)
	if err := legacy.EnsureAll(ctx, legacyPool); err != nil {
		t.Fatal(err)
	}
	seeded := migratedPool(t)
	apply(t, seeded)
	for table, cols := range map[string]string{
		"tenants":          "id, name, slug, status",
		"sla_policy":       "severity, duration_hours, updated_by",
		"payload_families": "technique_id, name, description, payload, purpose, risk_level, tactic",
	} {
		q := `SELECT coalesce(string_agg(r::text, E'\n' ORDER BY r::text), '') FROM (SELECT ` + cols + ` FROM ` + table + `) r`
		var a, b string
		if err := legacyPool.QueryRow(ctx, q).Scan(&a); err != nil {
			t.Fatal(err)
		}
		if err := seeded.QueryRow(ctx, q).Scan(&b); err != nil {
			t.Fatal(err)
		}
		if a == "" || a != b {
			t.Errorf("%s differs:\nlegacy:\n%s\nseed:\n%s", table, a, b)
		}
	}
}

// Only files newer than the recorded version run, in order.
func TestApplyFS_RunsOnlyPendingFiles(t *testing.T) {
	ctx := context.Background()
	pool := migratedPool(t)
	pgtest.Exec(t, pool, `CREATE TABLE h1_seed_t (v text)`)
	fsys := fstest.MapFS{
		"0001_a.sql": {Data: []byte(`INSERT INTO h1_seed_t VALUES ('a');`)},
		"0002_b.sql": {Data: []byte(`INSERT INTO h1_seed_t VALUES ('b');`)},
	}
	for i := 0; i < 2; i++ {
		tx, _ := pool.Begin(ctx)
		if err := seed.ApplyFS(ctx, tx, fsys); err != nil {
			t.Fatal(err)
		}
		tx.Commit(ctx)
	}
	fsys["0003_c.sql"] = &fstest.MapFile{Data: []byte(`INSERT INTO h1_seed_t VALUES ('c');`)}
	tx, _ := pool.Begin(ctx)
	if err := seed.ApplyFS(ctx, tx, fsys); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	var got string
	pool.QueryRow(ctx, `SELECT string_agg(v, '' ORDER BY v) FROM h1_seed_t`).Scan(&got)
	if got != "abc" {
		t.Fatalf("rows = %q, want each file applied exactly once", got)
	}
	if v, _ := seed.Current(ctx, pool); v != 3 {
		t.Fatalf("Current = %d", v)
	}
}

func TestApplyFS_RejectsBadNames(t *testing.T) {
	ctx := context.Background()
	pool := migratedPool(t)
	for _, name := range []string{"1_a.sql", "000a_x.sql", "0001.sql"} {
		tx, _ := pool.Begin(ctx)
		err := seed.ApplyFS(ctx, tx, fstest.MapFS{name: {Data: []byte(`SELECT 1;`)}})
		tx.Rollback(ctx)
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	tx, _ := pool.Begin(ctx)
	defer tx.Rollback(ctx)
	if err := seed.ApplyFS(ctx, tx, fstest.MapFS{"0001_a.sql": {Data: []byte(`SELECT 1;`)}, "0001_b.sql": {Data: []byte(`SELECT 1;`)}}); err == nil {
		t.Error("duplicate version accepted")
	}
}
