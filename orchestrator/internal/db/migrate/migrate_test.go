package migrate_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db/migrate"
	"github.com/audspect/bas/internal/db/migrations"
	"github.com/audspect/bas/internal/db/pgtest"
	"github.com/audspect/bas/internal/db/schemacheck"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Run(m)) }

var noRole = migrate.Options{SkipRole: true}

func up(t *testing.T, dsn string, opt migrate.Options) migrate.Result {
	t.Helper()
	r, err := migrate.Up(context.Background(), dsn, opt)
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	return r
}

func fingerprint(t *testing.T, pool *pgxpool.Pool) schemacheck.Fingerprint {
	t.Helper()
	f, err := schemacheck.Take(context.Background(), pool, "public")
	if err != nil {
		t.Fatal(err)
	}
	for k := range f {
		if regexp.MustCompile(`^(table|column|constraint)/schema_migrations\b`).MatchString(k) {
			delete(f, k)
		}
	}
	return f
}

// The schema Up builds must equal every embedded up file executed in order.
func assertSchemaEqualsRawMigrations(t *testing.T, dsn string) {
	t.Helper()
	raw := pgtest.NewPool(t)
	entries, _ := fs.Glob(migrations.FS, "*.up.sql")
	sort.Strings(entries)
	for _, e := range entries {
		sql, _ := migrations.FS.ReadFile(e)
		pgtest.Exec(t, raw, string(sql))
	}
	want, got := fingerprint(t, raw), fingerprint(t, pgtest.PoolFor(t, dsn))
	if m, d, e := schemacheck.Diff(want, got); len(m)+len(d)+len(e) > 0 {
		t.Fatalf("missing %v\ndifferent %v\nextra %v", m, d, e)
	}
}

func rowCounts(t *testing.T, pool *pgxpool.Pool) map[string]int {
	t.Helper()
	ctx := context.Background()
	rows, err := pool.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	out := map[string]int{}
	for _, tb := range tables {
		var n int
		pool.QueryRow(ctx, `SELECT count(*) FROM "`+tb+`"`).Scan(&n)
		out[tb] = n
	}
	return out
}

func TestUp_FreshDatabase(t *testing.T) { // H1-T1 (schema + seed)
	dsn := pgtest.NewDatabase(t)
	r := up(t, dsn, noRole)
	latest, _ := migrations.Latest()
	if r.FromVersion != 0 || r.ToVersion != latest || r.Adopted || r.ToSeed < 1 {
		t.Fatalf("result %+v", r)
	}
	assertSchemaEqualsRawMigrations(t, dsn)
	st, err := migrate.GetStatus(context.Background(), dsn)
	if err != nil || st.Pending || st.Dirty || st.Version != latest {
		t.Fatalf("status %+v %v", st, err)
	}
}

func TestUp_Idempotent(t *testing.T) { // H1-T2
	dsn := pgtest.NewDatabase(t)
	pool := pgtest.PoolFor(t, dsn)
	up(t, dsn, noRole)
	f0, c0 := fingerprint(t, pool), rowCounts(t, pool)
	for i := 0; i < 2; i++ {
		r := up(t, dsn, noRole)
		if r.FromVersion != r.ToVersion || r.FromSeed != r.ToSeed {
			t.Fatalf("run %d did work: %+v", i, r)
		}
	}
	if m, d, e := schemacheck.Diff(f0, fingerprint(t, pool)); len(m)+len(d)+len(e) > 0 || !reflect.DeepEqual(c0, rowCounts(t, pool)) {
		t.Fatal("schema or row counts changed on a no-op run")
	}
}

// concurrentUp starts three Up runs at once and requires that exactly one did
// any work: the others must wait on the lock and then find nothing pending.
func concurrentUp(t *testing.T, dsn string) {
	t.Helper()
	var wg sync.WaitGroup
	res := make([]migrate.Result, 3)
	errs := make([]error, 3)
	for i := range errs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); res[i], errs[i] = migrate.Up(context.Background(), dsn, noRole) }(i)
	}
	wg.Wait()
	worked := 0
	for i, err := range errs {
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		r := res[i]
		if r.Adopted || r.FromVersion != r.ToVersion || r.FromSeed != r.ToSeed {
			worked++
		}
	}
	if worked != 1 {
		t.Fatalf("%d runs did work, want exactly 1: %+v", worked, res)
	}
	st, _ := migrate.GetStatus(context.Background(), dsn)
	if st.Dirty || st.Pending {
		t.Fatalf("status %+v", st)
	}
}

func TestUp_ConcurrentRunsSerialize(t *testing.T) { // Review Focus: double-run
	concurrentUp(t, pgtest.NewDatabase(t))
}

func TestUp_ConcurrentAdoptionSerializes(t *testing.T) { // Review Focus: double-run on a pre-H1 install
	dsn, _ := legacyInstall(t)
	concurrentUp(t, dsn)
}

func TestMigrationSet_OrderedNoGapsNoDuplicates(t *testing.T) { // H1-T4
	if err := migrate.CheckSet(migrations.FS); err != nil {
		t.Fatal(err)
	}
	bad := map[string]fstest.MapFS{
		"gap":       {"000001_a.up.sql": {}, "000001_a.down.sql": {}, "000003_c.up.sql": {}, "000003_c.down.sql": {}},
		"duplicate": {"000001_a.up.sql": {}, "000001_a.down.sql": {}, "000001_b.up.sql": {}, "000001_b.down.sql": {}},
		"no down":   {"000001_a.up.sql": {}},
		"bad name":  {"1_a.up.sql": {}, "1_a.down.sql": {}},
	}
	for name, fsys := range bad {
		if err := migrate.CheckSet(fsys); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// withExtra returns the embedded set plus one extra migration (version latest+1).
func withExtra(t *testing.T, name, upSQL, downSQL string) (fstest.MapFS, uint) {
	t.Helper()
	fsys := fstest.MapFS{}
	entries, _ := fs.ReadDir(migrations.FS, ".")
	for _, e := range entries {
		b, _ := migrations.FS.ReadFile(e.Name())
		fsys[e.Name()] = &fstest.MapFile{Data: b}
	}
	latest, _ := migrations.Latest()
	v := latest + 1
	fsys[fmt.Sprintf("%06d_%s.up.sql", v, name)] = &fstest.MapFile{Data: []byte(upSQL)}
	fsys[fmt.Sprintf("%06d_%s.down.sql", v, name)] = &fstest.MapFile{Data: []byte(downSQL)}
	return fsys, v
}

func TestUp_FailingMigrationLeavesDirtyAndRefuses(t *testing.T) { // H1-T5
	ctx := context.Background()
	dsn := pgtest.NewDatabase(t)
	bad, v := withExtra(t, "fail", "CREATE TABLE h1_t5 (id int); SELECT 1/0;", "DROP TABLE IF EXISTS h1_t5;")
	if _, err := migrate.Up(ctx, dsn, migrate.Options{SkipRole: true, Source: bad}); err == nil {
		t.Fatal("want failure")
	}
	st, err := migrate.GetStatus(ctx, dsn)
	if err != nil || !st.Dirty || st.Version != v {
		t.Fatalf("status %+v %v", st, err)
	}
	if _, err := migrate.Up(ctx, dsn, migrate.Options{SkipRole: true, Source: bad}); !errors.Is(err, migrate.ErrDirty) {
		t.Fatalf("second Up err = %v", err)
	}
}

func TestUpDownUp_TestMigration(t *testing.T) { // H1-T6
	ctx := context.Background()
	dsn := pgtest.NewDatabase(t)
	src, v := withExtra(t, "t6", "CREATE TABLE h1_t6 (id int);", "DROP TABLE h1_t6;")
	pool := pgtest.PoolFor(t, dsn)
	exists := func() bool {
		var ok bool
		pool.QueryRow(ctx, `SELECT to_regclass('h1_t6') IS NOT NULL`).Scan(&ok)
		return ok
	}
	if r := up(t, dsn, migrate.Options{SkipRole: true, Source: src}); r.ToVersion != v || !exists() {
		t.Fatalf("up: %+v exists=%v", r, exists())
	}
	if err := migrate.DownOne(ctx, dsn, src); err != nil || exists() {
		t.Fatalf("down: %v exists=%v", err, exists())
	}
	if r := up(t, dsn, migrate.Options{SkipRole: true, Source: src}); r.ToVersion != v || !exists() {
		t.Fatalf("up again: %+v exists=%v", r, exists())
	}
}

func TestClassify_NewerAndUnrecognised(t *testing.T) {
	ctx := context.Background()
	dsn := pgtest.NewDatabase(t)
	up(t, dsn, noRole)
	pgtest.Exec(t, pgtest.PoolFor(t, dsn), `UPDATE schema_migrations SET version = 999`)
	if _, err := migrate.Up(ctx, dsn, noRole); !errors.Is(err, migrate.ErrNewer) {
		t.Fatalf("newer: err = %v", err)
	}
	dsn2 := pgtest.NewDatabase(t)
	pgtest.Exec(t, pgtest.PoolFor(t, dsn2), `CREATE TABLE someone_elses (id int)`)
	if _, err := migrate.Up(ctx, dsn2, noRole); !errors.Is(err, migrate.ErrUnrecognised) {
		t.Fatalf("unrecognised: err = %v", err)
	}
	var n int
	pgtest.PoolFor(t, dsn2).QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE schemaname = 'public'`).Scan(&n)
	if n != 1 {
		t.Fatalf("refused Up still changed the database: %d tables", n)
	}
}
