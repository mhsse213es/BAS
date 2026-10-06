package schemacheck_test

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/db/pgtest"
	"github.com/audspect/bas/internal/db/schemacheck"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Run(m)) }

func keys(f schemacheck.Fingerprint) []string {
	var k []string
	for x := range f {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func TestTake_OrderInsensitiveAndSchemaRelative(t *testing.T) {
	ctx := context.Background()
	c := pgtest.NewConn(t)
	pgtest.Exec(t, c, `CREATE SCHEMA a; CREATE SCHEMA b;
		CREATE TABLE a.t (id serial PRIMARY KEY, x text NOT NULL DEFAULT 'v', y int);
		CREATE INDEX t_x ON a.t (x);
		CREATE TABLE b.t (id serial PRIMARY KEY, y int, x text NOT NULL DEFAULT 'v');
		CREATE INDEX t_x ON b.t (x);`)
	fa, err := schemacheck.Take(ctx, c, "a")
	if err != nil {
		t.Fatal(err)
	}
	fb, err := schemacheck.Take(ctx, c, "b")
	if err != nil {
		t.Fatal(err)
	}
	if m, d, e := schemacheck.Diff(fa, fb); len(m)+len(d)+len(e) != 0 {
		t.Fatalf("missing %v different %v extra %v", m, d, e)
	}
}

func TestDiff_ReportsMissingDifferentExtra(t *testing.T) {
	ctx := context.Background()
	c := pgtest.NewConn(t)
	pgtest.Exec(t, c, `CREATE SCHEMA a; CREATE SCHEMA b;
		CREATE TABLE a.t (id int PRIMARY KEY, x text, z int);
		CREATE TABLE b.t (id int PRIMARY KEY, x varchar(5), w int);`)
	fa, err := schemacheck.Take(ctx, c, "a")
	if err != nil {
		t.Fatal(err)
	}
	fb, err := schemacheck.Take(ctx, c, "b")
	if err != nil {
		t.Fatal(err)
	}
	m, d, e := schemacheck.Diff(fa, fb)
	if len(m) != 1 || m[0].Name != "t.z" {
		t.Fatalf("missing = %v", m)
	}
	if len(d) != 1 || d[0].Name != "t.x" {
		t.Fatalf("different = %v", d)
	}
	if len(e) != 1 || e[0].Name != "t.w" {
		t.Fatalf("extra = %v", e)
	}
}

func TestTake_CoversEveryKind(t *testing.T) {
	ctx := context.Background()
	c := pgtest.NewConn(t)
	pgtest.Exec(t, c, `CREATE EXTENSION IF NOT EXISTS pgcrypto; CREATE SCHEMA a;
		CREATE SEQUENCE a.s;
		CREATE TABLE a.p (id int PRIMARY KEY);
		CREATE TABLE a.t (id int PRIMARY KEY, p int REFERENCES a.p(id), u text UNIQUE, g text DEFAULT gen_random_uuid()::text, CHECK (id > 0));
		CREATE INDEX i ON a.t (u);
		CREATE FUNCTION a.f() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$;
		CREATE TRIGGER tr BEFORE INSERT ON a.t FOR EACH ROW EXECUTE FUNCTION a.f();`)
	f, err := schemacheck.Take(ctx, c, "a")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"table/t", "column/t.p", "constraint/t.t_p_fkey", "index/i", "sequence/s", "function/f()", "trigger/t.tr", "extension/pgcrypto"} {
		if _, ok := f[k]; !ok {
			t.Errorf("missing %s in %v", k, keys(f))
		}
	}
	for _, k := range []string{"column/t.g", "constraint/t.t_p_fkey", "function/f()", "trigger/t.tr"} {
		if strings.Contains(f[k].Detail, "a.") {
			t.Errorf("schema qualifier leaked in %s: %q", k, f[k].Detail)
		}
	}
}

// The same object reached through a different schema name must compare equal
// even when Postgres qualifies references with the schema (FKs, triggers).
func TestTake_QualifiedReferencesCompareEqual(t *testing.T) {
	ctx := context.Background()
	c := pgtest.NewConn(t)
	for _, s := range []string{"a", "b"} {
		pgtest.Exec(t, c, `CREATE SCHEMA `+s+`;
			CREATE TABLE `+s+`.p (id int PRIMARY KEY);
			CREATE TABLE `+s+`.t (id int PRIMARY KEY, p int REFERENCES `+s+`.p(id));
			CREATE FUNCTION `+s+`.f() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$;
			CREATE TRIGGER tr BEFORE INSERT ON `+s+`.t FOR EACH ROW EXECUTE FUNCTION `+s+`.f();`)
	}
	fa, err := schemacheck.Take(ctx, c, "a")
	if err != nil {
		t.Fatal(err)
	}
	fb, err := schemacheck.Take(ctx, c, "b")
	if err != nil {
		t.Fatal(err)
	}
	if len(fa) < 6 {
		t.Fatalf("fingerprint too small to mean anything: %v", keys(fa))
	}
	if m, d, e := schemacheck.Diff(fa, fb); len(m)+len(d)+len(e) != 0 {
		t.Fatalf("missing %v different %v extra %v", m, d, e)
	}
}
