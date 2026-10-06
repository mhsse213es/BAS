package migrate_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db/legacy"
	"github.com/audspect/bas/internal/db/migrate"
	"github.com/audspect/bas/internal/db/pgtest"
)

// legacyInstall is a pre-H1 database: the frozen boot chain run on an empty DB.
func legacyInstall(t *testing.T) (string, *pgxpool.Pool) {
	t.Helper()
	dsn := pgtest.NewDatabase(t)
	pool := pgtest.PoolFor(t, dsn)
	if err := legacy.EnsureAll(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	return dsn, pool
}

// operatorRows writes customer data plus the operator edits that adoption and
// the seed step must never undo.
func operatorRows(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	pgtest.Exec(t, pool, `
		INSERT INTO tenants (id, name, slug) VALUES ('t-acme', 'Acme', 'acme');
		INSERT INTO users (username, password_hash) VALUES ('alice', 'x');
		INSERT INTO agents (agent_id, hostname) VALUES ('a-1', 'host-1');
		INSERT INTO payload_families (technique_id, name, description, payload, purpose, risk_level, tactic)
			VALUES ('T9999', 'Operator family', 'd', 'p', 'recon', 'SAFE', 'execution');
		UPDATE tenants SET name = 'Acme Bank' WHERE id = 'default';
		UPDATE sla_policy SET duration_hours = 12 WHERE severity = 'Critical';`)
}

// tableChecksums is md5 over every row of every public table, keyed by table.
func tableChecksums(t *testing.T, pool *pgxpool.Pool) map[string]string {
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
	out := map[string]string{}
	for _, tb := range tables {
		var sum string
		q := `SELECT coalesce(md5(string_agg(r::text, E'\n' ORDER BY r::text)), '') FROM "` + tb + `" r`
		if err := pool.QueryRow(ctx, q).Scan(&sum); err != nil {
			t.Fatalf("%s: %v", tb, err)
		}
		out[tb] = sum
	}
	return out
}

func TestAdopt_PreservesDataAndMarksBaseline(t *testing.T) { // H1-T3
	ctx := context.Background()
	dsn, pool := legacyInstall(t)
	operatorRows(t, pool)
	before := tableChecksums(t, pool)
	r, err := migrate.Up(ctx, dsn, noRole)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Adopted || r.FromVersion != 0 || len(r.Extra) != 0 {
		t.Fatalf("result %+v", r)
	}
	after := tableChecksums(t, pool)
	for tb, sum := range before {
		if after[tb] != sum {
			t.Errorf("table %s changed during adoption", tb)
		}
	}
	st, err := migrate.GetStatus(ctx, dsn)
	if err != nil || st.Pending || st.Dirty {
		t.Fatalf("status %+v %v", st, err)
	}
	// Before H1 every boot re-inserted seeded payload families, so deleting one
	// was never durable; adoption re-runs that chain once. From here on a
	// deletion survives upgrades, and a second run is a plain managed no-op.
	pgtest.Exec(t, pool, `DELETE FROM payload_families WHERE technique_id = 'T1059.001' AND name = 'Recon - Identity'`)
	if r2 := up(t, dsn, noRole); r2.Adopted || r2.FromVersion != r2.ToVersion || r2.FromSeed != r2.ToSeed {
		t.Fatalf("second run %+v", r2)
	}
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM payload_families WHERE technique_id = 'T1059.001' AND name = 'Recon - Identity'`).Scan(&n)
	if n != 0 {
		t.Fatal("seeded family deleted after adoption was resurrected")
	}
}

func TestAdopt_OlderReleaseSchema(t *testing.T) { // H1-T3 variant
	dsn, pool := legacyInstall(t)
	// What an older release lacked: the chain is additive, so these were
	// created by later releases (agents.transport is the newest agents column).
	pgtest.Exec(t, pool, `
		DROP TABLE legacy_transport_log, legacy_transport_unattributed, agent_certificates;
		ALTER TABLE agents DROP COLUMN transport CASCADE;`)
	r := up(t, dsn, noRole)
	if !r.Adopted || len(r.Extra) != 0 {
		t.Fatalf("result %+v", r)
	}
	var ok bool
	pool.QueryRow(context.Background(), `SELECT to_regclass('agent_certificates') IS NOT NULL
		AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'agents' AND column_name = 'transport')`).Scan(&ok)
	if !ok {
		t.Fatal("older-release objects were not restored")
	}
}

func TestAdopt_ExtraObjectsReportedNotBlocking(t *testing.T) { // H1-T3 variant
	ctx := context.Background()
	dsn, pool := legacyInstall(t)
	pgtest.Exec(t, pool, `CREATE TABLE old_leftover (id int); ALTER TABLE agents ADD COLUMN old_col text;`)
	r := up(t, dsn, noRole)
	got := map[string]bool{}
	for _, o := range r.Extra {
		got[o.Kind+"/"+o.Name] = true
	}
	if !r.Adopted || !got["table/old_leftover"] || !got["column/agents.old_col"] {
		t.Fatalf("extra = %+v", r.Extra)
	}
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM h1_adoption_report
		WHERE (kind, object) IN (('table', 'old_leftover'), ('column', 'agents.old_col'))`).Scan(&n)
	if n != 2 {
		t.Fatalf("h1_adoption_report rows = %d", n)
	}
}

func TestAdopt_MissingObjectFailsClosed(t *testing.T) { // H1-T3b
	ctx := context.Background()
	dsn, pool := legacyInstall(t)
	// The additive chain never changes an existing column back.
	pgtest.Exec(t, pool, `ALTER TABLE agents ALTER COLUMN hostname TYPE varchar(3) USING left(hostname, 3)`)
	_, err := migrate.Up(ctx, dsn, noRole)
	if !errors.Is(err, migrate.ErrAdoptionMismatch) || !strings.Contains(err.Error(), "column/agents.hostname") {
		t.Fatalf("err = %v", err)
	}
	var exists bool
	pool.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists)
	if exists {
		t.Fatal("schema_migrations written despite mismatch")
	}
}
