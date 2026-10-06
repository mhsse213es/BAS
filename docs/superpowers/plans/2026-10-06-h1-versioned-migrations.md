# H1 — Versioned Migrations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace boot-time idempotent DDL with embedded, versioned golang-migrate migrations run by an explicit `orchestrator migrate` command from `install.sh`, with snapshot-based rollback and a runtime that only holds `bas_app` and refuses to start on a schema mismatch.

**Architecture:** Today's seven `Ensure*Schema` functions are frozen in `internal/db/legacy` and used only to bring pre-H1 installs to a baseline captured mechanically from them (`000001_baseline.up.sql`). `internal/db/migrate` classifies the database (fresh / pre-H1 / managed / dirty / newer / unrecognised), adopts or migrates under an advisory lock, applies an idempotent versioned seed, provisions `bas_app` without silently changing its password, and offers `CheckRuntime` for startup. `install.sh` wraps upgrades in a recorded, encrypted DB snapshot and restores exactly that snapshot on rollback.

**Tech Stack:** Go 1.26.6, pgx/v5 v5.9.2, golang-migrate v4 (`database/pgx/v5`, `source/iofs`), `embed.FS`, testcontainers-go v0.43.0 (`postgres:16-alpine`), Bash (`install.sh`), Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-06-h1-versioned-migrations-design.md` (approved 2026-10-06).

## Global Constraints

- Contract: the baseline reproduces today's schema exactly; no schema clean-up, renames or drops in H1.
- The running orchestrator issues no DDL, no DML and no role statements at startup and connects only with `DATABASE_URL` (bas_app).
- `migrate up` never changes the password of an existing `bas_app`; password is set only on creation or by `migrate rotate-app-password`.
- Shipped migration and seed files are immutable; `internal/db/legacy` is frozen once Task 2 lands.
- Rollback = restore of the encrypted pre-upgrade snapshot recorded for that upgrade; never a scheduled backup.
- Postgres `postgres:16-alpine` (compose and testcontainers).
- Work on `main`; commit and push after every commit; stage files by name; never stage `.claude/settings.local.json`, `go.work.sum`, `Assessment/COMPETITIVE_ANALYSIS.html`, `orchestrator/staging-loadtest-linux`, `docs/superpowers/plans/2026-10-04-g1b-xss-ci-regression-guard.md`, `orchestrator/web/eslint-browser-globals.json`; no directory-level `git checkout --`, `git clean`, `git stash`, resets.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Go tests from `orchestrator/` (Docker Desktop must be running for testcontainers): `go test ./internal/db/... -count=1`; full suite `go test ./... -p 2` (`-p 1` if memory-starved); race runs via the Docker recipe: `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/src" -v gomodcache:/go/pkg/mod -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal -w /src/orchestrator golang:1.26.6 go test -race <pkgs>` (full package set needs `-timeout 45m`).
- Bash heredocs on the Windows host mangle backslashes: create/edit files with Write/Edit.
- Client production changes only through `install.sh`/`uninstall.sh`.

## Plan corrections to the spec (confirm at plan review)

- **P1 — dependency pinning.** The spec says "vendored"; the repository does not vendor any module (no `vendor/`, builds use the module cache). Introducing vendoring for one module would change every build. Plan: pin golang-migrate exactly in `go.mod`/`go.sum` (sum-verified, like every other dependency) and gate it with the existing govulncheck/gosec CI; record the version in the Task 1 report.
- **P2 — legacy signature.** The frozen `Ensure*` functions take `*pgxpool.Pool`; adoption runs them inside one transaction. The freeze changes only their parameter type to a small interface (`legacy.DB`: `Exec`, `Query`, `QueryRow`, `Begin`) satisfied by both `*pgxpool.Pool` and `pgx.Tx` (`Begin` on a `pgx.Tx` opens a savepoint). Statement text is untouched.

## Review Focus

- A pre-H1 install whose schema differs only in column order or in `public.`-qualified defaults — must adopt (fingerprint is order- and qualifier-insensitive). Pinned in Task 3's tests.
- Two `migrate up` runs started at once (operator double-runs install.sh) — the second must wait and then find nothing pending, never interleave. Pinned in Task 5's tests.
- `BAS_APP_DB_PASSWORD` changed in `.env` by hand without rotation — `migrate up` must stop with the rotation message and leave the database password unchanged. Pinned in Task 7's tests.
- A rollback started when the latest backup directory is a scheduled backup newer than the upgrade record — must use the upgrade record, never the scheduled backup. Pinned in Task 9's tests.
- The orchestrator started (e.g. by systemd after a host reboot) between a failed `migrate up` and the operator's rollback — must refuse to start against the dirty or older schema. Pinned in Task 8's tests.

---

## File structure

| File | Responsibility | Task |
|---|---|---|
| `orchestrator/internal/db/schemacheck/{fingerprint.go,fingerprint_test.go}` | Order/qualifier-insensitive catalog fingerprint and diff | 1 |
| `orchestrator/internal/db/legacy/*.go` (+ `freeze_test.go`, `FROZEN.sha256`) | Frozen pre-H1 chain; adoption only | 2 |
| `orchestrator/internal/db/{postgres.go,content_schema.go,ioc.go,ioc_enrichment.go,agent_groups_schema.go,agent_uninstall_schema.go,exercise_schema.go}` | `Ensure*` become delegates (Task 2), deleted (Task 8) | 2, 8 |
| `orchestrator/tools/h1-capture-baseline/main.go` | One-time baseline capture | 3 |
| `orchestrator/internal/db/migrations/{embed.go,000001_baseline.up.sql,000001_baseline.down.sql,README.md,MANIFEST.sha256}` | Embedded migration set + rules | 3, 10 |
| `orchestrator/internal/db/seed/{embed.go,seed.go,SEED_VERSION,*.sql,seed_test.go}` | Reference-data seed | 4 |
| `orchestrator/internal/db/migrate/{migrate.go,classify.go,adopt.go,role.go,runtime.go,*_test.go}` | Orchestration | 5–8 |
| `orchestrator/cmd/server/main.go` | `migrate` subcommands; startup uses `CheckRuntime` only | 8 |
| `orchestrator/internal/testutil/testdb.go` | Test DB via the real `migrate.Up` | 8 |
| `packaging/compose/{docker-compose.yml,docker-compose.prod.yml,install.sh}`, `packaging/compose/lib/upgrade-db.sh`, `packaging/compose/tests/upgrade_db_test.sh` | Upgrade record, snapshot, migrate step, rollback, rotation | 9 |
| `scripts/h1-check-no-runtime-ddl.py` (+ test), `.github/workflows/test.yml`, `docs/release-notes/h1-versioned-migrations.md` | Guardrails, release notes | 10 |

---

### Task 1: golang-migrate dependency and `schemacheck`

**Files:** Create `orchestrator/internal/db/schemacheck/fingerprint.go`, `fingerprint_test.go`; modify `orchestrator/go.mod`, `go.sum`.

**Interfaces:**
- Produces: `type Object struct{ Kind, Name, Detail string }`; `type Fingerprint map[string]Object` keyed `Kind + "/" + Name`; `func Take(ctx context.Context, q Querier, schema string) (Fingerprint, error)`; `func Diff(want, got Fingerprint) (missing, different, extra []Object)` (each sorted by key); `type Querier interface { Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) }` (satisfied by `*pgxpool.Pool`, `*pgx.Conn`, `pgx.Tx`). Kinds: `table`, `column`, `constraint`, `index`, `sequence`, `function`, `trigger`, `extension`. Names are schema-relative (`table/agents`, `column/agents.hostname`, `constraint/agents.agents_pkey`, `index/idx_x`, …). `Detail` holds the normalized definition; every occurrence of `"<schema>".`, `<schema>.` and `public.` is removed so the same object in `public` and in a temporary schema compares equal; column order is never part of the fingerprint.

- [ ] **Step 1: Add the dependency.** From `orchestrator/`: `go get github.com/golang-migrate/migrate/v4@latest` then `go mod tidy`. Record the resolved version in the report. Confirm it provides `github.com/golang-migrate/migrate/v4/database/pgx/v5` and `.../source/iofs` (`go doc github.com/golang-migrate/migrate/v4/database/pgx/v5 WithInstance`). Run `govulncheck ./...` if installed (or rely on CI) and note the result.

- [ ] **Step 2: Failing tests** — `orchestrator/internal/db/schemacheck/fingerprint_test.go` (package `schemacheck_test`, uses `testutil.NewTestDB`-style container via `tcpostgres.Run(ctx, "postgres:16-alpine", …)` — copy the container setup from `internal/testutil/testdb.go:41-75` into a local `newConn(t)` helper that returns a `*pgx.Conn` to an empty database, because testutil will import `migrate` later and must not be imported here):

```go
func TestTake_OrderInsensitiveAndSchemaRelative(t *testing.T) {
	ctx := context.Background()
	c := newConn(t)
	mustExec(t, c, `CREATE SCHEMA a; CREATE SCHEMA b;
		CREATE TABLE a.t (id serial PRIMARY KEY, x text NOT NULL DEFAULT 'v', y int);
		CREATE INDEX t_x ON a.t (x);
		CREATE TABLE b.t (id serial PRIMARY KEY, y int, x text NOT NULL DEFAULT 'v');
		CREATE INDEX t_x ON b.t (x);`)
	fa, err := schemacheck.Take(ctx, c, "a")
	if err != nil { t.Fatal(err) }
	fb, err := schemacheck.Take(ctx, c, "b")
	if err != nil { t.Fatal(err) }
	m, d, e := schemacheck.Diff(fa, fb)
	if len(m)+len(d)+len(e) != 0 { t.Fatalf("missing %v different %v extra %v", m, d, e) }
}

func TestDiff_ReportsMissingDifferentExtra(t *testing.T) {
	ctx := context.Background()
	c := newConn(t)
	mustExec(t, c, `CREATE SCHEMA a; CREATE SCHEMA b;
		CREATE TABLE a.t (id int PRIMARY KEY, x text, z int);
		CREATE TABLE b.t (id int PRIMARY KEY, x varchar(5), w int);`)
	fa, _ := schemacheck.Take(ctx, c, "a")
	fb, _ := schemacheck.Take(ctx, c, "b")
	m, d, e := schemacheck.Diff(fa, fb)
	if len(m) != 1 || m[0].Name != "t.z" { t.Fatalf("missing = %v", m) }
	if len(d) != 1 || d[0].Name != "t.x" { t.Fatalf("different = %v", d) }
	if len(e) != 1 || e[0].Name != "t.w" { t.Fatalf("extra = %v", e) }
}

func TestTake_CoversEveryKind(t *testing.T) {
	ctx := context.Background()
	c := newConn(t)
	mustExec(t, c, `CREATE EXTENSION IF NOT EXISTS pgcrypto; CREATE SCHEMA a;
		CREATE SEQUENCE a.s;
		CREATE TABLE a.p (id int PRIMARY KEY);
		CREATE TABLE a.t (id int PRIMARY KEY, p int REFERENCES a.p(id), u text UNIQUE, g text DEFAULT gen_random_uuid()::text, CHECK (id > 0));
		CREATE INDEX i ON a.t (u);
		CREATE FUNCTION a.f() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$;
		CREATE TRIGGER tr BEFORE INSERT ON a.t FOR EACH ROW EXECUTE FUNCTION a.f();`)
	f, err := schemacheck.Take(ctx, c, "a")
	if err != nil { t.Fatal(err) }
	for _, k := range []string{"table/t", "column/t.p", "constraint/t.t_p_fkey", "index/i", "sequence/s", "function/f()", "trigger/t.tr", "extension/pgcrypto"} {
		if _, ok := f[k]; !ok { t.Errorf("missing %s in %v", k, keys(f)) }
	}
	if strings.Contains(f["column/t.g"].Detail, "a.") || strings.Contains(f["constraint/t.t_p_fkey"].Detail, "a.") {
		t.Errorf("schema qualifier leaked: %q / %q", f["column/t.g"].Detail, f["constraint/t.t_p_fkey"].Detail)
	}
}
```
(`mustExec`, `keys` are small local helpers.) Run `go test ./internal/db/schemacheck/ -count=1` → FAIL: package does not exist.

- [ ] **Step 3: Implement** `orchestrator/internal/db/schemacheck/fingerprint.go`:

```go
// Package schemacheck fingerprints a PostgreSQL schema from the catalog so two
// schemas can be compared regardless of column order or schema qualifiers
// (H1 spec 4.2). Used by migrate adoption and the baseline equivalence test.
package schemacheck

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

type Object struct{ Kind, Name, Detail string }
type Fingerprint map[string]Object
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

var queries = []struct{ kind, sql string }{
	{"table", `SELECT c.relname, c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind IN ('r','p')`},
	{"column", `SELECT c.relname || '.' || a.attname,
		format_type(a.atttypid, a.atttypmod) || ' notnull=' || a.attnotnull || ' default=' || coalesce(pg_get_expr(d.adbin, d.adrelid), '') ||
		' identity=' || a.attidentity || ' generated=' || a.attgenerated
		FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE n.nspname = $1 AND c.relkind IN ('r','p') AND a.attnum > 0 AND NOT a.attisdropped`},
	{"constraint", `SELECT c.relname || '.' || con.conname, con.contype::text || ' ' || pg_get_constraintdef(con.oid)
		FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1`},
	{"index", `SELECT i.relname, pg_get_indexdef(i.oid)
		FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_namespace n ON n.oid = i.relnamespace
		WHERE n.nspname = $1 AND NOT EXISTS (SELECT 1 FROM pg_constraint con WHERE con.conindid = i.oid)`},
	{"sequence", `SELECT c.relname, format_type(s.seqtypid, NULL) || ' ' || s.seqstart || ' ' || s.seqincrement || ' ' || s.seqmin || ' ' || s.seqmax || ' ' || s.seqcache || ' ' || s.seqcycle
		FROM pg_sequence s JOIN pg_class c ON c.oid = s.seqrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1`},
	{"function", `SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', pg_get_functiondef(p.oid)
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = $1 AND p.prokind IN ('f','p')
		AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')`},
	{"trigger", `SELECT c.relname || '.' || t.tgname, pg_get_triggerdef(t.oid)
		FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND NOT t.tgisinternal`},
	{"extension", `SELECT extname, extversion FROM pg_extension WHERE $1 <> ''`},
}

func Take(ctx context.Context, q Querier, schema string) (Fingerprint, error) {
	strip := regexp.MustCompile(`"?(?:` + regexp.QuoteMeta(schema) + `|public)"?\.`)
	fp := Fingerprint{}
	for _, qq := range queries {
		rows, err := q.Query(ctx, qq.sql, schema)
		if err != nil {
			return nil, fmt.Errorf("schemacheck %s: %w", qq.kind, err)
		}
		for rows.Next() {
			var name, detail string
			if err := rows.Scan(&name, &detail); err != nil {
				rows.Close()
				return nil, fmt.Errorf("schemacheck %s: %w", qq.kind, err)
			}
			detail = strings.Join(strings.Fields(strip.ReplaceAllString(detail, "")), " ")
			fp[qq.kind+"/"+name] = Object{Kind: qq.kind, Name: name, Detail: detail}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return fp, nil
}

func Diff(want, got Fingerprint) (missing, different, extra []Object) {
	for k, w := range want {
		g, ok := got[k]
		switch {
		case !ok:
			missing = append(missing, w)
		case g.Detail != w.Detail:
			different = append(different, Object{Kind: w.Kind, Name: w.Name, Detail: "want: " + w.Detail + " | got: " + g.Detail})
		}
	}
	for k, g := range got {
		if _, ok := want[k]; !ok {
			extra = append(extra, g)
		}
	}
	for _, s := range [][]Object{missing, different, extra} {
		sort.Slice(s, func(i, j int) bool { return s[i].Kind+"/"+s[i].Name < s[j].Kind+"/"+s[j].Name })
	}
	return missing, different, extra
}
```
Note: the expected names in the test (`t.t_p_fkey`, `f()`, `t.tr`) follow these queries. If `pg_get_functiondef` output embeds the schema in `CREATE OR REPLACE FUNCTION a.f()`, the strip regex removes it — the test pins this.

- [ ] **Step 4: Run** → PASS 3/3. `go vet ./internal/db/schemacheck/`.

- [ ] **Step 5: Commit:**

```bash
git add orchestrator/go.mod orchestrator/go.sum orchestrator/internal/db/schemacheck
git commit -m "feat(db): schemacheck catalog fingerprint; add golang-migrate (H1)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 2: Freeze the legacy chain

**Files:** Create `orchestrator/internal/db/legacy/{db.go,schema.go,content_schema.go,ioc.go,ioc_enrichment.go,agent_groups_schema.go,agent_uninstall_schema.go,exercise_schema.go,freeze_test.go,FROZEN.sha256}`; modify the seven source files in `orchestrator/internal/db/` so each `Ensure*Schema` delegates.

**Interfaces:**
- Produces: `legacy.DB` interface; `legacy.EnsureSchema`, `EnsureContentSchema`, `EnsureIOCSchema`, `EnsureIOCEnrichmentSchema`, `EnsureAgentGroupSchema`, `EnsureAgentUninstallSchema`, `EnsureExerciseSchema` — each `func(ctx context.Context, db DB) error`; `legacy.EnsureAll(ctx, db DB) error` running them in the order `cmd/server/main.go:254-272` uses (Schema, Content, IOC, IOCEnrichment, AgentGroup, AgentUninstall, Exercise). `db.Ensure*` keep their signatures and delegate (removed in Task 8).

- [ ] **Step 1: Failing freeze test** — `orchestrator/internal/db/legacy/freeze_test.go`:

```go
// The legacy chain is frozen (H1 spec 7): it exists only to bring pre-H1
// installs to the baseline. Any edit must fail CI.
func TestLegacyChainIsFrozen(t *testing.T) {
	want, err := os.ReadFile("FROZEN.sha256")
	if err != nil { t.Fatal(err) }
	if got := hashSources(t); strings.TrimSpace(string(want)) != got {
		t.Fatalf("internal/db/legacy changed (got %s). The legacy chain is frozen; ship schema changes as a new migration in internal/db/migrations.", got)
	}
}

func hashSources(t *testing.T) string {
	files, err := filepath.Glob("*.go")
	if err != nil { t.Fatal(err) }
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") { continue }
		b, err := os.ReadFile(f)
		if err != nil { t.Fatal(err) }
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		fmt.Fprintf(h, "%s\x00%d\x00", f, len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestEnsureAllMatchesTodaysChain(t *testing.T) {
	// Pinned by Task 3's baseline equivalence test; here only that EnsureAll
	// runs cleanly twice (idempotent, like boot today).
	ctx := context.Background()
	pool := newPool(t) // empty postgres:16-alpine, same setup as testutil
	if err := legacy.EnsureAll(ctx, pool); err != nil { t.Fatal(err) }
	if err := legacy.EnsureAll(ctx, pool); err != nil { t.Fatalf("second run: %v", err) }
}
```
Run `go test ./internal/db/legacy/ -count=1` → FAIL: package does not exist.

- [ ] **Step 2: Move.** For each of the seven `Ensure*Schema` functions, MOVE the function (body unchanged, statement text byte-identical) into the matching file in `internal/db/legacy/`, plus any unexported helper or constant it references (copy the helper if other `db` code also uses it). Change only the parameter `pool *pgxpool.Pool` to `db DB` and rename uses `pool.` → `db.` inside the function (P2). `legacy/db.go`:

```go
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

func EnsureAll(ctx context.Context, db DB) error {
	for _, f := range []func(context.Context, DB) error{
		EnsureSchema, EnsureContentSchema, EnsureIOCSchema, EnsureIOCEnrichmentSchema,
		EnsureAgentGroupSchema, EnsureAgentUninstallSchema, EnsureExerciseSchema,
	} {
		if err := f(ctx, db); err != nil {
			return err
		}
	}
	return nil
}
```
In each original file in `internal/db/`, replace the moved function with a delegate keeping its exported signature and doc line, e.g. `func EnsureSchema(ctx context.Context, pool *pgxpool.Pool) error { return legacy.EnsureSchema(ctx, pool) }`. Before writing `FROZEN.sha256`, confirm the move is verbatim: `git diff -M --stat` plus, for each function, a diff of the old body (from `git show HEAD:orchestrator/internal/db/<file>`) against the new one showing only the `pool`→`db` parameter and receiver renames.

- [ ] **Step 3: Pin.** Run the freeze test once to print the hash (`go test ./internal/db/legacy/ -run Frozen` fails showing `got <hash>`), write that hash to `FROZEN.sha256`, run again → PASS. Run `go test ./internal/db/... ./internal/testutil/... -count=1` and `go build ./...` → PASS (behaviour unchanged: callers still reach the same statements).

- [ ] **Step 4: Commit:**

```bash
git add orchestrator/internal/db/legacy orchestrator/internal/db/postgres.go orchestrator/internal/db/content_schema.go orchestrator/internal/db/ioc.go orchestrator/internal/db/ioc_enrichment.go orchestrator/internal/db/agent_groups_schema.go orchestrator/internal/db/agent_uninstall_schema.go orchestrator/internal/db/exercise_schema.go
git commit -m "refactor(db): freeze the boot-time schema chain in internal/db/legacy (H1)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 3: Baseline capture and migration 000001

**Files:** Create `orchestrator/tools/h1-capture-baseline/main.go`, `orchestrator/internal/db/migrations/{embed.go,000001_baseline.up.sql,000001_baseline.down.sql,baseline_test.go}`.

**Interfaces:**
- Consumes: `legacy.EnsureAll` (Task 2), `schemacheck.Take/Diff` (Task 1).
- Produces: `migrations.FS embed.FS` (files `*.sql` at the root of the embed) and `migrations.Latest() (uint, error)` (highest `NNNNNN` prefix); baseline SQL is schema-relative (no `public.` qualifiers) and runs under `search_path` = target schema, `public`.

- [ ] **Step 1: Failing equivalence test** — `orchestrator/internal/db/migrations/baseline_test.go`:

```go
// fingerprint(empty + 000001) must equal fingerprint(empty + legacy chain);
// runs in CI until internal/db/legacy is deleted (H1 spec 4.5).
func TestBaselineEqualsLegacyChain(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	if err := legacy.EnsureAll(ctx, pool); err != nil { t.Fatal(err) }
	up, err := migrations.FS.ReadFile("000001_baseline.up.sql")
	if err != nil { t.Fatal(err) }
	mustExec(t, pool, `CREATE SCHEMA h1_fp`)
	tx, err := pool.Begin(ctx)
	if err != nil { t.Fatal(err) }
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL search_path TO h1_fp, public`); err != nil { t.Fatal(err) }
	if _, err := tx.Exec(ctx, string(up)); err != nil { t.Fatalf("baseline: %v", err) }
	want, err := schemacheck.Take(ctx, tx, "public")
	if err != nil { t.Fatal(err) }
	got, err := schemacheck.Take(ctx, tx, "h1_fp")
	if err != nil { t.Fatal(err) }
	if m, d, e := schemacheck.Diff(want, got); len(m)+len(d)+len(e) > 0 {
		t.Fatalf("baseline differs from legacy chain:\nmissing %v\ndifferent %v\nextra %v", m, d, e)
	}
}

func TestBaselineDownThenUp(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	up, _ := migrations.FS.ReadFile("000001_baseline.up.sql")
	down, _ := migrations.FS.ReadFile("000001_baseline.down.sql")
	for i, sql := range []string{string(up), string(down), string(up)} {
		if _, err := pool.Exec(ctx, sql); err != nil { t.Fatalf("step %d: %v", i, err) }
	}
}

func TestLatest(t *testing.T) {
	if v, err := migrations.Latest(); err != nil || v < 1 { t.Fatalf("Latest = %d, %v", v, err) }
}
```
Run → FAIL: package does not exist.

- [ ] **Step 2: `embed.go`:**

```go
// Package migrations is the embedded, immutable migration set (H1). Rules:
// README.md. Shipped files never change; CI pins them in MANIFEST.sha256.
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"strconv"
)

//go:embed *.sql
var FS embed.FS

func Latest() (uint, error) {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		return 0, err
	}
	var max uint
	for _, e := range entries {
		if len(e.Name()) < 7 {
			continue
		}
		n, err := strconv.ParseUint(e.Name()[:6], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("migration %s: bad version prefix", e.Name())
		}
		if uint(n) > max {
			max = uint(n)
		}
	}
	return max, nil
}
```

- [ ] **Step 3: Capture tool** — `orchestrator/tools/h1-capture-baseline/main.go` (one-time; kept for audit, not built into the server):

```go
// One-time H1 tool: builds a fresh database with the frozen legacy chain and
// writes internal/db/migrations/000001_baseline.up.sql from pg_dump.
// Usage (from orchestrator/, Docker running): go run ./tools/h1-capture-baseline
package main
```
Behaviour: start `postgres:16-alpine` with testcontainers (`tcpostgres.Run`), connect, `legacy.EnsureAll`, then `docker exec <container> pg_dump -U <user> --schema-only --no-owner --no-privileges --no-comments <db>` (use the container's `Exec` API); normalize the dump text:
  - drop lines starting with `SET `, `SELECT pg_catalog.set_config`, `--`, and blank-line runs;
  - remove every `public.` qualifier (regex `\bpublic\.`), and replace `CREATE SCHEMA public;`/`COMMENT ON SCHEMA public` lines with nothing;
  - keep `CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;` as `CREATE EXTENSION IF NOT EXISTS pgcrypto;`;
  - no `GRANT`/`REVOKE`/`ALTER DEFAULT PRIVILEGES`/`OWNER TO` remain (assert; `--no-owner --no-privileges` should already drop them);
  write with a header comment (`-- 000001 baseline captured <date> from internal/db/legacy (frozen). Never edit.`).
Also write `000001_baseline.down.sql`: `DROP TABLE IF EXISTS <every table> CASCADE;` (from the fingerprint's tables, sorted), then `DROP SEQUENCE IF EXISTS …`, `DROP FUNCTION IF EXISTS …`, in that order, with a header: `-- Development/test only. Production rollback is the upgrade snapshot (install.sh --rollback).`

Run: `go run ./tools/h1-capture-baseline` → writes both files. Inspect the up file: no `IF NOT EXISTS` on tables (pg_dump emits plain `CREATE TABLE`), no `INSERT`/`COPY` (schema-only), no role statements.

- [ ] **Step 4: Run the tests** → PASS 3/3. If the equivalence test reports differences, fix the normalizer (never hand-edit the dump to make it pass) and recapture.

- [ ] **Step 5: Commit:**

```bash
git add orchestrator/tools/h1-capture-baseline orchestrator/internal/db/migrations
git commit -m "feat(db): 000001 baseline migration captured from the frozen legacy chain (H1)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 4: Reference-data seed

**Files:** Create `orchestrator/internal/db/seed/{embed.go,seed.go,SEED_VERSION,seed_test.go}` and one `.sql` per group (names below); `docs/` none.

**Interfaces:**
- Produces: `seed.Version() (int, error)` (reads `SEED_VERSION`); `seed.Apply(ctx context.Context, tx pgx.Tx) error` — executes every `*.sql` in lexical order, then `INSERT INTO reference_data_version (id, version, applied_at) VALUES (1, $1, now()) ON CONFLICT (id) DO UPDATE SET version = EXCLUDED.version, applied_at = EXCLUDED.applied_at`; `seed.Current(ctx, q schemacheck.Querier) (int, error)` (0 when the table is absent or empty). `reference_data_version` is created by migration `000002_reference_data_version.up.sql` (this task): `CREATE TABLE reference_data_version (id int PRIMARY KEY CHECK (id = 1), version int NOT NULL, applied_at timestamptz NOT NULL);` with down `DROP TABLE reference_data_version;`.

- [ ] **Step 1: Classify every boot-time data statement.** List every `INSERT`/`UPDATE`/`DELETE` in `internal/db/legacy/*.go` (expected ≈47) in the report with: table, statement summary, and destination:
  - **seed** — required system rows (default tenant, default `sla_policy` rows, …) and reference definitions (`payload_families`, …);
  - **already done** — one-time repairs (`DELETE FROM variant_findings …` dedupe): pre-H1 installs get them from the legacy chain during adoption; fresh installs have nothing to repair. Not carried forward.
  For each seed table decide **editable or not**: `grep -rn "<table>" internal/api` for `INSERT`/`UPDATE`/`DELETE` write paths reachable from HTTP handlers. Editable → the seed statement uses `ON CONFLICT (<natural key>) DO NOTHING` (never overwrite operator changes); not editable → `ON CONFLICT … DO UPDATE` exactly as today. Record the decision in each `.sql` header: `-- table: payload_families; operator-editable: no (no API write path); policy: DO UPDATE`.

- [ ] **Step 2: Failing tests** — `seed_test.go` (pool from a fresh DB migrated with `000001` + `000002` via plain `Exec` of the files, since `migrate` arrives in Task 5):

```go
func TestApply_IdempotentAndVersioned(t *testing.T) {
	ctx := context.Background()
	pool := migratedPool(t)
	for i := 0; i < 2; i++ {
		tx, _ := pool.Begin(ctx)
		if err := seed.Apply(ctx, tx); err != nil { t.Fatal(err) }
		if err := tx.Commit(ctx); err != nil { t.Fatal(err) }
	}
	v, _ := seed.Version()
	if got, err := seed.Current(ctx, pool); err != nil || got != v { t.Fatalf("Current = %d, %v; want %d", got, err, v) }
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id = 'default'`).Scan(&n)
	if n != 1 { t.Fatalf("default tenant rows = %d", n) }
}

func TestApply_NeverOverwritesOperatorEditableRows(t *testing.T) {
	// For each table classified operator-editable in Step 1: edit a seeded
	// row's editable column, re-apply, assert the edit survived. One subtest
	// per editable table (table, key, column, edited value).
}

func TestApply_MatchesLegacySeedRows(t *testing.T) {
	// Fresh DB A: legacy.EnsureAll. Fresh DB B: 000001 + 000002 + seed.Apply.
	// For every seed table: identical row sets (SELECT * ORDER BY <pk>,
	// excluding created_at/updated_at-style timestamp columns).
}
```
Fill the two outlined tests with the concrete tables from Step 1 (the comments state exactly what each asserts). Run → FAIL: package does not exist.

- [ ] **Step 3: Implement.** `embed.go` (`//go:embed *.sql SEED_VERSION`), `seed.go` per the Interfaces block, `SEED_VERSION` = `1`, and the `.sql` files (`010_tenants.sql`, `020_system_defaults.sql`, `030_payload_families.sql`, … — copy each statement's text from the legacy chain, applying only the Step 1 conflict policy). Add `000002_reference_data_version.{up,down}.sql` to `internal/db/migrations/`.

- [ ] **Step 4: Run** → PASS. `go vet ./internal/db/seed/`.

- [ ] **Step 5: Commit:**

```bash
git add orchestrator/internal/db/seed orchestrator/internal/db/migrations/000002_reference_data_version.up.sql orchestrator/internal/db/migrations/000002_reference_data_version.down.sql
git commit -m "feat(db): versioned reference-data seed, separate from schema migrations (H1)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 5: `migrate` core — classification, golang-migrate, lock, status

**Files:** Create `orchestrator/internal/db/migrate/{migrate.go,classify.go,migrate_test.go,testdata/bad/000001_x.up.sql …}`.

**Interfaces:**
- Consumes: `migrations.FS`, `migrations.Latest` (Task 3); `seed.Apply`, `seed.Version`, `seed.Current` (Task 4).
- Produces:
  - `type State int` with `Fresh, PreH1, Managed, Dirty, Newer, Unrecognised`; `func Classify(ctx, conn *pgx.Conn) (State, uint, error)` (uint = recorded version).
  - `type Options struct { AppPassword string; SkipRole bool; Out io.Writer; Source fs.FS }` (`Source` defaults to `migrations.FS`; tests inject bad sets; `SkipRole` for tests that do not exercise roles).
  - `type Result struct { FromVersion, ToVersion uint; FromSeed, ToSeed int; Adopted bool; Extra []schemacheck.Object; Role string }`; `func (r Result) Summary() string` → `schema 1→3, reference data 2→3, bas_app ok`.
  - `func Up(ctx context.Context, adminDSN string, opt Options) (Result, error)`.
  - `type Status struct { Version uint; Dirty bool; Seed, WantVersion uint; WantSeed int; Pending bool }`; `func GetStatus(ctx, adminDSN string) (Status, error)`.
  - Errors: `ErrDirty`, `ErrNewer`, `ErrUnrecognised` (wrapped with the operator message).
  - Lock: `pg_advisory_lock(7264110001)` held on a dedicated connection for the whole `Up`.

Classification (spec 4.3): `schema_migrations` exists → read `version, dirty` → `dirty` ⇒ Dirty; `version > Latest` ⇒ Newer; else Managed. No `schema_migrations`: count of sentinel tables (`tenants`, `agents`, `scenario_runs`) in `public` = 3 ⇒ PreH1; no user tables in `public` ⇒ Fresh; else ⇒ Unrecognised.

- [ ] **Step 1: Failing tests** — `migrate_test.go` (each test gets a fresh database; `newDSN(t)` returns an admin DSN to a new empty database on a shared container):

```go
func TestUp_FreshDatabase(t *testing.T) { // H1-T1 (schema part)
	ctx := context.Background()
	dsn := newDSN(t)
	r, err := migrate.Up(ctx, dsn, migrate.Options{SkipRole: true})
	if err != nil { t.Fatal(err) }
	latest, _ := migrations.Latest()
	if r.FromVersion != 0 || r.ToVersion != latest { t.Fatalf("result %+v", r) }
	assertFingerprintEqualsBaselinePlus(t, dsn) // public vs empty+all migrations in a temp schema
}

func TestUp_Idempotent(t *testing.T) { // H1-T2
	ctx := context.Background()
	dsn := newDSN(t)
	migrate.Up(ctx, dsn, migrate.Options{SkipRole: true})
	before := fingerprintAndCounts(t, dsn)
	for i := 0; i < 2; i++ {
		r, err := migrate.Up(ctx, dsn, migrate.Options{SkipRole: true})
		if err != nil || r.FromVersion != r.ToVersion { t.Fatalf("run %d: %+v %v", i, r, err) }
	}
	if after := fingerprintAndCounts(t, dsn); !reflect.DeepEqual(before, after) { t.Fatal("schema or row counts changed") }
}

func TestUp_ConcurrentRunsSerialize(t *testing.T) { // Review Focus 2
	ctx := context.Background()
	dsn := newDSN(t)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, errs[i] = migrate.Up(ctx, dsn, migrate.Options{SkipRole: true}) }(i)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil { t.Fatalf("errs %v", errs) }
	st, _ := migrate.GetStatus(ctx, dsn)
	if st.Dirty || st.Pending { t.Fatalf("status %+v", st) }
}

func TestMigrationSet_OrderedNoGapsNoDuplicates(t *testing.T) { // H1-T4
	checkSet(t, migrations.FS) // versions 1..N contiguous, each with .up.sql and .down.sql, no duplicates
}

func TestUp_FailingMigrationLeavesDirtyAndRefuses(t *testing.T) { // H1-T5
	ctx := context.Background()
	dsn := newDSN(t)
	bad := fstest.MapFS{} // 000001 + 000002 copied from migrations.FS, plus 000003_fail.up.sql = "SELECT 1/0;" and its down
	copyInto(t, bad, migrations.FS)
	bad["000003_fail.up.sql"] = &fstest.MapFile{Data: []byte("CREATE TABLE h1_t5 (id int); SELECT 1/0;")}
	bad["000003_fail.down.sql"] = &fstest.MapFile{Data: []byte("DROP TABLE IF EXISTS h1_t5;")}
	if _, err := migrate.Up(ctx, dsn, migrate.Options{SkipRole: true, Source: bad}); err == nil { t.Fatal("want failure") }
	st, _ := migrate.GetStatus(ctx, dsn)
	if !st.Dirty || st.Version != 3 { t.Fatalf("status %+v", st) }
	if _, err := migrate.Up(ctx, dsn, migrate.Options{SkipRole: true}); !errors.Is(err, migrate.ErrDirty) { t.Fatalf("second Up err = %v", err) }
}

func TestUpDownUp_TestMigration(t *testing.T) { // H1-T6
	// Source = migrations.FS + 000003_t6 (CREATE TABLE h1_t6 (id int) / DROP TABLE h1_t6);
	// Up to 3, then golang-migrate Steps(-1) via migrate.DownOne(ctx, dsn, src) (test-only
	// export in export_test.go), then Up again; table exists after the final Up.
}

func TestClassify_NewerAndUnrecognised(t *testing.T) {
	ctx := context.Background()
	dsn := newDSN(t)
	migrate.Up(ctx, dsn, migrate.Options{SkipRole: true})
	mustExecDSN(t, dsn, `UPDATE schema_migrations SET version = 999`)
	if _, err := migrate.Up(ctx, dsn, migrate.Options{SkipRole: true}); !errors.Is(err, migrate.ErrNewer) { t.Fatalf("err = %v", err) }
	dsn2 := newDSN(t)
	mustExecDSN(t, dsn2, `CREATE TABLE someone_elses (id int)`)
	if _, err := migrate.Up(ctx, dsn2, migrate.Options{SkipRole: true}); !errors.Is(err, migrate.ErrUnrecognised) { t.Fatalf("err = %v", err) }
}
```
Write the outlined test (`TestUpDownUp_TestMigration`) in full with the helpers. Run `go test ./internal/db/migrate/ -count=1` → FAIL: package does not exist.

- [ ] **Step 2: Implement** `classify.go` (per the rules above) and `migrate.go`:
  - `Up`: open a dedicated `*pgx.Conn` (admin DSN) and take the advisory lock; `Classify`; Dirty/Newer/Unrecognised → return the wrapped error with the operator message from spec 4.3; PreH1 → `adopt(...)` (Task 6; until then return `errors.New("adoption not implemented")` — Task 6 replaces it, and no test in this task reaches it); Fresh/Managed → run golang-migrate: `src, _ := iofs.New(opt.Source, ".")`; `sqlDB := stdlib.OpenDBFromPool(pool)` (pool from admin DSN); `drv, _ := pgx5.WithInstance(sqlDB, &pgx5.Config{})`; `m, _ := gomigrate.NewWithInstance("iofs", src, "pgx5", drv)`; `m.Up()` (treat `gomigrate.ErrNoChange` as success). Then, in one transaction: `seed.Apply`. Then role (Task 7; skipped when `SkipRole`, and until Task 7 always skipped). Release the lock; return `Result`.
  - `GetStatus`: read `schema_migrations` and `seed.Current`; compare with `migrations.Latest` and `seed.Version`.
  Note: golang-migrate's pgx5 driver takes its own advisory lock as well; ours covers adoption, seed and role around it.

- [ ] **Step 3: Run** → PASS. `go vet ./internal/db/migrate/`. Race: Docker recipe on `./internal/db/migrate/`.

- [ ] **Step 4: Commit:**

```bash
git add orchestrator/internal/db/migrate
git commit -m "feat(db): migrate core -- classification, embedded golang-migrate, advisory lock, status (H1)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 6: Adoption of pre-H1 installs

**Files:** Create `orchestrator/internal/db/migrate/{adopt.go,adopt_test.go}`; migration `000003_h1_adoption_report.{up,down}.sql`.

**Interfaces:**
- Consumes: `legacy.EnsureAll` (Task 2), `schemacheck` (Task 1), `migrations.FS` (Task 3), `Up`'s PreH1 branch (Task 5).
- Produces: `adopt(ctx, conn *pgx.Conn, opt Options) (extra []schemacheck.Object, err error)`; `ErrAdoptionMismatch` (message lists every missing/different object); table `h1_adoption_report(object text, kind text, detail text, recorded_at timestamptz NOT NULL DEFAULT now())` created by migration 000003 (so fresh installs have it too); extras are inserted after 000003 is applied.

Adoption sequence (spec 4.3), all in one transaction `tx` on `conn`:
1. `legacy.EnsureAll(ctx, tx)`.
2. `CREATE SCHEMA h1_fp`; `SET LOCAL search_path TO h1_fp, public`; execute `000001_baseline.up.sql`; `want := Take(tx, "h1_fp")`; `SET LOCAL search_path TO public`; `got := Take(tx, "public")`; `DROP SCHEMA h1_fp CASCADE`.
3. `missing, different, extra := Diff(want, got)`; `len(missing)+len(different) > 0` → return `ErrAdoptionMismatch` (transaction rolled back by the caller: nothing written, no `schema_migrations`).
4. Create golang-migrate's table in the same transaction exactly as the pgx5 driver defines it (`CREATE TABLE IF NOT EXISTS schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)`) and `INSERT INTO schema_migrations VALUES (1, false)`.
5. Commit. `Up` then continues as Managed (migrations 2…N, which includes 000003), then inserts `extra` into `h1_adoption_report`, then seed and role. `Result.Adopted = true`, `Result.Extra = extra`, and `Up` writes the extras to `opt.Out`.

- [ ] **Step 1: Failing tests** — `adopt_test.go`:

```go
func TestAdopt_PreservesDataAndMarksBaseline(t *testing.T) { // H1-T3
	ctx := context.Background()
	dsn := newDSN(t)
	pool := poolFor(t, dsn)
	if err := legacy.EnsureAll(ctx, pool); err != nil { t.Fatal(err) }
	seedRepresentativeRows(t, pool) // >= 1 row in every table, via testutil builders where they exist
	before := tableChecksums(t, pool) // map[table]md5(string_agg(row::text ORDER BY row::text))
	r, err := migrate.Up(ctx, dsn, migrate.Options{SkipRole: true})
	if err != nil { t.Fatal(err) }
	if !r.Adopted || r.FromVersion != 0 { t.Fatalf("result %+v", r) }
	after := tableChecksums(t, pool)
	for tbl, sum := range before {
		if after[tbl] != sum && !isSeedTable(tbl) { t.Errorf("table %s changed", tbl) }
	}
	st, _ := migrate.GetStatus(ctx, dsn)
	if st.Pending || st.Dirty { t.Fatalf("status %+v", st) }
}

func TestAdopt_OlderReleaseSchema(t *testing.T) { // H1-T3 variant
	// legacy.EnsureAll, then simulate an older release by dropping objects
	// added recently (DROP TABLE legacy_transport_log, legacy_transport_unattributed,
	// agent_certificates; ALTER TABLE agents DROP COLUMN <one recent column>) --
	// the legacy chain is additive, so these are exactly what an older release
	// lacked. Up must adopt (the legacy run restores them) with no error.
}

func TestAdopt_ExtraObjectsReportedNotBlocking(t *testing.T) { // H1-T3 variant
	// legacy.EnsureAll + CREATE TABLE old_leftover(id int) + ALTER TABLE agents ADD COLUMN old_col text.
	// Up succeeds; r.Extra contains table/old_leftover and column/agents.old_col;
	// h1_adoption_report has both rows.
}

func TestAdopt_MissingObjectFailsClosed(t *testing.T) { // H1-T3b
	// legacy.EnsureAll, then make the baseline unreachable for the legacy chain:
	// ALTER TABLE agents ALTER COLUMN hostname TYPE varchar(3) USING left(hostname,3)
	// (the additive chain never changes an existing column back). Up returns
	// ErrAdoptionMismatch naming column/agents.hostname; schema_migrations does
	// not exist afterwards.
}
```
Write the three outlined tests in full (the comments specify inputs and assertions). Pick the "recent column" in `TestAdopt_OlderReleaseSchema` from the legacy chain's latest `ADD COLUMN` statements and name it in the test. Run → FAIL (`adoption not implemented`).

- [ ] **Step 2: Implement** `adopt.go` per the sequence; wire it into `Up`'s PreH1 branch; add migration `000003_h1_adoption_report.{up,down}.sql`.

- [ ] **Step 3: Run** `go test ./internal/db/migrate/ ./internal/db/migrations/ -count=1` → PASS (Task 5 tests still pass with 000003 present). Race via the Docker recipe.

- [ ] **Step 4: Commit:**

```bash
git add orchestrator/internal/db/migrate/adopt.go orchestrator/internal/db/migrate/adopt_test.go orchestrator/internal/db/migrate/migrate.go orchestrator/internal/db/migrations/000003_h1_adoption_report.up.sql orchestrator/internal/db/migrations/000003_h1_adoption_report.down.sql
git commit -m "feat(db): adopt pre-H1 installs -- frozen chain, fingerprint check, fail closed (H1)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 7: `bas_app` provisioning, verification and rotation

**Files:** Create `orchestrator/internal/db/migrate/{role.go,role_test.go}`; modify `migrate.go` (call role step unless `SkipRole`).

**Interfaces:**
- Consumes: today's `db.EnsureAppRole` statements (`internal/db/app_role.go`) — the grant statements are copied verbatim; the per-boot password `ALTER ROLE` is not.
- Produces: `const AppRole = "bas_app"`; `func ensureRole(ctx, conn *pgx.Conn, appPassword, adminDSN string) (created bool, err error)`; `func RotateAppPassword(ctx context.Context, adminDSN, newPassword string) error`; `ErrAppPasswordMismatch` with message `bas_app password does not match BAS_APP_DB_PASSWORD -- run: install.sh --rotate-db-app-password`.

Role step: if `pg_roles` has no `bas_app` → `CREATE ROLE bas_app LOGIN NOSUPERUSER NOBYPASSRLS` + password via `format('ALTER ROLE bas_app PASSWORD %L', $1)` (server-side escaping, as today) → `created = true`. Always re-apply the grant block from `EnsureAppRole` (CONNECT via `format('GRANT CONNECT ON DATABASE %I …', current_database())`, `USAGE ON SCHEMA public`, table DML, sequence privileges, `ALTER DEFAULT PRIVILEGES`). Then build a bas_app DSN from the admin DSN (same host/port/database, user `bas_app`, password `appPassword`) and `pgx.Connect` + `Ping`; failure with SQLSTATE `28P01` → `ErrAppPasswordMismatch`. `Result.Role = "bas_app created"` or `"bas_app ok"`.

- [ ] **Step 1: Failing tests** — `role_test.go`:

```go
func TestRole_CreatedWithDMLOnly(t *testing.T) { // H1-T1 (role part), H1-T8
	ctx := context.Background()
	dsn := newDSN(t)
	r, err := migrate.Up(ctx, dsn, migrate.Options{AppPassword: "p1"})
	if err != nil || r.Role != "bas_app created" { t.Fatalf("%+v %v", r, err) }
	app := connectAs(t, dsn, "bas_app", "p1")
	if _, err := app.Exec(ctx, `CREATE TABLE x (id int)`); err == nil { t.Fatal("bas_app could run DDL") }
	if _, err := app.Exec(ctx, `SELECT count(*) FROM agents`); err != nil { t.Fatalf("bas_app cannot read: %v", err) }
}

func TestRole_WrongConfiguredPasswordStopsAndLeavesPassword(t *testing.T) { // Review Focus 3
	ctx := context.Background()
	dsn := newDSN(t)
	migrate.Up(ctx, dsn, migrate.Options{AppPassword: "p1"})
	_, err := migrate.Up(ctx, dsn, migrate.Options{AppPassword: "edited-in-env"})
	if !errors.Is(err, migrate.ErrAppPasswordMismatch) { t.Fatalf("err = %v", err) }
	connectAs(t, dsn, "bas_app", "p1") // still the old password
}

func TestRotateAppPassword(t *testing.T) {
	ctx := context.Background()
	dsn := newDSN(t)
	migrate.Up(ctx, dsn, migrate.Options{AppPassword: "p1"})
	if err := migrate.RotateAppPassword(ctx, dsn, "p2"); err != nil { t.Fatal(err) }
	connectAs(t, dsn, "bas_app", "p2")
	if c, err := tryConnect(ctx, dsn, "bas_app", "p1"); err == nil { c.Close(ctx); t.Fatal("old password still works") }
	if r, err := migrate.Up(ctx, dsn, migrate.Options{AppPassword: "p2"}); err != nil || r.Role != "bas_app ok" { t.Fatalf("%+v %v", r, err) }
}

func TestRole_GrantsCoverTablesCreatedByLaterMigrations(t *testing.T) {
	// Up with a Source containing an extra 00000N_t (CREATE TABLE h1_later (id int));
	// bas_app can INSERT into h1_later (default privileges or re-applied grants).
}
```
`bas_app` is a cluster-wide role: each test uses a fresh container (`newIsolatedDSN(t)`) or drops the role in `t.Cleanup`. Write the outlined test in full. Run → FAIL.

- [ ] **Step 2: Implement** `role.go`; in `Up`, call `ensureRole` after the seed unless `SkipRole`. Delete nothing in `internal/db/app_role.go` yet (Task 8 removes the boot call).

- [ ] **Step 3: Run** `go test ./internal/db/migrate/ -count=1` → PASS; race via Docker.

- [ ] **Step 4: Commit:**

```bash
git add orchestrator/internal/db/migrate/role.go orchestrator/internal/db/migrate/role_test.go orchestrator/internal/db/migrate/migrate.go
git commit -m "feat(db): migrate provisions bas_app, verifies its password, explicit rotation (H1)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 8: Command, runtime check, startup switch, test harness

**Files:** Create `orchestrator/internal/db/migrate/{runtime.go,runtime_test.go}`, `orchestrator/cmd/server/migrate_cmd.go` (+ test); modify `orchestrator/cmd/server/main.go`, `orchestrator/internal/testutil/testdb.go`, every test file calling `db.Ensure*` directly (9 files: `grep -rln 'db\.Ensure[A-Za-z]*Schema' --include=*_test.go .`), `orchestrator/internal/db/{postgres.go,…}` (delete the Task 2 delegates), `orchestrator/internal/db/app_role.go` (delete `EnsureAppRole`; keep only what `migrate` imports, or move the constant), `orchestrator/config/config.go` (comment: admin URL only for migrate), `packaging/compose/docker-compose.yml`, `docker-compose.prod.yml`.

**Interfaces:**
- Produces: `func CheckRuntime(ctx context.Context, q schemacheck.Querier) error` (SELECT-only); errors `ErrSchemaBehind`, `ErrSchemaAhead`, `ErrSchemaDirty`, `ErrSchemaMissing`, `ErrSeedBehind`, each with the operator action (`run: install.sh --upgrade` / `run: install.sh --rollback`); `func runMigrateCmd(args []string, cfg *config.Config, out io.Writer) int` handling `migrate up|status|rotate-app-password`.

- [ ] **Step 1: Failing runtime tests** — `runtime_test.go`:

```go
func TestCheckRuntime(t *testing.T) { // H1-T7, Review Focus 5
	ctx := context.Background()
	dsn := newDSN(t)
	pool := poolFor(t, dsn)
	if err := migrate.CheckRuntime(ctx, pool); !errors.Is(err, migrate.ErrSchemaMissing) { t.Fatalf("empty: %v", err) }
	migrate.Up(ctx, dsn, migrate.Options{SkipRole: true})
	if err := migrate.CheckRuntime(ctx, pool); err != nil { t.Fatalf("current: %v", err) }
	mustExec(t, pool, `UPDATE schema_migrations SET version = version - 1`)
	if err := migrate.CheckRuntime(ctx, pool); !errors.Is(err, migrate.ErrSchemaBehind) || !strings.Contains(err.Error(), "install.sh --upgrade") { t.Fatalf("behind: %v", err) }
	mustExec(t, pool, `UPDATE schema_migrations SET version = 999`)
	if err := migrate.CheckRuntime(ctx, pool); !errors.Is(err, migrate.ErrSchemaAhead) { t.Fatalf("ahead: %v", err) }
	mustExec(t, pool, `UPDATE schema_migrations SET version = (SELECT 3), dirty = true`)
	if err := migrate.CheckRuntime(ctx, pool); !errors.Is(err, migrate.ErrSchemaDirty) { t.Fatalf("dirty: %v", err) }
}

func TestCheckRuntime_IssuesOnlySelects(t *testing.T) { // H1-T7
	// Connect with a pgx QueryTracer recording every SQL string; run CheckRuntime
	// on a current database; every recorded statement starts with SELECT.
}
```
Write the outlined test in full. Run → FAIL.

- [ ] **Step 2: Implement** `runtime.go`: read `schema_migrations` (missing table → `ErrSchemaMissing`), dirty → `ErrSchemaDirty`, compare with `migrations.Latest()`, then `seed.Current` vs `seed.Version()` (`ErrSeedBehind`, message also `install.sh --upgrade`). Run → PASS.

- [ ] **Step 3: Command.** `cmd/server/migrate_cmd.go`: `runMigrateCmd` — `up`: `migrate.Up(ctx, cfg.DatabaseAdminURL, migrate.Options{AppPassword: cfg.AppDBPassword, Out: out})`, print `Summary()` and extras, exit 0/1; `status`: print `GetStatus` as one line (`schema 3 (latest 3), dirty=false, reference data 1 (latest 1), pending=false`), exit 0 when not pending, 2 when pending, 1 on error; `rotate-app-password`: `migrate.RotateAppPassword(ctx, cfg.DatabaseAdminURL, cfg.AppDBPassword)`. All require `DATABASE_ADMIN_URL` (exit 1 with a clear message when empty). Unit-test argument handling (`migrate`, `migrate bogus`, missing admin URL) in `migrate_cmd_test.go` without a database.
  In `main.go`, before the existing `os.Args[1]` handling: `if len(os.Args) > 1 && os.Args[1] == "migrate" { cfg := <load config exactly as the server does>; os.Exit(runMigrateCmd(os.Args[2:], cfg, os.Stdout)) }`. Replace lines 241-290 (admin pool, seven `Ensure*`, `EnsureAppRole`) with nothing; after the runtime pool connects (`db.Connect(ctx, cfg.DatabaseURL)`), call `migrate.CheckRuntime(ctx, pool)` and `log.Fatalf("[FATAL] %v", err)` on error. Keep the comments' rationale where it still applies.

- [ ] **Step 4: Test harness.** `internal/testutil/testdb.go` `newTestDB`: replace the seven `Ensure*` calls with `migrate.Up(ctx, adminDSN, migrate.Options{SkipRole: true})`. In `truncateAll`, replace the hand-re-inserted default rows (tenant, `sla_policy`, …) with `seed.Apply` in a transaction (same rows, now from the single source). Change the 9 test files that call `db.Ensure*` to use the testutil DB (or `migrate.Up` on their own container); `internal/db/postgres_test.go`'s idempotency test becomes a migrate test or is deleted with a note (its subject, boot-time `EnsureSchema`, no longer exists — `TestUp_Idempotent` covers it). Delete the Task 2 delegates and `EnsureAppRole`'s boot path; `go build ./...` must show no remaining reference (`grep -rn 'db\.Ensure' --include=*.go .` → only none).

- [ ] **Step 5: Compose.** In `packaging/compose/docker-compose.yml` (and `.prod.yml` if it repeats the env), remove `DATABASE_ADMIN_URL` and `POSTGRES_PASSWORD` from the `orchestrator` service's `environment`; keep `DATABASE_URL` and `BAS_APP_DB_PASSWORD` (the latter is needed by `migrate` runs, which receive the admin DSN separately from install.sh — see Task 9 — and is harmless at runtime). Update the surrounding comments.

- [ ] **Step 6: Full verification.** `go build ./...`; `go vet ./...`; `go test ./... -p 2 -count=1` (record pass counts; failures that predate H1 are reported by name); race via Docker on `./internal/db/... ./internal/testutil/... ./cmd/server/...`. Build the garbled image as the Dockerfile does (`docker build -f orchestrator/Dockerfile .` or the repo's build script) to confirm embedded SQL survives garble; run the built image with `migrate status` against a throwaway Postgres container to prove the subcommand works in the distroless image.

- [ ] **Step 7: Commit:**

```bash
git add orchestrator/internal/db/migrate/runtime.go orchestrator/internal/db/migrate/runtime_test.go orchestrator/cmd/server/migrate_cmd.go orchestrator/cmd/server/migrate_cmd_test.go orchestrator/cmd/server/main.go orchestrator/internal/testutil/testdb.go orchestrator/internal/db/<each changed file> <each changed test file> orchestrator/config/config.go packaging/compose/docker-compose.yml packaging/compose/docker-compose.prod.yml
git commit -m "feat(server): migrate subcommands; startup only checks the schema version, no boot DDL (H1)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 9: install.sh — upgrade record, snapshot, migrate step, rollback, rotation

**Files:** Create `packaging/compose/lib/upgrade-db.sh`, `packaging/compose/tests/upgrade_db_test.sh`; modify `packaging/compose/install.sh` (`--install`, `--upgrade`, `--rollback`, new `--rotate-db-app-password`, usage text), `packaging/compose/VERIFY.md` (operator notes).

**Interfaces:**
- Consumes: `orchestrator migrate up|status|rotate-app-password` (Task 8); existing helpers `_run_pg_dump`, the `openssl enc -aes-256-cbc -pbkdf2 … -pass file:${DATA_DIR}/.backup_key` pattern, `log/info/err/step`.
- Produces (`lib/upgrade-db.sh`, sourced by install.sh; every function takes explicit arguments so the test can drive it):
  - `upgrade_record_create <data_dir> <from> <to>` → prints the record dir `backups/upgrade-<ts>-<from>-to-<to>`, writes `UPGRADE.json` with `state: started`;
  - `upgrade_record_set <dir> <key> <value>` (updates one JSON field with `python3 -c`/`jq` if available, else a fixed sed on the known keys — use whichever the install host already requires; `install.sh --check` lists required tools);
  - `db_snapshot <dir>` → `db.dump.enc` via `_run_pg_dump` + encrypt, `pg_restore --list` check on the decrypted stream, SHA-256 into `UPGRADE.json`;
  - `db_restore <dir>` → verify hash; `docker exec audspect-postgres dropdb -U bas_user --force bas_platform` + `createdb -U bas_user bas_platform`; decrypt | `docker exec -i audspect-postgres pg_restore -U bas_user -d bas_platform --no-owner`;
  - `upgrade_record_latest <data_dir>` → newest `backups/upgrade-*` dir by its timestamp prefix, ignoring every other backup directory;
  - `run_migrate <subcommand>` → `docker compose -f "${DATA_DIR}/docker-compose.yml" run --rm -e DATABASE_ADMIN_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}?sslmode=prefer" orchestrator migrate <subcommand>`.

- [ ] **Step 1: Failing shell test** — `packaging/compose/tests/upgrade_db_test.sh` (runs on a Docker host; starts `postgres:16-alpine` named `audspect-postgres` with `POSTGRES_USER=bas_user POSTGRES_DB=bas_platform`, a temp `DATA_DIR` with a `.backup_key`, sources `lib/upgrade-db.sh` and install.sh's helper functions it needs):
  1. create table + rows; `upgrade_record_create` + `db_snapshot`; assert `UPGRADE.json` has the dump hash and `pg_restore --list` succeeded;
  2. mutate (insert rows, add a column) → `db_restore` → exact pre-upgrade row set and no added column (H1-T10);
  3. create `backups/<newer-timestamp>` scheduled-backup dir (the `backup-worker` naming) after the upgrade record → `upgrade_record_latest` returns the upgrade record (Review Focus 4);
  4. tamper with `db.dump.enc` → `db_restore` refuses (hash mismatch) and the database is untouched.
  Run `bash packaging/compose/tests/upgrade_db_test.sh` → FAIL (lib missing).

- [ ] **Step 2: Implement** `lib/upgrade-db.sh` → test PASS.

- [ ] **Step 3: Wire install.sh** (keep existing structure, numbering and messages style):
  - `--install`: after Postgres is healthy and before starting the orchestrator: `run_migrate up` (fatal on failure).
  - `--upgrade` (spec 5): validate (existing checks + free space ≥ 2× `pg_database_size`); `upgrade_record_create`; `docker compose stop orchestrator`; `db_snapshot` (fatal on failure, orchestrator left stopped); existing image/bundle load; `run_migrate up` → on failure `upgrade_record_set state failed`, print `Database migration failed. The orchestrator is stopped. To restore the pre-upgrade state run: sudo bash install.sh --rollback --upgrade-id <dir>`, exit non-zero; `upgrade_record_set state migrated`; start; health check → `healthy` or `failed` with the same guidance.
  - `--rollback`: `--upgrade-id <dir>` or `upgrade_record_latest`; refuse with a clear error if none exists (never fall back to a scheduled backup); print from/to and the warning `Database changes made after this upgrade began (<started_at>) will be lost.`; require typing the from-version unless `--yes`; stop orchestrator; `db_restore`; restore images/config as today; start; health check; `upgrade_record_set state rolled-back`.
  - `--rotate-db-app-password`: generate (`openssl rand -base64 32 | tr -d '/+='`), write `BAS_APP_DB_PASSWORD` in `${DATA_DIR}/.env`, `run_migrate rotate-app-password`, restart the orchestrator; on failure restore the previous `.env` value.
  - Usage/help text lists the new flag and `--upgrade-id`.
  `bash -n install.sh` and `shellcheck install.sh lib/upgrade-db.sh` (if available) clean.

- [ ] **Step 4: Commit:**

```bash
git add packaging/compose/lib/upgrade-db.sh packaging/compose/tests/upgrade_db_test.sh packaging/compose/install.sh packaging/compose/VERIFY.md
git commit -m "feat(packaging): upgrade record with encrypted DB snapshot; rollback restores it; migrate step (H1)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

- [ ] **Step 5: Staging QA handoff (user-run).** Record in the report the checklist for the user on staging: `--upgrade` from the current deployed release (pre-H1 → adoption; capture the summary line and any extras), `migrate status`, orchestrator healthy, `--rollback` restores the previous release and data, `--upgrade` again, `--rotate-db-app-password`. Credentials are entered by the user only.

---

### Task 10: Guardrails, rules, release notes

**Files:** Create `orchestrator/internal/db/migrations/{README.md,MANIFEST.sha256,manifest_test.go}`, `orchestrator/internal/db/seed/MANIFEST.sha256` (+ test), `scripts/h1-check-no-runtime-ddl.py`, `scripts/test_h1_check_no_runtime_ddl.py`, `docs/release-notes/h1-versioned-migrations.md`; modify `.github/workflows/test.yml`.

**Interfaces:**
- Produces: manifest format `<sha256>  <file>` per line, sorted; test fails when a listed file changed or is missing (new files must be appended to the manifest in the same commit; LF-normalized hashing as in Task 2).

- [ ] **Step 1: Failing tests.** `manifest_test.go` (migrations and seed): hash every listed file and compare; assert every `*.sql` in the FS is listed. Python test for the DDL check: a temp tree with `internal/api/x.go` containing `` `CREATE TABLE t (id int)` `` → reported; same text under `internal/db/legacy/` or `internal/db/migrate/` or `_test.go` → not reported; `ALTER ROLE`/`GRANT`/`DROP` likewise. Run → FAIL.

- [ ] **Step 2: Implement.** Generate both manifests from the current files. `scripts/h1-check-no-runtime-ddl.py`: scan `orchestrator/**/*.go` except `_test.go`, `internal/db/legacy/`, `internal/db/migrate/`, `tools/h1-capture-baseline/`; flag Go string literals matching `(?i)\b(CREATE|ALTER|DROP)\s+(TABLE|INDEX|UNIQUE INDEX|SEQUENCE|TYPE|FUNCTION|TRIGGER|EXTENSION|ROLE|SCHEMA|VIEW)\b|\bGRANT\b|\bREVOKE\b|\bTRUNCATE\b`; print file:line and exit 1. `migrations/README.md`: the development rules from spec §7 verbatim in substance (new numbered migration per change; immutable once shipped; corrective migrations; down where safe; destructive changes forward-compatible; production rollback = snapshot; data repairs = numbered data migrations; reference data in `seed/` with `SEED_VERSION` bump; customer data never seeded; append to MANIFEST.sha256). Release notes: adoption on first H1 upgrade, `install.sh --upgrade` now mandatory, rollback semantics and data-loss warning, new `--rotate-db-app-password`, the orchestrator refuses to start on a schema mismatch and what to run.

- [ ] **Step 3: CI.** In `.github/workflows/test.yml`'s Go job, add steps: `python3 scripts/h1-check-no-runtime-ddl.py` and `python3 -m unittest scripts.test_h1_check_no_runtime_ddl`. The manifest, freeze and baseline-equivalence tests run as part of `go test`.

- [ ] **Step 4: Run** all → PASS; `python3 scripts/h1-check-no-runtime-ddl.py` on the real tree → OK (if it flags real code, that code is boot-time DDL Task 8 missed — move it into a migration, never allowlist).

- [ ] **Step 5: Commit:**

```bash
git add orchestrator/internal/db/migrations/README.md orchestrator/internal/db/migrations/MANIFEST.sha256 orchestrator/internal/db/migrations/manifest_test.go orchestrator/internal/db/seed/MANIFEST.sha256 orchestrator/internal/db/seed/manifest_test.go scripts/h1-check-no-runtime-ddl.py scripts/test_h1_check_no_runtime_ddl.py docs/release-notes/h1-versioned-migrations.md .github/workflows/test.yml
git commit -m "ci(h1): migration/seed immutability manifests, no-runtime-DDL check, rules and release notes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

## Self-review

- **Spec coverage:** §4.1 commands → Task 8; §4.2 packages → Tasks 1–8; §4.3 classification/adoption/seed/role/output → Tasks 5, 6, 4, 7; §4.4 runtime + compose env → Task 8; §4.5 baseline capture + equivalence → Task 3; §5 install/upgrade/rollback/rotate/airgap → Task 9 (airgap unchanged by design: it calls `--upgrade`); §6 H1-T1…T10 → T1 Tasks 5/7, T2 Task 5, T3/T3b Task 6, T4/T5/T6 Task 5, T7 Task 8, T8 Task 7, T9 Task 4, T10 Task 9; §7 guardrails → Tasks 2 (freeze), 3 (equivalence), 10 (manifests, DDL check, README); §8 rollout → Task 10 release notes, Task 9 staging QA; §10 constraints → Global Constraints + P1.
- **Type consistency:** `legacy.DB`, `legacy.EnsureAll` (Tasks 2, 3, 6); `schemacheck.Take/Diff/Object/Querier` (1, 3, 6, 8); `migrations.FS/Latest` (3, 5, 8); `seed.Apply/Version/Current` (4, 5, 8); `migrate.Up/Options/Result/GetStatus/Status/CheckRuntime/RotateAppPassword/AppRole` and errors (5–8); shell functions (9).
