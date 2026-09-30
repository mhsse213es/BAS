# Runtime Role Separation (bas_user / bas_app) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the orchestrator a runtime PostgreSQL identity (`bas_app`,
`NOSUPERUSER`/`NOBYPASSRLS`, owns nothing) separate from the bootstrap/schema
role (`bas_user`), retiring the now-impossible `HardenRuntimeRole` demotion
approach.

**Architecture:** Two PostgreSQL connections at startup — a short-lived
bootstrap connection (`bas_user`, via a new `DATABASE_ADMIN_URL`) runs all
schema DDL and provisions `bas_app`, then closes; a long-lived runtime
connection (`bas_app`, via the existing `DATABASE_URL`, repointed) is what
every other line of the application uses from that point on. A startup
assertion fails closed if the runtime connection ever turns out to be
privileged.

**Tech Stack:** Go (`pgx`/`pgxpool`), PostgreSQL 16, bash (`install.sh`),
Docker Compose.

**Spec:** `docs/superpowers/specs/2026-09-30-runtime-role-separation-design.md`

## Global Constraints

- `bas_app`: `NOSUPERUSER NOBYPASSRLS`, owns nothing, granted only
  `SELECT, INSERT, UPDATE, DELETE` on tables + `USAGE, SELECT` on sequences —
  never `GRANT ALL`, never ownership, never DDL privilege.
- `bas_user` is unchanged: stays the bootstrap/superuser/schema-owner role.
- No RLS `ENABLE`/`FORCE` anywhere in this plan — out of scope per the spec's
  non-goals.
- `audit_logs`: `REVOKE UPDATE, DELETE FROM bas_app` (append-only enforced at
  the DB layer), applied after the blanket grant.
- `BAS_APP_DB_PASSWORD`: `openssl rand -hex 32`, auto-generated, preserved
  across upgrades (read from existing `.env` first), never operator-facing.
- `DATABASE_URL` → `bas_app` (runtime, the default/ordinary connection).
  `DATABASE_ADMIN_URL` → `bas_user` (bootstrap only, never held past
  startup).
- The runtime identity assertion fails closed (`log.Fatalf`) if `rolsuper`
  OR `rolbypassrls` is true — unconditional, not gated behind an opt-in flag.
- No worktree — this session works directly on `main`.
- TDD for all Go changes: RED (watch a real test fail for the right reason)
  → GREEN, real `go test` output verified, never assumed.
- Commit after each task; push after every commit.

## Review Focus

- **Sequence privilege gap** — `bigserial` columns (`audit_logs`,
  `agent_op_logs`, `agent_sec_logs`, `agent_telemetry`) need an explicit
  sequence grant beyond table-level DML, or every `INSERT` into them fails
  with `permission denied for sequence ..._id_seq` (verified empirically
  during design). Task 2 tests this directly.
- **Boot-order correctness against an already-populated database** —
  `bas_app` must be fully created and granted *before* the application ever
  opens its runtime connection as `bas_app`; getting this backwards makes
  every upgrade fail to authenticate on the very first boot after the
  change. Task 4's manual verification step exercises this against a
  pre-populated (bas_user-only) database, not just a fresh one.
- **Stray `BAS_DB_BREAKGLASS_PASSWORD` in an existing deployment's `.env`** —
  the config loader must not error just because that now-unused env var
  happens to still be set (or blank); simply no longer reading it is
  sufficient, but Task 1 verifies this explicitly rather than assuming it.
- **`EnsureExerciseSchema` ordering** — it previously ran *after* the old
  hardening call site, already inconsistent with `harden.go`'s own
  documented contract. If the admin-pool phase doesn't correctly absorb it
  alongside the other six `Ensure*Schema` calls, exercise-engine tables
  would be missing when `EnsureAppRole`'s blanket grant runs, leaving them
  silently un-granted for `bas_app`. Task 4 moves this call explicitly.
- **Hardcoding the bootstrap role's name in `ALTER DEFAULT PRIVILEGES`** —
  the spec's illustrative SQL says `FOR ROLE bas_user`, but the shared test
  harness bootstraps as `bas_test`, not `bas_user`. Task 2's implementation
  omits the `FOR ROLE` clause entirely (Postgres defaults to the current
  session's role), keeping the same code correct under both identities with
  nothing to keep in sync.

---

### Task 1: Retire HardenRuntimeRole and BAS_DB_BREAKGLASS_PASSWORD

**Files:**
- Delete: `orchestrator/internal/db/harden.go`
- Delete: `orchestrator/internal/db/harden_test.go`
- Modify: `orchestrator/config/config.go:63-67` (remove field + comment),
  `orchestrator/config/config.go:102-105` (update dangling comment
  reference), `orchestrator/config/config.go:204-206` (remove env wiring)
- Modify: `orchestrator/cmd/server/main.go:271-277` (remove call site +
  comment block)
- Modify: `orchestrator/internal/api/handlers.go:137-141` (update dangling
  comment reference)
- Modify: `packaging/compose/docker-compose.yml:139-143` (remove env
  wiring)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing new — this task only removes. Task 2 (config) and
  Task 4 (`main.go`) build on the *absence* of `DBBreakGlassPassword` and
  the old hardening call site this task leaves behind.

This is a deletion task, not new-behavior TDD — there is no failing test to
write first for code being removed. Instead, each step is verified by the
codebase compiling and the existing suite staying green with the deleted
symbols now genuinely gone (proving nothing else depended on them).

- [ ] **Step 1: Delete the harden.go and harden_test.go files**

```bash
rm orchestrator/internal/db/harden.go orchestrator/internal/db/harden_test.go
```

- [ ] **Step 2: Remove the DBBreakGlassPassword field from config.go**

In `orchestrator/config/config.go`, delete lines 63-67:

```go
	// DB role hardening (opt-in): when set, the orchestrator demotes its runtime
	// Postgres role to NOSUPERUSER/NOBYPASSRLS at startup (so RLS can enforce)
	// after creating a bas_breakglass recovery superuser with this password.
	// Unset = hardening inactive (default). Env: BAS_DB_BREAKGLASS_PASSWORD.
	DBBreakGlassPassword string `json:"db_breakglass_password,omitempty"`
```

Update the `RateLimitEnabled` block's comment immediately below (originally
lines 69-74) that references the just-removed field:

```go
	// API rate limiting (opt-in): a single global token-bucket limit protecting
	// against a runaway client, not a per-tenant/commercial quota system (that
	// belongs to the future Audspect Cloud offering, not this on-prem product).
	// Disabled by default so existing installs are never surprise-limited on
	// upgrade.
	// Env: API_RATE_LIMIT_ENABLED=true, API_RATE_LIMIT=1000/min, API_RATE_BURST=200.
```

Update the `MetricsToken` comment (originally lines 102-104):

```go
	// MetricsToken, when set, requires "Authorization: Bearer <token>" on
	// GET /metrics. Empty (the default) leaves it open -- same opt-in
	// posture as RateLimitEnabled.
	MetricsToken string `json:"metrics_token,omitempty"`
```

- [ ] **Step 3: Remove the BAS_DB_BREAKGLASS_PASSWORD env wiring in Load()**

In `orchestrator/config/config.go`, delete (originally lines 204-206):

```go
	if v := os.Getenv("BAS_DB_BREAKGLASS_PASSWORD"); v != "" {
		cfg.DBBreakGlassPassword = v
	}
```

- [ ] **Step 4: Remove the HardenRuntimeRole call site in main.go**

In `orchestrator/cmd/server/main.go`, delete (originally lines 271-277):

```go
	// ── DB role hardening (opt-in) ────────────────────────────────────────
	// Demote the runtime role to NOSUPERUSER/NOBYPASSRLS so RLS can enforce.
	// No-op unless BAS_DB_BREAKGLASS_PASSWORD is set. MUST run after all schema
	// DDL above — it drops this session's superuser privileges.
	if err := db.HardenRuntimeRole(context.Background(), pool, cfg.DBBreakGlassPassword); err != nil {
		log.Fatalf("[FATAL] db role hardening: %v", err)
	}

```

(Task 4 replaces this whole region of `main.go` again — this step just
gets the tree to a clean, compiling state first, independent of that
larger change.)

- [ ] **Step 5: Update the dangling comment in handlers.go**

In `orchestrator/internal/api/handlers.go`, change (originally lines
137-141):

```go
	// metricsToken, when non-empty, requires "Authorization: Bearer
	// <token>" on GET /metrics. Empty (the default) leaves it open --
	// same opt-in-by-default-off posture as BAS_DB_BREAKGLASS_PASSWORD
	// and API rate limiting.
	metricsToken string
```

to:

```go
	// metricsToken, when non-empty, requires "Authorization: Bearer
	// <token>" on GET /metrics. Empty (the default) leaves it open --
	// same opt-in-by-default-off posture as API rate limiting.
	metricsToken string
```

- [ ] **Step 6: Remove the env wiring from docker-compose.yml**

In `packaging/compose/docker-compose.yml`, delete (originally lines
139-143):

```yaml
      # DB role hardening (opt-in): set to a strong password to demote the
      # orchestrator's Postgres role to NOSUPERUSER/NOBYPASSRLS at startup and
      # create a `bas_breakglass` recovery superuser with this password. Blank =
      # inactive (role unchanged).
      BAS_DB_BREAKGLASS_PASSWORD: ${BAS_DB_BREAKGLASS_PASSWORD:-}
```

- [ ] **Step 7: Verify the tree builds and the affected packages' tests still pass**

```bash
cd orchestrator
go build ./...
go vet ./...
go test ./config/... ./internal/api/... ./internal/db/... ./cmd/server/... -run . -v 2>&1 | tail -60
```

Expected: `go build`/`go vet` succeed with no errors (confirms nothing else
referenced `HardenRuntimeRole`, `DBBreakGlassPassword`, or
`breakGlassRole`/`bas_breakglass`); the test packages run and show no
failures caused by this removal. `TestRBACMatrix_NoDrift` (ca-root route)
may still show its pre-existing, unrelated failure — that's expected and
not this task's concern.

Also confirm, explicitly (Review Focus item):

```bash
BAS_DB_BREAKGLASS_PASSWORD=leftover-from-an-old-install go run ./cmd/server --help 2>&1 | head -5
```

Expected: the process does not fail specifically because of this env var
being set (it's simply never read anymore) — any failure here should be
the ordinary "missing required config" kind (no `DATABASE_URL`/`JWT_SECRET`
in this bare invocation), not anything mentioning break-glass or hardening.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/config/config.go orchestrator/cmd/server/main.go \
  orchestrator/internal/api/handlers.go packaging/compose/docker-compose.yml
git rm orchestrator/internal/db/harden.go orchestrator/internal/db/harden_test.go
git commit -m "fix(db): retire HardenRuntimeRole and BAS_DB_BREAKGLASS_PASSWORD

Demoting bas_user is impossible -- it's the Postgres bootstrap role, and
PostgreSQL 16 refuses to remove SUPERUSER from it under any circumstances
(verified empirically). Superseded by the bas_app runtime role introduced
in the following tasks, which is born NOSUPERUSER/NOBYPASSRLS instead of
needing runtime demotion."
git push
```

---

### Task 2: Config — DatabaseAdminURL and AppDBPassword fields

**Files:**
- Modify: `orchestrator/config/config.go`
- Test: `orchestrator/config/config_test.go`

**Interfaces:**
- Produces: `Config.DatabaseAdminURL string` (env `DATABASE_ADMIN_URL`,
  required at `Load()`), `Config.AppDBPassword string` (env
  `BAS_APP_DB_PASSWORD`, required at `Load()`) — Task 4 reads both.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/config/config_test.go` (match the file's existing
`os.Setenv`/`Load("/nonexistent/config.json")` convention — see e.g.
`TestLoad_LegacyListenerEnabledDefaultsTrue`):

```go
func TestLoad_DatabaseAdminURLRequired(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://bas_app:pw@localhost/bas_platform")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")

	_, err := Load("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected an error when DATABASE_ADMIN_URL is unset, got nil")
	}
}

func TestLoad_DatabaseAdminURLFromEnv(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://bas_app:pw@localhost/bas_platform")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://bas_user:pw@localhost/bas_platform")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("BAS_APP_DB_PASSWORD", "test-app-password")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DatabaseAdminURL != "postgres://bas_user:pw@localhost/bas_platform" {
		t.Errorf("DatabaseAdminURL = %q, want the env value", cfg.DatabaseAdminURL)
	}
}

func TestLoad_AppDBPasswordRequired(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://bas_app:pw@localhost/bas_platform")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://bas_user:pw@localhost/bas_platform")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Unsetenv("BAS_APP_DB_PASSWORD")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("JWT_SECRET")

	_, err := Load("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected an error when BAS_APP_DB_PASSWORD is unset, got nil")
	}
}

func TestLoad_AppDBPasswordFromEnv(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://bas_app:pw@localhost/bas_platform")
	os.Setenv("DATABASE_ADMIN_URL", "postgres://bas_user:pw@localhost/bas_platform")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("BAS_APP_DB_PASSWORD", "rotated-password")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("DATABASE_ADMIN_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("BAS_APP_DB_PASSWORD")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AppDBPassword != "rotated-password" {
		t.Errorf("AppDBPassword = %q, want the env value", cfg.AppDBPassword)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd orchestrator
go test ./config/... -run TestLoad_DatabaseAdminURL -v
go test ./config/... -run TestLoad_AppDBPassword -v
```

Expected: compile errors (`cfg.DatabaseAdminURL undefined`,
`cfg.AppDBPassword undefined`) or, once the fields are stubbed without the
required-check, a straightforward assertion failure. Confirm you see a
real failure for the right reason before continuing.

- [ ] **Step 3: Add the fields, env wiring, and required checks**

In `orchestrator/config/config.go`, add the new field next to the existing
`DatabaseURL` (line 12):

```go
type Config struct {
	DatabaseURL       string `json:"database_url"`
	// DatabaseAdminURL is the bootstrap/schema-owner connection (bas_user) --
	// used only at startup to run schema DDL and provision bas_app, then
	// closed. Never held by the application past startup. See
	// docs/superpowers/specs/2026-09-30-runtime-role-separation-design.md.
	DatabaseAdminURL  string `json:"database_admin_url"`
	// AppDBPassword is bas_app's password (auto-generated by install.sh,
	// never operator-facing). Env: BAS_APP_DB_PASSWORD.
	AppDBPassword     string `json:"-"`
	JWTSecret         string `json:"jwt_secret"`
```

In `Load()`, add env wiring next to the existing `DATABASE_URL` wiring
(originally lines 201-203):

```go
	if v := os.Getenv("DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}
	if v := os.Getenv("DATABASE_ADMIN_URL"); v != "" {
		cfg.DatabaseAdminURL = v
	}
	if v := os.Getenv("BAS_APP_DB_PASSWORD"); v != "" {
		cfg.AppDBPassword = v
	}
```

Add the required-at-`Load()` checks next to the existing `DatabaseURL`
check (originally lines 365-367):

```go
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("database_url required (set DATABASE_URL env var or config file)")
	}
	if cfg.DatabaseAdminURL == "" {
		return nil, fmt.Errorf("database_admin_url required (set DATABASE_ADMIN_URL env var or config file)")
	}
	if cfg.AppDBPassword == "" {
		return nil, fmt.Errorf("bas_app db password required (set BAS_APP_DB_PASSWORD env var)")
	}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd orchestrator
go test ./config/... -run TestLoad_DatabaseAdminURL -v
go test ./config/... -run TestLoad_AppDBPassword -v
go test ./config/... -v 2>&1 | tail -40
```

Expected: all four new tests PASS, and the full `config` package suite
stays green (no existing test broke by adding two new required fields —
if any pre-existing test calls `Load()` without setting these env vars, it
will need the same three `os.Setenv` additions as the tests above; check
for that now, not later).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/config/config.go orchestrator/config/config_test.go
git commit -m "feat(db): add DatabaseAdminURL and AppDBPassword config fields

Prerequisite for the bas_user/bas_app runtime role split -- the bootstrap
(bas_user) and runtime (bas_app) connections need separate DSNs, and
bas_app needs its own auto-generated password threaded through to the
provisioning step."
git push
```

---

### Task 3: EnsureAppRole — bas_app provisioning function

**Files:**
- Create: `orchestrator/internal/db/app_role.go`
- Test: `orchestrator/internal/db/app_role_test.go`

**Interfaces:**
- Consumes: `internal/testutil`'s `sharedDB`/`mustExec` package-test
  conventions (already defined in `internal/db/tenant_test.go`, same test
  binary/package — no new import needed since `app_role_test.go` lives in
  the same `db_test` package).
- Produces: `func EnsureAppRole(ctx context.Context, pool *pgxpool.Pool, appPassword string) error` — Task 4's `main.go` calls this.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/db/app_role_test.go`:

```go
package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

const testAppPassword = "app-pw-testing-only"

// appConnectedPool returns a pool connected as bas_app. Callers must have
// already called db.EnsureAppRole(ctx, admin, testAppPassword) first.
func appConnectedPool(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	cfg := admin.Config().Copy()
	cfg.ConnConfig.User = "bas_app"
	cfg.ConnConfig.Password = testAppPassword
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("bas_app pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestEnsureAppRole_CreatesNonSuperuserNoBypassRLS(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := db.EnsureAppRole(context.Background(), pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		var rolsuper, rolbypassrls bool
		if err := pool.QueryRow(context.Background(),
			`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'bas_app'`,
		).Scan(&rolsuper, &rolbypassrls); err != nil {
			t.Fatalf("read bas_app attrs: %v", err)
		}
		if rolsuper || rolbypassrls {
			t.Fatalf("bas_app should be NOSUPERUSER/NOBYPASSRLS, got super=%v bypassrls=%v", rolsuper, rolbypassrls)
		}
	})
}

func TestEnsureAppRole_IdempotentOnRetry(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("first EnsureAppRole: %v", err)
		}
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("second EnsureAppRole (idempotent) errored: %v", err)
		}
	})
}

func TestEnsureAppRole_PasswordSyncsOnRepeatedCalls(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, "first-password"); err != nil {
			t.Fatalf("first EnsureAppRole: %v", err)
		}
		if err := db.EnsureAppRole(ctx, pool, "second-password"); err != nil {
			t.Fatalf("second EnsureAppRole: %v", err)
		}

		cfg := pool.Config().Copy()
		cfg.ConnConfig.User = "bas_app"
		cfg.ConnConfig.Password = "second-password"
		p, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("connect with rotated password: %v", err)
		}
		defer p.Close()
		if err := p.Ping(ctx); err != nil {
			t.Fatalf("ping with rotated password: %v", err)
		}
	})
}

func TestEnsureAppRole_OwnsNoTables(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := db.EnsureAppRole(context.Background(), pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM pg_tables WHERE tableowner = 'bas_app'`,
		).Scan(&count); err != nil {
			t.Fatalf("count owned tables: %v", err)
		}
		if count != 0 {
			t.Fatalf("bas_app should own zero tables, owns %d", count)
		}
	})
}

func TestEnsureAppRole_GrantsDMLOnExistingTable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		app := appConnectedPool(t, pool)

		if _, err := app.Exec(ctx,
			`INSERT INTO tenants (id, name, slug, status) VALUES ('dml-test','DML Test','dml-test','active')
			 ON CONFLICT (id) DO NOTHING`); err != nil {
			t.Fatalf("bas_app INSERT on tenants: %v", err)
		}
		var name string
		if err := app.QueryRow(ctx, `SELECT name FROM tenants WHERE id = 'dml-test'`).Scan(&name); err != nil {
			t.Fatalf("bas_app SELECT on tenants: %v", err)
		}
		if _, err := app.Exec(ctx, `UPDATE tenants SET name = 'Updated' WHERE id = 'dml-test'`); err != nil {
			t.Fatalf("bas_app UPDATE on tenants: %v", err)
		}
		if _, err := app.Exec(ctx, `DELETE FROM tenants WHERE id = 'dml-test'`); err != nil {
			t.Fatalf("bas_app DELETE on tenants: %v", err)
		}
	})
}

func TestEnsureAppRole_GrantsSequenceUsage(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		app := appConnectedPool(t, pool)

		// agent_op_logs.id is bigserial -- table-level INSERT alone does not
		// grant use of the backing sequence (verified empirically during
		// design). This proves the separate sequence grant actually works.
		if _, err := app.Exec(ctx,
			`INSERT INTO agent_op_logs (agent_id, message) VALUES ('seq-test-agent', 'hello')`); err != nil {
			t.Fatalf("bas_app INSERT into bigserial-keyed table: %v", err)
		}
	})
}

func TestEnsureAppRole_AuditLogsUpdateDeleteRevoked(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		app := appConnectedPool(t, pool)

		if _, err := app.Exec(ctx,
			`INSERT INTO audit_logs (action, resource) VALUES ('test.action', 'test.resource')`); err != nil {
			t.Fatalf("bas_app INSERT on audit_logs should succeed: %v", err)
		}
		if _, err := app.Exec(ctx, `UPDATE audit_logs SET action = 'changed' WHERE action = 'test.action'`); err == nil {
			t.Fatal("bas_app UPDATE on audit_logs should be rejected, succeeded instead")
		}
		if _, err := app.Exec(ctx, `DELETE FROM audit_logs WHERE action = 'test.action'`); err == nil {
			t.Fatal("bas_app DELETE on audit_logs should be rejected, succeeded instead")
		}
	})
}

func TestEnsureAppRole_DefaultPrivilegesCoverFutureTables(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}

		// A table created by the admin role AFTER EnsureAppRole already ran --
		// proves ALTER DEFAULT PRIVILEGES, not just the one-time blanket
		// GRANT, is what covers it.
		if _, err := pool.Exec(ctx,
			`CREATE TABLE IF NOT EXISTS future_table_test (id text PRIMARY KEY, val text)`); err != nil {
			t.Fatalf("create future_table_test: %v", err)
		}

		app := appConnectedPool(t, pool)
		if _, err := app.Exec(ctx,
			`INSERT INTO future_table_test (id, val) VALUES ('x','y')`); err != nil {
			t.Fatalf("bas_app INSERT into a table created after EnsureAppRole: %v", err)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd orchestrator
go test ./internal/db/... -run TestEnsureAppRole -v
```

Expected: `FAIL` with `undefined: db.EnsureAppRole` (a compile error across
every new test in the file, since none of them can build yet).

- [ ] **Step 3: Implement EnsureAppRole**

Create `orchestrator/internal/db/app_role.go`:

```go
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// appRole is the orchestrator's runtime PostgreSQL identity -- created
// NOSUPERUSER/NOBYPASSRLS and granted no ownership, so RLS enforcement
// (activated in a later phase, not this one) can actually apply to it. See
// docs/superpowers/specs/2026-09-30-runtime-role-separation-design.md.
const appRole = "bas_app"

// EnsureAppRole provisions the bas_app runtime role: creates it if absent
// (idempotent), syncs its password every call (so a rotated
// BAS_APP_DB_PASSWORD takes effect on the next restart), and grants it
// exactly the DML privileges normal application traffic needs -- never
// ownership, never DDL. Must be called from the bootstrap connection (a
// superuser/schema-owner role, e.g. bas_user), after every Ensure*Schema
// call has created every table bas_app needs granted.
func EnsureAppRole(ctx context.Context, pool *pgxpool.Pool, appPassword string) error {
	if appPassword == "" {
		return fmt.Errorf("EnsureAppRole: appPassword must not be empty")
	}

	if _, err := pool.Exec(ctx, `DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '`+appRole+`') THEN
				CREATE ROLE `+appRole+` LOGIN NOSUPERUSER NOBYPASSRLS;
			END IF;
		END $$`); err != nil {
		return fmt.Errorf("create bas_app role: %w", err)
	}

	// Password kept in sync every boot -- format(%I, %L) escapes
	// server-side, since CREATE/ALTER ROLE take no bind parameters
	// (same pattern the retired harden.go used for bas_breakglass).
	var alterStmt string
	if err := pool.QueryRow(ctx,
		`SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text)`,
		appRole, appPassword).Scan(&alterStmt); err != nil {
		return fmt.Errorf("build bas_app password stmt: %w", err)
	}
	if _, err := pool.Exec(ctx, alterStmt); err != nil {
		return fmt.Errorf("set bas_app password: %w", err)
	}

	// GRANT CONNECT needs a literal database name -- current_database()
	// keeps this correct under both bas_platform (production) and the test
	// harness's bas_test, without hardcoding either.
	var grantConnectStmt string
	if err := pool.QueryRow(ctx,
		`SELECT format('GRANT CONNECT ON DATABASE %I TO `+appRole+`', current_database())`,
	).Scan(&grantConnectStmt); err != nil {
		return fmt.Errorf("build grant connect stmt: %w", err)
	}
	if _, err := pool.Exec(ctx, grantConnectStmt); err != nil {
		return fmt.Errorf("grant connect: %w", err)
	}

	grants := []string{
		`GRANT USAGE ON SCHEMA public TO ` + appRole,

		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + appRole,
		// No "FOR ROLE bas_user" clause: omitted, ALTER DEFAULT PRIVILEGES
		// defaults to the CURRENT session's role, which keeps this correct
		// whether the bootstrap connection is bas_user (production) or
		// bas_test (this package's own test harness) -- no literal role
		// name to keep in sync between the two.
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public
			GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ` + appRole,

		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ` + appRole,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public
			GRANT USAGE, SELECT ON SEQUENCES TO ` + appRole,

		// audit_logs is documented as "immutable, append-only" (postgres.go)
		// -- carve out UPDATE/DELETE at the DB layer for defense-in-depth,
		// not just app-code discipline. Must run AFTER the blanket grant
		// above (a REVOKE before the matching GRANT would have nothing to
		// narrow).
		`REVOKE UPDATE, DELETE ON audit_logs FROM ` + appRole,
	}
	for _, stmt := range grants {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("grant provisioning (%q): %w", stmt, err)
		}
	}

	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd orchestrator
go test ./internal/db/... -run TestEnsureAppRole -v
```

Expected: all eight tests PASS. Watch the actual output, not just the exit
code — `TestEnsureAppRole_AuditLogsUpdateDeleteRevoked` and
`TestEnsureAppRole_GrantsSequenceUsage` are the two most likely to reveal a
real mistake (wrong grant, wrong ordering) rather than a typo.

- [ ] **Step 5: Run the full internal/db package suite**

```bash
cd orchestrator
go test ./internal/db/... -v 2>&1 | tail -80
```

Expected: no regressions in the rest of the package (in particular
`tenant_test.go`'s RLS-mechanism tests, which share the same container).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/db/app_role.go orchestrator/internal/db/app_role_test.go
git commit -m "feat(db): add EnsureAppRole to provision the bas_app runtime role

Idempotent CREATE ROLE + password sync + scoped GRANTs (no ownership, no
GRANT ALL, no DDL). Includes the two easy-to-miss cases verified during
design: a bigserial column's sequence needs its own separate grant beyond
table-level INSERT, and audit_logs' append-only invariant is now enforced
at the DB layer via a REVOKE UPDATE, DELETE carve-out."
git push
```

---

### Task 4: main.go — two-pool startup sequence

**Files:**
- Create: `orchestrator/cmd/server/runtime_identity.go`
- Test: `orchestrator/cmd/server/runtime_identity_test.go`
- Modify: `orchestrator/cmd/server/main.go:241-277` (database setup +
  removed hardening region), `orchestrator/cmd/server/main.go:543-547`
  (exercise engine region)

**Interfaces:**
- Consumes: `config.Config.DatabaseAdminURL`, `config.Config.AppDBPassword`
  (Task 2); `db.EnsureAppRole` (Task 3).
- Produces: `func assertRuntimeIdentity(ctx context.Context, pool *pgxpool.Pool) error` — used only by `main()` in this plan, but kept
  as its own small testable function rather than inlined, matching this
  file's existing `legacyListenerShouldStart`/`checkCANotSilentlyRotated`
  convention of factoring startup checks out for direct testing.

- [ ] **Step 1: Write the failing tests for assertRuntimeIdentity**

Create `orchestrator/cmd/server/runtime_identity_test.go`:

```go
package main

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

func TestAssertRuntimeIdentity_FailsForSuperuser(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	if err := assertRuntimeIdentity(context.Background(), tdb.Pool); err == nil {
		t.Fatal("expected an error for a superuser connection, got nil")
	}
}

func TestAssertRuntimeIdentity_PassesForNonPrivilegedRole(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	if _, err := tdb.Pool.Exec(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'identity_probe_ok') THEN
			CREATE ROLE identity_probe_ok LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'x';
		END IF;
	END $$`); err != nil {
		t.Fatalf("create identity_probe_ok: %v", err)
	}
	t.Cleanup(func() { _, _ = tdb.Pool.Exec(ctx, `DROP ROLE IF EXISTS identity_probe_ok`) })

	cfg := tdb.Pool.Config().Copy()
	cfg.ConnConfig.User = "identity_probe_ok"
	cfg.ConnConfig.Password = "x"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect as identity_probe_ok: %v", err)
	}
	defer p.Close()

	if err := assertRuntimeIdentity(ctx, p); err != nil {
		t.Fatalf("expected nil for a non-privileged role, got: %v", err)
	}
}

func TestAssertRuntimeIdentity_FailsForBypassRLSRole(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	if _, err := tdb.Pool.Exec(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'identity_probe_bypass') THEN
			CREATE ROLE identity_probe_bypass LOGIN NOSUPERUSER BYPASSRLS PASSWORD 'x';
		END IF;
	END $$`); err != nil {
		t.Fatalf("create identity_probe_bypass: %v", err)
	}
	t.Cleanup(func() { _, _ = tdb.Pool.Exec(ctx, `DROP ROLE IF EXISTS identity_probe_bypass`) })

	cfg := tdb.Pool.Config().Copy()
	cfg.ConnConfig.User = "identity_probe_bypass"
	cfg.ConnConfig.Password = "x"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect as identity_probe_bypass: %v", err)
	}
	defer p.Close()

	if err := assertRuntimeIdentity(ctx, p); err == nil {
		t.Fatal("expected an error for a BYPASSRLS role, got nil")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd orchestrator
go test ./cmd/server/... -run TestAssertRuntimeIdentity -v
```

Expected: `FAIL` with `undefined: assertRuntimeIdentity`.

- [ ] **Step 3: Implement assertRuntimeIdentity**

Create `orchestrator/cmd/server/runtime_identity.go`:

```go
package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// assertRuntimeIdentity fails loudly if the runtime DB connection turns out
// to be privileged -- a future deployment/configuration mistake pointing
// DATABASE_URL back at a superuser or BYPASSRLS role must never pass
// silently, since RLS enforcement (a later phase) depends on this being
// false. See docs/superpowers/specs/2026-09-30-runtime-role-separation-design.md.
func assertRuntimeIdentity(ctx context.Context, pool *pgxpool.Pool) error {
	var rolsuper, rolbypassrls bool
	if err := pool.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&rolsuper, &rolbypassrls); err != nil {
		return fmt.Errorf("query current_user attributes: %w", err)
	}
	if rolsuper || rolbypassrls {
		return fmt.Errorf("runtime DB connection is privileged (rolsuper=%v rolbypassrls=%v) -- refusing to start on a bypassing identity", rolsuper, rolbypassrls)
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd orchestrator
go test ./cmd/server/... -run TestAssertRuntimeIdentity -v
```

Expected: all three PASS.

- [ ] **Step 5: Restructure main.go's database startup sequence**

By this point (after Task 1's removal), `main.go` has one contiguous block
running from the `// ── Database ──` comment through the `log.Println("[+]
Schema verified")` line, directly followed by the `// ── Seed ART content`
comment (Task 1 left no gap between them). In
`orchestrator/cmd/server/main.go`, replace that whole block — comment
through `Schema verified` — with:

```go
	// ── Database: bootstrap connection (bas_user) ───────────────────────────
	// Schema DDL and bas_app provisioning run here, as the privileged
	// bootstrap/schema-owner role. Closed once that work is done -- the
	// application never holds this connection past startup. See
	// docs/superpowers/specs/2026-09-30-runtime-role-separation-design.md.
	adminCtx, adminCancel := context.WithTimeout(context.Background(), 30*time.Second)
	adminPool, err := db.Connect(adminCtx, cfg.DatabaseAdminURL)
	adminCancel()
	if err != nil {
		log.Fatalf("[FATAL] db admin connect: %v", err)
	}
	log.Println("[+] PostgreSQL (admin) connected")

	if err := db.EnsureSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] schema bootstrap: %v", err)
	}
	if err := db.EnsureContentSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] content schema bootstrap: %v", err)
	}
	if err := db.EnsureIOCSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] ioc schema bootstrap: %v", err)
	}
	if err := db.EnsureIOCEnrichmentSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] ioc enrichment schema bootstrap: %v", err)
	}
	if err := db.EnsureAgentGroupSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] agent group schema bootstrap: %v", err)
	}
	if err := db.EnsureAgentUninstallSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] agent uninstall schema bootstrap: %v", err)
	}
	if err := db.EnsureExerciseSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] exercise schema: %v", err)
	}
	log.Println("[+] Schema verified")

	// ── bas_app provisioning ─────────────────────────────────────────────
	// Idempotent every boot: creates bas_app if absent, syncs its password
	// from BAS_APP_DB_PASSWORD, and grants exactly the runtime DML it needs.
	// Must run after every schema call above, against every table those
	// calls just created.
	if err := db.EnsureAppRole(context.Background(), adminPool, cfg.AppDBPassword); err != nil {
		log.Fatalf("[FATAL] bas_app provisioning: %v", err)
	}
	adminPool.Close()
	log.Println("[+] bas_app provisioned")

	// ── Database: runtime connection (bas_app) ───────────────────────────
	// Every application code path from here on uses this pool -- the
	// bootstrap connection above is already closed.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	cancel()
	if err != nil {
		log.Fatalf("[FATAL] db connect: %v", err)
	}
	defer pool.Close()
	log.Println("[+] PostgreSQL (runtime) connected")

	if err := assertRuntimeIdentity(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] runtime identity check: %v", err)
	}

```

(This replaces both the old single-connection setup AND the six
`Ensure*Schema` calls AND the deleted-in-Task-1 hardening block in one
contiguous edit — they were already contiguous in the original file.)

- [ ] **Step 6: Remove the now-duplicate EnsureExerciseSchema call**

In `orchestrator/cmd/server/main.go`, change (originally lines 543-547):

```go
	// ── Exercise Engine ───────────────────────────────────────────────────
	if err := db.EnsureExerciseSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] exercise schema: %v", err)
	}
	exStore := exercise.NewStore(pool)
```

to:

```go
	// ── Exercise Engine ───────────────────────────────────────────────────
	// Schema already ensured earlier, against the bootstrap connection.
	exStore := exercise.NewStore(pool)
```

- [ ] **Step 7: Build and run the affected test suites**

```bash
cd orchestrator
go build ./...
go vet ./...
go test ./cmd/server/... -v 2>&1 | tail -60
```

Expected: clean build, clean vet, and every `cmd/server` test (the three
new `TestAssertRuntimeIdentity_*` tests plus the pre-existing
`TestLegacyListenerShouldStart_*`) passes.

- [ ] **Step 8: Manual end-to-end boot verification (fresh install)**

This is the highest-risk task in the plan — the only way to genuinely
prove the two-pool sequencing is correct end to end is to actually boot
the binary against a real, freshly-created database where `bas_app` does
not exist yet, matching a real first install:

```bash
docker rm -f role-sep-boot-check >/dev/null 2>&1
docker run -d --name role-sep-boot-check -e POSTGRES_USER=bas_user \
  -e POSTGRES_PASSWORD=boottest123 -e POSTGRES_DB=bas_platform \
  -p 55496:5432 postgres:16-alpine
sleep 4

cd orchestrator
DATABASE_ADMIN_URL="postgres://bas_user:boottest123@localhost:55496/bas_platform?sslmode=disable" \
DATABASE_URL_PLACEHOLDER_NOTE="DATABASE_URL is set by the app's own bas_app provisioning step below -- \
  on a first run bas_app does not exist yet, so this env var must already point at the \
  password the app is about to create bas_app WITH" \
DATABASE_URL="postgres://bas_app:apptest123@localhost:55496/bas_platform?sslmode=disable" \
BAS_APP_DB_PASSWORD="apptest123" \
JWT_SECRET="boot-check-jwt-secret" \
timeout 30 go run ./cmd/server 2>&1 | head -40

docker rm -f role-sep-boot-check >/dev/null 2>&1
```

Expected in the output, in order: `PostgreSQL (admin) connected`,
`Schema verified`, `bas_app provisioned`,
`PostgreSQL (runtime) connected`, and no `[FATAL]` line mentioning
`runtime identity check`, `db admin connect`, `db connect`, `schema
bootstrap`, or `bas_app provisioning`. (The process will likely keep
running past other unrelated startup steps — like ART content seeding
needing files this throwaway container doesn't have — that's fine and
expected; `timeout 30` and the log prefix check above are what matter for
this step. Kill it and move on once the four expected log lines are
confirmed.)

- [ ] **Step 9: Manual end-to-end boot verification (pre-populated database)**

Repeat Step 8's boot, but this time seed the database as `bas_user`-only
first (simulating an existing deployment upgrading, where `bas_app`
doesn't exist yet but real schema/data already does) — confirms the
upgrade path, not just a fresh install:

```bash
docker rm -f role-sep-upgrade-check >/dev/null 2>&1
docker run -d --name role-sep-upgrade-check -e POSTGRES_USER=bas_user \
  -e POSTGRES_PASSWORD=upgradetest123 -e POSTGRES_DB=bas_platform \
  -p 55495:5432 postgres:16-alpine
sleep 4
docker exec role-sep-upgrade-check psql -U bas_user -d bas_platform -c \
  "CREATE TABLE tenants (id text PRIMARY KEY);"  # minimal pre-existing state

cd orchestrator
DATABASE_ADMIN_URL="postgres://bas_user:upgradetest123@localhost:55495/bas_platform?sslmode=disable" \
DATABASE_URL="postgres://bas_app:apptest123@localhost:55495/bas_platform?sslmode=disable" \
BAS_APP_DB_PASSWORD="apptest123" \
JWT_SECRET="upgrade-check-jwt-secret" \
timeout 30 go run ./cmd/server 2>&1 | head -40

docker rm -f role-sep-upgrade-check >/dev/null 2>&1
```

Expected: the same four log lines as Step 8, with no error about the
pre-existing `tenants` table conflicting with `EnsureSchema`'s own
`CREATE TABLE IF NOT EXISTS tenants (...)` (idempotent by design — the
minimal one-column version created above is intentionally incompatible
with the real schema's columns, so if `EnsureSchema` errors here on
something other than a clean idempotent skip, investigate before
proceeding — though the expected/normal case is that `ADD COLUMN IF NOT
EXISTS` statements later in `EnsureSchema` simply add the missing columns
to the existing table).

- [ ] **Step 10: Commit**

```bash
git add orchestrator/cmd/server/main.go orchestrator/cmd/server/runtime_identity.go \
  orchestrator/cmd/server/runtime_identity_test.go
git commit -m "feat(db): split orchestrator startup into bootstrap/runtime DB connections

Bootstrap connection (bas_user, DATABASE_ADMIN_URL) runs schema DDL and
provisions bas_app, then closes. Runtime connection (bas_app,
DATABASE_URL) is what the rest of the application uses from that point
on, gated by a fail-closed startup assertion against pg_roles. Also fixes
EnsureExerciseSchema's ordering -- it previously ran after the
(now-removed) hardening call site, already inconsistent with that
mechanism's own documented contract."
git push
```

---

### Task 5: Deployment wiring — docker-compose.yml and install.sh

**Files:**
- Modify: `packaging/compose/docker-compose.yml`
- Modify: `packaging/compose/install.sh` (`load_config()` and
  `_write_env()` functions)

**Interfaces:**
- Consumes: nothing from earlier tasks directly (this is deployment
  config, not Go code) — but must match the env var names Task 2's
  `config.go` reads (`DATABASE_URL`, `DATABASE_ADMIN_URL`,
  `BAS_APP_DB_PASSWORD`) exactly.
- Produces: nothing consumed elsewhere in this plan — this is the final
  task.

No `go test` cycle applies to bash/YAML; verification here is syntax
checking plus rendering the compose file with representative values and
inspecting the result.

- [ ] **Step 1: Split DATABASE_URL in docker-compose.yml**

By this point (after Task 1, Step 6 already removed the
`BAS_DB_BREAKGLASS_PASSWORD` line), `packaging/compose/docker-compose.yml`
has:

```yaml
    environment:
      # sslmode=prefer encrypts when Postgres offers TLS (default in official image).
      # Production deployments with a certificate chain should use sslmode=require
      # or sslmode=verify-full with PGSSLROOTCERT set.
      DATABASE_URL:     "postgres://${POSTGRES_USER:-bas_user}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-bas_platform}?sslmode=prefer"
      JWT_SECRET:       ${JWT_SECRET}
      AGENT_SECRET:     ${AGENT_SECRET:-}
```

Change it to:

```yaml
    environment:
      # sslmode=prefer encrypts when Postgres offers TLS (default in official image).
      # Production deployments with a certificate chain should use sslmode=require
      # or sslmode=verify-full with PGSSLROOTCERT set.
      #
      # DATABASE_URL is the orchestrator's normal runtime connection -- bas_app,
      # NOSUPERUSER/NOBYPASSRLS, owns nothing. DATABASE_ADMIN_URL is used only
      # during startup schema bootstrap/bas_app provisioning, then closed. See
      # docs/superpowers/specs/2026-09-30-runtime-role-separation-design.md.
      DATABASE_URL:       "postgres://bas_app:${BAS_APP_DB_PASSWORD}@postgres:5432/${POSTGRES_DB:-bas_platform}?sslmode=prefer"
      DATABASE_ADMIN_URL: "postgres://${POSTGRES_USER:-bas_user}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-bas_platform}?sslmode=prefer"
      JWT_SECRET:       ${JWT_SECRET}
      AGENT_SECRET:     ${AGENT_SECRET:-}
```

- [ ] **Step 2: Add BAS_APP_DB_PASSWORD generation to install.sh**

In `packaging/compose/install.sh`, add a new global var declaration next
to the existing ones (originally lines 158-159):

```bash
JWT_SECRET=""
AGENT_SECRET=""
BAS_APP_DB_PASSWORD=""
```

In the `load_config()` function, immediately after the existing
`JWT_SECRET`/`AGENT_SECRET` priority-order block (originally lines
296-303, shown below as context — do not duplicate these two lines, only
add the new block that follows them):

```bash
  [[ -z "$JWT_SECRET"   ]] && JWT_SECRET=$(openssl rand -hex 32)
  [[ -z "$AGENT_SECRET" ]] && AGENT_SECRET=$(openssl rand -hex 24)

  # bas_app runtime DB password -- same priority order as JWT_SECRET/
  # AGENT_SECRET above (existing .env, then generate). Never operator-
  # configurable: unlike DB_PASSWORD (the bas_user admin credential), this
  # is a purely internal orchestrator<->Postgres secret, so there is no
  # setup.conf key or CLI flag for it -- only auto-generation and .env
  # persistence.
  if [[ -z "$BAS_APP_DB_PASSWORD" && -f "$existing_env" ]]; then
    BAS_APP_DB_PASSWORD=$(grep -oP '(?<=^BAS_APP_DB_PASSWORD=).+' "$existing_env" 2>/dev/null || true)
  fi
  [[ -z "$BAS_APP_DB_PASSWORD" ]] && BAS_APP_DB_PASSWORD=$(openssl rand -hex 32)
```

(The first two lines above are the pre-existing `JWT_SECRET`/
`AGENT_SECRET` lines shown for placement context — only the
`BAS_APP_DB_PASSWORD` block after them is new.)

In `_write_env()`, add the new value to the generated `.env` (originally
lines 1204-1205):

```
JWT_SECRET=${JWT_SECRET}
AGENT_SECRET=${AGENT_SECRET}
BAS_APP_DB_PASSWORD=${BAS_APP_DB_PASSWORD}
```

- [ ] **Step 3: Syntax-check install.sh**

```bash
bash -n packaging/compose/install.sh
```

Expected: no output, exit code 0 (a bash syntax error would print a
`syntax error near ...` line and exit non-zero).

- [ ] **Step 4: Validate the rendered docker-compose.yml**

```bash
cd packaging/compose
POSTGRES_PASSWORD=x BAS_APP_DB_PASSWORD=y JWT_SECRET=z AGENT_SECRET=w \
  BAS_VERSION=test COMPOSE_PROJECT_NAME=role-sep-check \
  docker compose -f docker-compose.yml config 2>&1 | grep -A1 "DATABASE_"
```

Expected output includes both:

```
      DATABASE_URL: postgres://bas_app:y@postgres:5432/bas_platform?sslmode=prefer
      DATABASE_ADMIN_URL: postgres://bas_user:x@postgres:5432/bas_platform?sslmode=prefer
```

(exact whitespace/quoting may differ — what matters is `bas_app` appears
in `DATABASE_URL` and `bas_user` appears in `DATABASE_ADMIN_URL`, and
`docker compose config` exits 0, proving the YAML is syntactically valid).

- [ ] **Step 5: Commit**

```bash
git add packaging/compose/docker-compose.yml packaging/compose/install.sh
git commit -m "feat(deploy): provision bas_app credentials and split DATABASE_URL

BAS_APP_DB_PASSWORD is auto-generated (openssl rand -hex 32) the same way
JWT_SECRET/AGENT_SECRET already are -- upgrade-preserving, never
operator-facing. docker-compose.yml now wires DATABASE_URL to bas_app
(the orchestrator's normal runtime connection) and DATABASE_ADMIN_URL to
bas_user (bootstrap-only)."
git push
```

---

## Final Verification

After all five tasks:

```bash
cd orchestrator
go build ./...
go vet ./...
go test ./config/... ./internal/db/... ./internal/api/... ./cmd/server/... -v 2>&1 | tail -100
```

Expected: clean build and vet; the four affected packages' test suites are
green (modulo the pre-existing, unrelated `TestRBACMatrix_NoDrift` ca-root
failure noted in Global Constraints/Review Focus — confirm it's still that
exact, already-known failure and nothing new).

Then use `superpowers:finishing-a-development-branch` as this session has
throughout tonight.
