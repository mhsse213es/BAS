# Phase 7 Multi-Tenancy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the multi-tenancy *foundation* for Audspect BAS — a `tenants` table, `tenant_id` added to all 48 tenant-scoped tables (schema-only, safe, additive), a `WithTenant` transaction-scoping wrapper proven correct against Postgres Row-Level Security in isolation, tenant-aware JWT claims, and a platform-admin-only tenant-management API. No production handler is wired to enforce tenant isolation yet — that is an explicit, separately-scoped follow-up plan (see "Deliberately deferred" below).

**Architecture:** Additive schema migrations across the three existing `Ensure*Schema` files (`internal/db/postgres.go`, `content_schema.go`, `exercise_schema.go`), a new `WithTenant(ctx, pool, tenantID, isPlatformAdmin, fn)` helper in `internal/db/tenant.go` that scopes a transaction via Postgres `set_config()` (never raw `SET ... = $1`, which is invalid SQL, and never string-concatenation, which would be an injection risk), new tenant-aware JWT claims via an additive `GenerateTenantToken` function (the existing `GenerateToken` keeps its exact signature and behavior, so none of its 21 existing call sites change), and a `POST/GET /api/tenants` + `PATCH /api/tenants/{id}` API gated by a new `RequirePlatformAdmin` middleware — structurally distinct from `RequireRole`, since platform-admin is an orthogonal flag (which tenant, or none), not a fourth RBAC tier (what permission level).

**Tech Stack:** Go, pgx/v5, chi router, Postgres 16 (Row-Level Security), Docker testcontainers via `internal/testutil`.

## Global Constraints

- **No production handler routes through `WithTenant` in this plan.** RLS is proven correct against a purpose-built fixture table created and torn down entirely within its own test — never against a real table in the shared migration path — so nothing in this plan can silently break an existing feature.
- **`GenerateToken`'s existing 4-arg signature and behavior must not change.** All 21 existing call sites (production `Login` handler aside, which migrates to the new function) must keep compiling and passing unmodified.
- **Every new/altered SQL statement is idempotent** (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`), matching the existing `EnsureSchema`/`EnsureContentSchema`/`EnsureExerciseSchema` convention — these run on every startup.
- **Follow gofmt → build → vet → test** before every commit, matching this project's standing validation chain.

---

## Deliberately deferred (not in this plan)

Enabling RLS on any real, already-consumed table (`agents`, `findings`, or any of the other 46) and migrating every handler/package that queries it — across `internal/api` (24 handler files) and the Phase 6 aggregator packages (`internal/dashboard`, `internal/exposure`, `internal/predict`, `internal/reporting`, `internal/ticketing`) — is its own follow-up plan. Doing it here would mean re-touching already-shipped, already-tested `dashboard.Compute`/`exposure.Build`/`predict.Build` signatures, which is a materially different (and materially larger) piece of work than the foundation this plan lays. **A real, practical consequence of this deferral:** once Task 9 lands, `ListUsers`/`GetUser`/`UpdateUser`/`DeleteUser` are NOT tenant-filtered — a tenant admin can still see every user across every tenant via those endpoints, because RLS isn't enabled on `users` and those handlers aren't touched here. Multi-tenancy is not "live" or safe to expose to real MSSP clients until the follow-up plan closes this gap; this plan's deliverable is the foundation, not the finished feature.

---

## Task 1: `tenants` table + `users.tenant_id`

**Files:**
- Modify: `orchestrator/internal/db/postgres.go:29-43` (insert `tenants` table before `users`; add `tenant_id` column after the existing `users` ALTERs)
- Test: `orchestrator/internal/db/events_schema_test.go` pattern is `TEST_DATABASE_URL`-gated (see note below) — this task's test lives in a new Docker-backed file instead, per Task 5's package-cycle resolution

**Interfaces:**
- Produces: `tenants` table (`id`, `name`, `slug`, `status`, `created_at`); `users.tenant_id text REFERENCES tenants(id) DEFAULT 'default'`. Later tasks (2-4, 6-9) depend on the `tenants` table existing and on `'default'` being a valid, already-seeded tenant id.

`internal/db`'s own package (`package db`) cannot import `internal/testutil` — `testutil` imports `db` to build its Docker harness, so the reverse import would cycle. This task's verification therefore uses the same lightweight `TEST_DATABASE_URL`-gated pattern `events_schema_test.go` already established, consistent with that file, not the Docker-testcontainers-automatic pattern used elsewhere. Later tasks that need the full Docker harness use `internal/api` or an external `package db_test` file (Task 5).

- [ ] **Step 1: Add the `tenants` table and bootstrap row**

In `orchestrator/internal/db/postgres.go`, insert immediately before line 30 (`` `CREATE TABLE IF NOT EXISTS users (` ``):

```go
		`CREATE TABLE IF NOT EXISTS tenants (
			id         text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name       text        NOT NULL,
			slug       text        NOT NULL UNIQUE,
			status     text        NOT NULL DEFAULT 'active',
			created_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`INSERT INTO tenants (id, name, slug, status)
		 VALUES ('default', 'Default Tenant', 'default', 'active')
		 ON CONFLICT (id) DO NOTHING`,

```

- [ ] **Step 2: Add `users.tenant_id`, defaulted so every existing and future single-tenant user backfills correctly**

In `orchestrator/internal/db/postgres.go`, immediately after line 43 (`` `ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_pw boolean NOT NULL DEFAULT false`, ``), add:

```go
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id text REFERENCES tenants(id) DEFAULT 'default'`,
```

This single statement both adds the column and backfills every existing row to `'default'` (Postgres 11+ populates a new column's existing rows from a non-volatile `DEFAULT` without a table rewrite). A platform-admin user is created later by explicitly inserting `tenant_id = NULL`, which overrides the column default regardless — the default only applies when an `INSERT` omits the column entirely.

- [ ] **Step 3: Verify with the existing `TEST_DATABASE_URL` pattern**

Run (requires a reachable Postgres; skips cleanly otherwise): `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && TEST_DATABASE_URL="postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable" go test ./internal/db/ -run TestRunEventsSchemaCreated -v`
Expected: PASS (this only confirms `EnsureSchema` still runs without error after the edit — the real functional proof is Task 5's Docker-backed test, which runs the full migration automatically via `testutil.MustSharedTestDB()`).

If no local Postgres is reachable, skip this step's manual run — Task 5's test will exercise this same migration path via Docker and catch any SQL error.

- [ ] **Step 4: Build check**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./...`
Expected: clean build (this task only adds SQL strings, no Go signature changes).

- [ ] **Step 5: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/db/postgres.go
git commit -m "feat(tenancy): add tenants table and users.tenant_id

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 2: `tenant_id` on the 34 tenant-scoped tables in `postgres.go`

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (append `ALTER TABLE` statements to the existing `stmts` slice, near the end, before the closing `}` of the slice at line 882)

**Interfaces:**
- Consumes: `tenants` table from Task 1 (not a hard FK dependency here — these 34 tables use a plain `text` column with a literal default, matching the codebase's existing convention of not FK-constraining every relational column, e.g. `findings.agent_id`).
- Produces: `tenant_id text NOT NULL DEFAULT 'default'` on all 34 tables below. Task 5's fixture-table test and Task 10's regression both depend on this migration being idempotent and error-free.

- [ ] **Step 1: Add the 34 `ALTER TABLE` statements**

In `orchestrator/internal/db/postgres.go`, immediately before line 882 (the closing `}` of the `stmts` slice, right after the `dashboard_snapshots` index line), add:

```go
		// Phase 7 Multi-Tenancy — tenant_id on every operational table.
		// DEFAULT 'default' backfills existing rows and covers every INSERT
		// that doesn't specify tenant_id explicitly (matches Task 1's users.tenant_id).
		`ALTER TABLE agent_op_logs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE agent_sec_logs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE agent_telemetry ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE attackpath_collection_history ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE attackpath_collections ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE attackpath_jobs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE attackpath_schedule ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE campaign_variant_summary ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE compliance_snapshots ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE dashboard_snapshots ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE finding_tickets ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE findings ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE openaev_config ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE payload_families ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE report_log ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE run_events ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE scenario_variant_results ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE scenario_variant_technique_summary ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE siem_configs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE siem_correlations ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE tamper_events ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE ticketing_configs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE variant_findings ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE variant_run_steps ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE variant_runs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE verification_evidence ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE verification_evidence_blob ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE verification_history ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
```

- [ ] **Step 2: Verify count and build**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -c "ADD COLUMN IF NOT EXISTS tenant_id" internal/db/postgres.go`
Expected: `34` (this task's 34 statements; Task 1's `users` ALTER used different column-default wording and won't match this exact grep, confirming no double-count).

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./...`
Expected: clean build.

- [ ] **Step 3: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/db/postgres.go
git commit -m "feat(tenancy): add tenant_id to all postgres.go operational tables

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 3: `tenant_id` on the 5 tenant-scoped tables in `content_schema.go`

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go` (append to the `stmts` slice, before its closing `}` at line 251)

**Interfaces:**
- Produces: `tenant_id text NOT NULL DEFAULT 'default'` on `openaev_bundles`, `openaev_scenarios`, `scenario_techniques`, `scenarios`, `threat_readiness_history`. The 13 global content tables (`techniques`, `tactics`, ART/CVE/OWASP catalog) are deliberately untouched — per the spec's Decision 5, they stay shared across all tenants.

- [ ] **Step 1: Add the 5 `ALTER TABLE` statements**

In `orchestrator/internal/db/content_schema.go`, immediately before line 251 (the closing `}` of the `stmts` slice), add:

```go
		// Phase 7 Multi-Tenancy — the 5 tenant-owned tables in this file.
		// The other 13 tables here are the global ATT&CK/ART/CVE/OWASP catalog
		// and deliberately stay unscoped (spec Decision 5).
		`ALTER TABLE openaev_bundles ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE openaev_scenarios ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE scenario_techniques ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE scenarios ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE threat_readiness_history ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
```

- [ ] **Step 2: Build check**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./...`
Expected: clean build.

- [ ] **Step 3: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/db/content_schema.go
git commit -m "feat(tenancy): add tenant_id to the 5 tenant-owned content_schema tables

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 4: `tenant_id` on all 8 tables in `exercise_schema.go`

**Files:**
- Modify: `orchestrator/internal/db/exercise_schema.go` (append to the `stmts` slice, before its closing `}` at line 148)

**Interfaces:**
- Produces: `tenant_id text NOT NULL DEFAULT 'default'` on all 8 exercise tables (every table in this file is operational/tenant-owned — there is no global-content split within `exercise_schema.go`, unlike `content_schema.go`).

- [ ] **Step 1: Add the 8 `ALTER TABLE` statements**

In `orchestrator/internal/db/exercise_schema.go`, immediately before line 148 (the closing `}` of the `stmts` slice), add:

```go
		// Phase 7 Multi-Tenancy — every table in this file is tenant-owned.
		`ALTER TABLE exercise_events ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_evidence ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_executions ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_plans ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_step_executions ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_templates ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_track_tokens ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_webhook_calls ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
```

- [ ] **Step 2: Build check**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./...`
Expected: clean build.

- [ ] **Step 3: Full Docker-backed migration proof (all three schema files together)**

This is the first point where the complete migration (Tasks 1-4) can be exercised end-to-end, via any existing Docker-backed package test (which all call `testutil.MustSharedTestDB()` → `EnsureSchema` + `EnsureContentSchema` + `EnsureExerciseSchema` on container boot).

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/predict/ -run TestBuild_EmptyFleet -v`
Expected: PASS. This test doesn't touch tenancy at all — passing confirms the migration ran cleanly (a broken `ALTER` statement would fail every Docker-backed test in the repo at container setup, not just this one).

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/db/exercise_schema.go
git commit -m "feat(tenancy): add tenant_id to all exercise_schema tables

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 5: `WithTenant` wrapper, proven against a fixture table

**Files:**
- Create: `orchestrator/internal/db/tenant.go`
- Test: `orchestrator/internal/db/tenant_test.go` (external test package `db_test` — `internal/db` cannot import `internal/testutil` directly, since `testutil` already imports `db`; the `_test` package suffix is Go's standard escape hatch for exactly this cycle)

**Interfaces:**
- Produces: `func WithTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, isPlatformAdmin bool, fn func(pgx.Tx) error) error` — the exact signature Task 8/9 (and the deferred follow-up plan) build on.
- Consumes: nothing from earlier tasks directly (tests its own fixture table, not any real schema table).

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/db/tenant_test.go`:

```go
package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	if code != 0 {
		panic("tests failed")
	}
}

// setupProbeTable creates a purpose-built, RLS-enabled fixture table for
// proving WithTenant in isolation — never a real production table, so this
// test can never affect any other package's Docker-backed tests.
func setupProbeTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	mustExec(t, pool, `CREATE TABLE IF NOT EXISTS tenant_isolation_probe (
		id        text PRIMARY KEY DEFAULT gen_random_uuid()::text,
		tenant_id text NOT NULL,
		label     text NOT NULL
	)`)
	mustExec(t, pool, `ALTER TABLE tenant_isolation_probe ENABLE ROW LEVEL SECURITY`)
	mustExec(t, pool, `DROP POLICY IF EXISTS tenant_isolation ON tenant_isolation_probe`)
	mustExec(t, pool, `CREATE POLICY tenant_isolation ON tenant_isolation_probe
		USING (
			tenant_id = current_setting('app.tenant_id', true)
			OR current_setting('app.is_platform_admin', true) = 'true'
		)`)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS tenant_isolation_probe`)
	})
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func TestWithTenant_IsolatesRowsBetweenTenants(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		setupProbeTable(t, pool)
		ctx := context.Background()

		// Seed one row per tenant, each written under its own WithTenant scope
		// (proving writes are scoped too, not just reads).
		if err := db.WithTenant(ctx, pool, "tenant-a", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO tenant_isolation_probe (tenant_id, label) VALUES ('tenant-a', 'a-row')`)
			return err
		}); err != nil {
			t.Fatalf("seed tenant-a: %v", err)
		}
		if err := db.WithTenant(ctx, pool, "tenant-b", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO tenant_isolation_probe (tenant_id, label) VALUES ('tenant-b', 'b-row')`)
			return err
		}); err != nil {
			t.Fatalf("seed tenant-b: %v", err)
		}

		// Tenant A's session must not see tenant B's row, even via a query
		// with no WHERE tenant_id clause at all — the whole point of RLS.
		var gotLabels []string
		err := db.WithTenant(ctx, pool, "tenant-a", false, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT label FROM tenant_isolation_probe`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var label string
				if err := rows.Scan(&label); err != nil {
					return err
				}
				gotLabels = append(gotLabels, label)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatalf("query as tenant-a: %v", err)
		}
		if len(gotLabels) != 1 || gotLabels[0] != "a-row" {
			t.Fatalf("tenant-a saw %v, want exactly [a-row]", gotLabels)
		}
	})
}

func TestWithTenant_PlatformAdminSeesEveryTenant(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		setupProbeTable(t, pool)
		ctx := context.Background()

		if err := db.WithTenant(ctx, pool, "tenant-a", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO tenant_isolation_probe (tenant_id, label) VALUES ('tenant-a', 'a-row')`)
			return err
		}); err != nil {
			t.Fatalf("seed tenant-a: %v", err)
		}
		if err := db.WithTenant(ctx, pool, "tenant-b", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO tenant_isolation_probe (tenant_id, label) VALUES ('tenant-b', 'b-row')`)
			return err
		}); err != nil {
			t.Fatalf("seed tenant-b: %v", err)
		}

		var count int
		// isPlatformAdmin=true, tenantID irrelevant (empty) — the RLS policy's
		// OR-bypass clause must grant visibility into every tenant's rows.
		err := db.WithTenant(ctx, pool, "", true, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM tenant_isolation_probe`).Scan(&count)
		})
		if err != nil {
			t.Fatalf("query as platform-admin: %v", err)
		}
		if count != 2 {
			t.Fatalf("platform-admin saw %d rows, want 2", count)
		}
	})
}

func TestWithTenant_SetLocalDoesNotLeakAcrossTransactions(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		setupProbeTable(t, pool)
		ctx := context.Background()

		if err := db.WithTenant(ctx, pool, "tenant-a", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO tenant_isolation_probe (tenant_id, label) VALUES ('tenant-a', 'a-row')`)
			return err
		}); err != nil {
			t.Fatalf("seed as tenant-a: %v", err)
		}

		// Run many sequential WithTenant calls with alternating tenant context
		// on the same pool (which reuses connections) — SET LOCAL is
		// transaction-scoped, so none of these should ever see the other
		// tenant's row.
		for i := 0; i < 10; i++ {
			tenant := "tenant-a"
			if i%2 == 1 {
				tenant = "tenant-b"
			}
			var count int
			err := db.WithTenant(ctx, pool, tenant, false, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM tenant_isolation_probe`).Scan(&count)
			})
			if err != nil {
				t.Fatalf("iteration %d (%s): %v", i, tenant, err)
			}
			want := 0
			if tenant == "tenant-a" {
				want = 1
			}
			if count != want {
				t.Fatalf("iteration %d (%s): count = %d, want %d — SET LOCAL leaked across a pooled connection", i, tenant, count, want)
			}
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/db/ -run TestWithTenant -v`
Expected: FAIL — `undefined: db.WithTenant` (compile error).

- [ ] **Step 3: Write `WithTenant`**

Create `orchestrator/internal/db/tenant.go`:

```go
// Package db's tenant.go provides the transaction-scoping seam every
// tenant-aware query must go through. Session-scoping uses Postgres's
// set_config() rather than a raw `SET LOCAL ... = $1` (which is not valid
// SQL — SET does not accept bind parameters) or string concatenation (which
// would be an injection risk). See
// docs/superpowers/specs/2026-07-18-phase7-multi-tenancy-design.md.
package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithTenant runs fn inside a transaction whose Postgres session variables
// (app.tenant_id, app.is_platform_admin) are set for Row-Level Security
// policies to key off. Both variables are set via set_config(..., true) —
// the `true` third argument makes them LOCAL, i.e. scoped to this
// transaction only, so they can never leak into a pooled connection's next,
// unrelated use.
func WithTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, isPlatformAdmin bool, fn func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
		return err
	}
	adminFlag := "false"
	if isPlatformAdmin {
		adminFlag = "true"
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.is_platform_admin', $1, true)`, adminFlag); err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/db/ -run TestWithTenant -v`
Expected: PASS (3/3 — isolation, platform-admin bypass, no cross-transaction leak).

- [ ] **Step 5: gofmt + vet**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -l internal/db/tenant.go internal/db/tenant_test.go && go vet ./internal/db/`
Expected: no output, no errors.

- [ ] **Step 6: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/db/tenant.go internal/db/tenant_test.go
git commit -m "feat(tenancy): add WithTenant RLS-scoping wrapper, proven against a fixture table

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 6: Tenant-aware JWT claims + `RequirePlatformAdmin` middleware

**Files:**
- Modify: `orchestrator/internal/auth/jwt.go`
- Modify: `orchestrator/internal/auth/jwt_test.go`
- Modify: `orchestrator/internal/auth/middleware.go`
- Modify: `orchestrator/internal/auth/middleware_test.go`

**Interfaces:**
- Produces: `Claims.TenantID *string`, `Claims.IsPlatformAdmin bool`; `GenerateTenantToken(userID string, role Role, tenantID *string, isPlatformAdmin bool, secret string, ttl time.Duration) (string, error)`; `RequirePlatformAdmin() func(http.Handler) http.Handler`. Task 7 (Login) and Task 8 (tenant-management API routes) depend on all three.
- Consumes: nothing from earlier tasks (pure auth-package change).

**`GenerateToken`'s existing signature does not change** — it becomes a thin wrapper over the new function with `tenantID=nil, isPlatformAdmin=false`, so all 21 existing call sites across the repo keep compiling and passing exactly as before.

- [ ] **Step 1: Write the failing tests**

In `orchestrator/internal/auth/jwt_test.go`, add:

```go
func TestGenerateTenantToken_RoundTrip(t *testing.T) {
	tenantID := "acme"
	tok, err := GenerateTenantToken("user-1", RoleAdmin, &tenantID, false, "secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateTenantToken: %v", err)
	}
	claims, err := ValidateToken(tok, "secret")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.TenantID == nil || *claims.TenantID != "acme" {
		t.Errorf("TenantID = %v, want acme", claims.TenantID)
	}
	if claims.IsPlatformAdmin {
		t.Error("IsPlatformAdmin = true, want false")
	}
}

func TestGenerateTenantToken_PlatformAdminHasNoTenant(t *testing.T) {
	tok, err := GenerateTenantToken("admin-1", RoleAdmin, nil, true, "secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateTenantToken: %v", err)
	}
	claims, err := ValidateToken(tok, "secret")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.TenantID != nil {
		t.Errorf("TenantID = %v, want nil for platform-admin", claims.TenantID)
	}
	if !claims.IsPlatformAdmin {
		t.Error("IsPlatformAdmin = false, want true")
	}
}

func TestGenerateToken_StillHasNoTenantContext(t *testing.T) {
	// GenerateToken must keep working exactly as before, with zero tenant
	// claims, so every pre-tenancy call site keeps compiling and passing.
	tok, err := GenerateToken("user-1", RoleAnalyst, "secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := ValidateToken(tok, "secret")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.TenantID != nil {
		t.Errorf("TenantID = %v, want nil", claims.TenantID)
	}
	if claims.IsPlatformAdmin {
		t.Error("IsPlatformAdmin = true, want false")
	}
}
```

In `orchestrator/internal/auth/middleware_test.go`, add (mirroring the existing `TestRequireRole_AllowedRolePasses`/`TestRequireRole_DisallowedRoleForbidden` pattern exactly):

```go
func TestRequirePlatformAdmin_PlatformAdminPasses(t *testing.T) {
	tok, _ := GenerateTenantToken("pa-1", RoleAdmin, nil, true, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	called := false
	handler := Middleware("secret")(RequirePlatformAdmin()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v status=%d, want called=true status=200", called, rec.Code)
	}
}

func TestRequirePlatformAdmin_TenantAdminForbidden(t *testing.T) {
	tenantID := "acme"
	tok, _ := GenerateTenantToken("ta-1", RoleAdmin, &tenantID, false, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler := Middleware("secret")(RequirePlatformAdmin()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called for a non-platform-admin, even with RoleAdmin")
	})))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/auth/ -run 'TestGenerateTenantToken|TestGenerateToken_StillHasNoTenantContext|TestRequirePlatformAdmin' -v`
Expected: FAIL — compile errors (`undefined: GenerateTenantToken`, `undefined: RequirePlatformAdmin`, `Claims.TenantID` field missing).

- [ ] **Step 3: Add the claims fields and `GenerateTenantToken`**

In `orchestrator/internal/auth/jwt.go`, replace:

```go
// Claims is the JWT payload.
type Claims struct {
	UserID string `json:"user_id"`
	Role   Role   `json:"role"`
	jwt.RegisteredClaims
}

// GenerateToken creates a signed JWT for the given user and role.
func GenerateToken(userID string, role Role, secret string, ttl time.Duration) (string, error) {
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}
```

with:

```go
// Claims is the JWT payload. TenantID is nil for a platform-admin (who
// belongs to no single tenant) and non-nil for a regular tenant user.
// IsPlatformAdmin is an orthogonal flag — which tenant, or none — distinct
// from Role, which answers what permission level within that scope.
type Claims struct {
	UserID          string  `json:"user_id"`
	Role            Role    `json:"role"`
	TenantID        *string `json:"tenant_id,omitempty"`
	IsPlatformAdmin bool    `json:"is_platform_admin,omitempty"`
	jwt.RegisteredClaims
}

// GenerateTenantToken creates a signed JWT carrying tenant context.
// tenantID must be nil when isPlatformAdmin is true, and non-nil otherwise.
func GenerateTenantToken(userID string, role Role, tenantID *string, isPlatformAdmin bool, secret string, ttl time.Duration) (string, error) {
	claims := Claims{
		UserID:          userID,
		Role:            role,
		TenantID:        tenantID,
		IsPlatformAdmin: isPlatformAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

// GenerateToken creates a signed JWT for the given user and role, with no
// tenant context. Equivalent to GenerateTenantToken with tenantID=nil,
// isPlatformAdmin=false — kept as a separate, stable-signature function so
// the many pre-tenancy call sites across the codebase never need to change.
func GenerateToken(userID string, role Role, secret string, ttl time.Duration) (string, error) {
	return GenerateTenantToken(userID, role, nil, false, secret, ttl)
}
```

- [ ] **Step 4: Add `RequirePlatformAdmin`**

In `orchestrator/internal/auth/middleware.go`, add after the existing `RequireRole` function:

```go
// RequirePlatformAdmin rejects requests from users who are not
// platform-admins. Distinct from RequireRole: platform-admin is an
// orthogonal flag (which tenant, or none), not a fourth RBAC tier (what
// permission level).
func RequirePlatformAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFrom(r.Context())
			if !ok || !claims.IsPlatformAdmin {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/auth/ -v`
Expected: PASS, full package (new tests plus every pre-existing test in `internal/auth` — confirming `GenerateToken`'s 21 existing call sites across the repo still compile, since this package's own tests exercise it directly and the repo-wide build in Step 6 exercises the rest).

- [ ] **Step 6: Full repo build check (catches any of the 21 `GenerateToken` call sites that might have broken)**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go vet ./...`
Expected: clean build and vet — zero call sites should need changes, since `GenerateToken`'s signature is unchanged.

- [ ] **Step 7: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/auth/jwt.go internal/auth/jwt_test.go internal/auth/middleware.go internal/auth/middleware_test.go
git commit -m "feat(tenancy): add tenant-aware JWT claims and RequirePlatformAdmin middleware

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 7: `Login` handler mints tenant-aware tokens

**Files:**
- Modify: `orchestrator/internal/api/handlers.go:272-330` (the `Login` handler)
- Modify: `orchestrator/internal/api/auth_handlers_test.go` (the existing `TestLogin_*` tests already live here, alongside the `loginReq(username, password) *http.Request` helper)

**Interfaces:**
- Consumes: `auth.GenerateTenantToken` (Task 6); `users.tenant_id` column (Task 1); the existing `seedUser(t, pool, username, password, role string, active bool) string` helper (`internal/api/testmain_test.go:34`) and `loginReq` helper (`internal/api/auth_handlers_test.go:17`) — reused as-is, not reinvented.
- Produces: a `bas_token` cookie/response token that carries `tenant_id` (nil for a platform-admin row) and `is_platform_admin` (derived as `tenant_id IS NULL`).

- [ ] **Step 1: Write the failing test**

`seedUser`'s `INSERT` doesn't mention `tenant_id`, so — thanks to Task 1's column-level `DEFAULT 'default'` — any user it creates automatically lands in the `default` tenant with zero changes needed to that helper. Only the platform-admin case (`tenant_id IS NULL`) needs a one-off raw insert, since `seedUser`'s fixed 4-column insert has no way to express `NULL`.

Add to `orchestrator/internal/api/auth_handlers_test.go`:

```go
func TestLogin_TokenCarriesTenantContext(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)

		seedUser(t, pool, "tenant-user", "correct-horse-battery", "admin", true) // lands in 'default' via the column DEFAULT

		hash, err := auth.HashPassword("correct-horse-battery")
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO users (username, password_hash, role, is_active, tenant_id) VALUES ('pa-user', $1, 'admin', true, NULL)`,
			hash,
		); err != nil {
			t.Fatalf("seed platform-admin user: %v", err)
		}

		rec := httptest.NewRecorder()
		h.Login(rec, loginReq("tenant-user", "correct-horse-battery"))
		if rec.Code != http.StatusOK {
			t.Fatalf("tenant-user login status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		claims, err := auth.ValidateToken(resp.Token, testJWTSecret)
		if err != nil {
			t.Fatalf("ValidateToken: %v", err)
		}
		if claims.TenantID == nil || *claims.TenantID != "default" {
			t.Errorf("tenant-user TenantID = %v, want default", claims.TenantID)
		}
		if claims.IsPlatformAdmin {
			t.Error("tenant-user IsPlatformAdmin = true, want false")
		}

		rec = httptest.NewRecorder()
		h.Login(rec, loginReq("pa-user", "correct-horse-battery"))
		if rec.Code != http.StatusOK {
			t.Fatalf("pa-user login status = %d, body=%s", rec.Code, rec.Body.String())
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		claims, err = auth.ValidateToken(resp.Token, testJWTSecret)
		if err != nil {
			t.Fatalf("ValidateToken: %v", err)
		}
		if claims.TenantID != nil {
			t.Errorf("pa-user TenantID = %v, want nil", claims.TenantID)
		}
		if !claims.IsPlatformAdmin {
			t.Error("pa-user IsPlatformAdmin = false, want true")
		}
	})
}
```

`auth_handlers_test.go`'s existing import block already has everything this test needs (`encoding/json`, `net/http`, `net/http/httptest`, `testing`, `auth`, `ws`, `pgxpool`) — no import changes required.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/ -run TestLogin_TokenCarriesTenantContext -v`
Expected: FAIL — the token's claims have `TenantID: nil, IsPlatformAdmin: false` for BOTH users, since `Login` doesn't fetch or use `tenant_id` yet.

- [ ] **Step 3: Wire `Login` to fetch and use `tenant_id`**

In `orchestrator/internal/api/handlers.go`, replace:

```go
	var id, hash, role string
	var isActive, mustChangePw bool
	dbErr := h.db.QueryRow(r.Context(),
		`SELECT id, password_hash, role, is_active, must_change_pw FROM users WHERE username = $1`, req.Username,
	).Scan(&id, &hash, &role, &isActive, &mustChangePw)
```

with:

```go
	var id, hash, role string
	var isActive, mustChangePw bool
	var tenantID *string
	dbErr := h.db.QueryRow(r.Context(),
		`SELECT id, password_hash, role, is_active, must_change_pw, tenant_id FROM users WHERE username = $1`, req.Username,
	).Scan(&id, &hash, &role, &isActive, &mustChangePw, &tenantID)
```

and replace:

```go
	token, err := auth.GenerateToken(id, auth.Role(role), h.secret, 24*time.Hour)
```

with:

```go
	token, err := auth.GenerateTenantToken(id, auth.Role(role), tenantID, tenantID == nil, h.secret, 24*time.Hour)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/ -run TestLogin_TokenCarriesTenantContext -v`
Expected: PASS.

- [ ] **Step 5: Full `internal/api` regression**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/`
Expected: PASS (this suite runs several minutes; confirms the `Login` query/scan change didn't break any existing login-path test).

- [ ] **Step 6: gofmt + vet**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -l internal/api/handlers.go && go vet ./internal/api/`
Expected: no output, no errors.

- [ ] **Step 7: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/api/handlers.go internal/api/auth_handlers_test.go
git commit -m "feat(tenancy): Login mints tenant-aware tokens

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 8: Tenant-management API

**Files:**
- Create: `orchestrator/internal/api/tenant_handlers.go`
- Create: `orchestrator/internal/api/tenant_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (register the new group, after the existing admin-only group ends around line 335+ — grounded precisely in Step 1)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `RequirePlatformAdmin` (Task 6); `tenants` table (Task 1).
- Produces: `Tenant` struct (`ID`, `Name`, `Slug`, `Status`, `CreatedAt` — all `string`-typed JSON fields), used again by Task 9's tests if needed.

- [ ] **Step 1: Find the exact end of the existing admin-only group**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -n "r.Group(func(r chi.Router) {" -A 2 internal/api/routes.go | grep -A2 "RequireRole(auth.RoleAdmin)$"`

This confirms the admin-only group's opening (matches the `r.Use(auth.RequireRole(auth.RoleAdmin))` line already read at routes.go:308) — place the new platform-admin group immediately after that group's closing `})`, which Step 4 locates precisely before editing.

- [ ] **Step 2: Write the failing tests**

Create `orchestrator/internal/api/tenant_handlers_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func tenantHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
}

func TestCreateTenant_ThenListTenants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tenantHandler(t, pool)

		body := `{"name":"Acme Bank","slug":"acme"}`
		rec := httptest.NewRecorder()
		h.CreateTenant(rec, httptest.NewRequest(http.MethodPost, "/api/tenants", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("CreateTenant status = %d, body=%s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		h.ListTenants(rec, httptest.NewRequest(http.MethodGet, "/api/tenants", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("ListTenants status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var got []Tenant
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		// 'default' (from the Task 1 bootstrap row) plus the one just created.
		if len(got) != 2 {
			t.Fatalf("ListTenants returned %d tenants, want 2 (default + acme): %+v", len(got), got)
		}
		foundAcme := false
		for _, tn := range got {
			if tn.Slug == "acme" && tn.Name == "Acme Bank" && tn.Status == "active" {
				foundAcme = true
			}
		}
		if !foundAcme {
			t.Errorf("did not find the created acme tenant in %+v", got)
		}
	})
}

func TestCreateTenant_DuplicateSlugConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tenantHandler(t, pool)
		body := `{"name":"First","slug":"dupe"}`
		rec := httptest.NewRecorder()
		h.CreateTenant(rec, httptest.NewRequest(http.MethodPost, "/api/tenants", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("first create status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		h.CreateTenant(rec, httptest.NewRequest(http.MethodPost, "/api/tenants", strings.NewReader(body)))
		if rec.Code != http.StatusConflict {
			t.Fatalf("duplicate slug status = %d, want 409", rec.Code)
		}
	})
}

func TestUpdateTenant_SuspendAndRename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tenantHandler(t, pool)
		var id string
		if err := pool.QueryRow(t.Context(), `INSERT INTO tenants (name, slug) VALUES ('Old Name', 'update-me') RETURNING id`).Scan(&id); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}

		body := `{"name":"New Name","status":"suspended"}`
		req := httptest.NewRequest(http.MethodPatch, "/api/tenants/"+id, strings.NewReader(body))
		req = withURLParam(req, "id", id) // existing helper, internal/api/event_handlers_test.go:52
		rec := httptest.NewRecorder()
		h.UpdateTenant(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("UpdateTenant status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var name, status string
		if err := pool.QueryRow(t.Context(), `SELECT name, status FROM tenants WHERE id = $1`, id).Scan(&name, &status); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if name != "New Name" || status != "suspended" {
			t.Errorf("name=%q status=%q, want New Name/suspended", name, status)
		}
	})
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/ -run 'TestCreateTenant|TestUpdateTenant' -v`
Expected: FAIL — compile errors (`h.CreateTenant undefined`, etc.).

- [ ] **Step 4: Write the handlers**

Create `orchestrator/internal/api/tenant_handlers.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Tenant is one row from the tenants table.
type Tenant struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
}

// CreateTenant provisions a new tenant. Platform-admin only.
// POST /api/tenants
func (h *Handler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Slug == "" {
		jsonError(w, "name and slug are required", http.StatusBadRequest)
		return
	}
	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id`,
		req.Name, req.Slug,
	).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			jsonError(w, "slug already exists", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, Tenant{ID: id, Name: req.Name, Slug: req.Slug, Status: "active"})
}

// ListTenants returns every tenant. Platform-admin only.
// GET /api/tenants
func (h *Handler) ListTenants(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, name, slug, status, to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') FROM tenants ORDER BY created_at ASC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []Tenant{}
	for rows.Next() {
		var t Tenant
		if rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.CreatedAt) != nil {
			continue
		}
		out = append(out, t)
	}
	respond(w, out)
}

// UpdateTenant renames and/or suspends/reactivates a tenant. Platform-admin only.
// PATCH /api/tenants/{id}
func (h *Handler) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name   *string `json:"name"`
		Status *string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Status != nil && *req.Status != "active" && *req.Status != "suspended" {
		jsonError(w, "status must be active or suspended", http.StatusBadRequest)
		return
	}
	if req.Name == nil && req.Status == nil {
		jsonError(w, "nothing to update", http.StatusBadRequest)
		return
	}
	tag, err := h.db.Exec(r.Context(),
		`UPDATE tenants SET name = COALESCE($2, name), status = COALESCE($3, status) WHERE id = $1`,
		id, req.Name, req.Status,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "tenant not found", http.StatusNotFound)
		return
	}
	respond(w, map[string]string{"status": "ok"})
}
```

- [ ] **Step 5: Register the routes**

In `orchestrator/internal/api/routes.go`, immediately after the closing `})` of the existing admin-only `r.Group` block that starts at line 307 (the one containing `r.Post("/api/users", h.CreateUser)` etc. — verify the exact closing line via `grep -n "^\t\t})" internal/api/routes.go` and match it to the group opened at line 307 before editing), add a new group:

```go

		// Platform-admin only — Phase 7 Multi-Tenancy. Orthogonal to the role
		// tiers above: platform-admin is "which tenant, or none," not "what
		// permission level."
		r.Group(func(r chi.Router) {
			r.Use(auth.RequirePlatformAdmin())
			r.Post("/api/tenants", h.CreateTenant)
			r.Get("/api/tenants", h.ListTenants)
			r.Patch("/api/tenants/{id}", h.UpdateTenant)
		})
```

- [ ] **Step 6: Add the RBAC-matrix entries**

In `orchestrator/internal/api/rbac_matrix_test.go`, add a new tier constant to the existing `const` block:

```go
const (
	tierAny authTier = iota // any authenticated role (viewer, analyst, admin)
	tierAnalystAdmin
	tierAdminOnly
	tierPermission
	tierPlatformAdmin // orthogonal to role — see auth.RequirePlatformAdmin
)
```

Add a case to `tierAllows` (platform-admin is never implied by role alone, so every role-based identity the existing `TestRBACMatrix_AuthorizationBoundary` loop already tests correctly gets 403 for these routes with zero other changes to that test):

```go
	case tierPlatformAdmin:
		return false // no Role alone ever grants platform-admin; see TestPlatformAdminRoutes_Gating for the positive case
```

Add the three new routes to `routeMatrix`:

```go
	{http.MethodPost, "/api/tenants", tierPlatformAdmin, ""},
	{http.MethodGet, "/api/tenants", tierPlatformAdmin, ""},
	{http.MethodPatch, "/api/tenants/{id}", tierPlatformAdmin, ""},
```

Add a dedicated positive-case test proving a platform-admin token *does* pass (the `authTier`/`tierAllows` model above only expresses the role-based negative case):

```go
func TestPlatformAdminRoutes_Gating(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)

		platformAdminTok, _ := auth.GenerateTenantToken("pa-1", auth.RoleAdmin, nil, true, testJWTSecret, time.Hour)
		tenantID := "default"
		tenantAdminTok, _ := auth.GenerateTenantToken("ta-1", auth.RoleAdmin, &tenantID, false, testJWTSecret, time.Hour)

		req := httptest.NewRequest(http.MethodGet, "/api/tenants", nil)
		req.Header.Set("Authorization", "Bearer "+platformAdminTok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("platform-admin GET /api/tenants status = %d, want 200", rec.Code)
		}

		req = httptest.NewRequest(http.MethodGet, "/api/tenants", nil)
		req.Header.Set("Authorization", "Bearer "+tenantAdminTok)
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("tenant-admin (RoleAdmin, not platform-admin) GET /api/tenants status = %d, want 403", rec.Code)
		}
	})
}
```

- [ ] **Step 7: Run all the new tests**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/ -run 'TestCreateTenant|TestUpdateTenant|TestPlatformAdminRoutes_Gating|TestRBACMatrix' -v`
Expected: PASS, all of them — including `TestRBACMatrix_NoDrift` and `TestRBACMatrix_AuthorizationBoundary`, confirming the new routes are correctly registered and every existing role-based identity is correctly forbidden.

- [ ] **Step 8: Full `internal/api` regression**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/`
Expected: PASS.

- [ ] **Step 9: gofmt + vet + build**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -l internal/api/tenant_handlers.go internal/api/tenant_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go && go vet ./internal/api/ && go build ./...`
Expected: no output, no errors, clean build.

- [ ] **Step 10: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/api/tenant_handlers.go internal/api/tenant_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(tenancy): add platform-admin-only tenant management API

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 9: `CreateUser` accepts tenant assignment

**Files:**
- Modify: `orchestrator/internal/api/handlers.go:1982-2030` (the `CreateUser` handler)
- Modify: `orchestrator/internal/api/tenant_handlers_test.go` (append tests + update its import block)
- Modify: `orchestrator/internal/auth/middleware.go` (add `ContextWithClaims`, the missing setter counterpart to `ClaimsFrom`)

**Interfaces:**
- Consumes: `auth.ClaimsFrom` (existing); `Claims.TenantID`/`Claims.IsPlatformAdmin` (Task 6).
- Produces: nothing new consumed elsewhere — this closes the loop so a freshly created tenant (Task 8) can actually have a user placed in it, making the whole feature testable end-to-end rather than a dead end.

A platform-admin must specify which tenant a new user belongs to (they have no home tenant to default to); a regular tenant admin can only ever create users in their own tenant — the request body's `tenantId` is silently ignored for them, not merely validated, so a tenant admin can never smuggle a user into a different tenant even by guessing another tenant's id.

- [ ] **Step 1: Write the failing test**

`tenant_handlers_test.go`'s import block (written in Task 8) does not yet import `"time"` or `"github.com/audspect/bas/internal/auth"`, both of which the code below needs. Add them to the existing `import (...)` block first:

```go
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)
```

Then append to `orchestrator/internal/api/tenant_handlers_test.go`:

```go
func TestCreateUser_PlatformAdminMustSpecifyTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tenantHandler(t, pool)
		platformAdminTok, _ := auth.GenerateTenantToken("pa-1", auth.RoleAdmin, nil, true, testJWTSecret, time.Hour)

		body := `{"username":"noTenant","password":"correcthorsebatterystaple","role":"viewer"}`
		req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+platformAdminTok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.CreateUser(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("platform-admin CreateUser with no tenantId status = %d, want 400", rec.Code)
		}
	})
}

func TestCreateUser_TenantAdminIgnoresRequestedTenantId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tenantHandler(t, pool)
		var otherTenantID string
		if err := pool.QueryRow(t.Context(), `INSERT INTO tenants (name, slug) VALUES ('Other', 'other') RETURNING id`).Scan(&otherTenantID); err != nil {
			t.Fatalf("seed other tenant: %v", err)
		}
		defaultTenant := "default"
		tenantAdminTok, _ := auth.GenerateTenantToken("ta-1", auth.RoleAdmin, &defaultTenant, false, testJWTSecret, time.Hour)

		body := `{"username":"sneaky","password":"correcthorsebatterystaple","role":"viewer","tenantId":"` + otherTenantID + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tenantAdminTok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.CreateUser(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("CreateUser status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var gotTenant string
		if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM users WHERE username = 'sneaky'`).Scan(&gotTenant); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if gotTenant != "default" {
			t.Errorf("created user's tenant_id = %q, want default (the caller's own tenant, not the requested other) ", gotTenant)
		}
	})
}

// withClaims puts the request's own bearer token's claims into its context,
// the way auth.Middleware would in the real router — CreateUser reads
// caller identity via auth.ClaimsFrom, and these tests call the handler
// directly (bypassing Mount's middleware chain), so this must be done by hand.
func withClaims(t *testing.T, req *http.Request, secret string) *http.Request {
	t.Helper()
	tok := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	claims, err := auth.ValidateToken(tok, secret)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	return req.WithContext(auth.ContextWithClaims(req.Context(), claims))
}
```

- [ ] **Step 2: Check whether `auth.ContextWithClaims` already exists**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -n "ContextWithClaims\|ctxClaimsKey" internal/auth/middleware.go`

`middleware.go` currently only exposes `ClaimsFrom` (a getter) — there is no exported setter, since `Middleware()` sets the context value inline via the unexported `ctxClaimsKey{}`. Add one alongside `ClaimsFrom`:

```go
// ContextWithClaims returns a context carrying claims, retrievable via
// ClaimsFrom. Exported for tests that call a handler directly, bypassing
// Middleware's normal request-scoped context injection.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, ctxClaimsKey{}, claims)
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/ -run TestCreateUser_ -v`
Expected: FAIL — `TestCreateUser_PlatformAdminMustSpecifyTenant` gets 200 (not yet validated), `TestCreateUser_TenantAdminIgnoresRequestedTenantId` gets a `tenant_id` mismatch (CreateUser doesn't read `tenantId` from the body or the caller's claims yet).

- [ ] **Step 4: Wire `CreateUser`**

In `orchestrator/internal/api/handlers.go`, replace:

```go
// POST /api/users
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		jsonError(w, "username and password are required", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "analyst"
	}
	if req.Role != "admin" && req.Role != "analyst" && req.Role != "viewer" {
		jsonError(w, "role must be admin, analyst, or viewer", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		jsonError(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		jsonError(w, "password hashing failed", http.StatusInternalServerError)
		return
	}

	var id string
	err = h.db.QueryRow(r.Context(),
		`INSERT INTO users (username, password_hash, role, must_change_pw)
		 VALUES ($1, $2, $3, true)
		 RETURNING id`,
		req.Username, hash, req.Role,
	).Scan(&id)
```

with:

```go
// POST /api/users
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		TenantID string `json:"tenantId"` // platform-admin only; ignored otherwise
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		jsonError(w, "username and password are required", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "analyst"
	}
	if req.Role != "admin" && req.Role != "analyst" && req.Role != "viewer" {
		jsonError(w, "role must be admin, analyst, or viewer", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		jsonError(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	claims, ok := auth.ClaimsFrom(r.Context())
	tenantID := req.TenantID
	switch {
	case !ok:
		jsonError(w, "no caller identity", http.StatusForbidden)
		return
	case claims.IsPlatformAdmin:
		if tenantID == "" {
			jsonError(w, "tenantId is required for platform-admin-created users", http.StatusBadRequest)
			return
		}
	case claims.TenantID != nil:
		// A tenant admin can only ever create users within their own
		// tenant — the request body's tenantId is silently overridden,
		// not merely validated, so it can never be used to smuggle a
		// user into a different tenant.
		tenantID = *claims.TenantID
	default:
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		jsonError(w, "password hashing failed", http.StatusInternalServerError)
		return
	}

	var id string
	err = h.db.QueryRow(r.Context(),
		`INSERT INTO users (username, password_hash, role, must_change_pw, tenant_id)
		 VALUES ($1, $2, $3, true, $4)
		 RETURNING id`,
		req.Username, hash, req.Role, tenantID,
	).Scan(&id)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/ -run TestCreateUser_ -v`
Expected: PASS.

- [ ] **Step 6: Full `internal/api` regression (existing `CreateUser` tests must still pass unmodified)**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/`
Expected: PASS. If any pre-existing `CreateUser`-related test now fails with "no caller identity"/"no tenant context", it's because that test calls the handler directly without going through `Middleware`/`withClaims` the way the real router does — locate it via the failure output and add the same `req.WithContext(auth.ContextWithClaims(...))` pattern Step 1 introduced, using a `default`-tenant, non-platform-admin token so the existing test's original intent (a regular admin creating a user) is preserved exactly.

- [ ] **Step 7: gofmt + vet + build**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -l internal/api/handlers.go internal/auth/middleware.go && go vet ./internal/api/ ./internal/auth/ && go build ./...`
Expected: no output, no errors, clean build.

- [ ] **Step 8: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/api/handlers.go internal/api/tenant_handlers_test.go internal/auth/middleware.go
git add -u internal/api/
git commit -m "feat(tenancy): CreateUser assigns users to a tenant

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

## Task 10: Full regression + capture

**Files:** none (verification + vault/memory).

- [ ] **Step 1: Full repo test suite**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./...`
Expected: PASS across every package — this is the definitive proof that the 34+5+8 mechanical `ALTER TABLE` additions (Tasks 2-4) didn't break any existing Docker-backed test anywhere in the repo (a broken migration statement fails `EnsureSchema`/`EnsureContentSchema`/`EnsureExerciseSchema` at container boot, which every Docker-backed test across every package depends on).

- [ ] **Step 2: Whole-build + vet**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 3: Update the vault (outside the git repo)**

The vault at `C:\Users\Administrator\Audspect-Vault` is NOT in the repo — update it directly, do not `git add` it.
- Create `04 Features/Multi-Tenancy.md` (feature note: MSSP model, two-tier users, shared-schema+RLS decision, what's proven vs. deferred, the `GenerateToken`-signature-preservation trick, the `set_config` vs. invalid `SET LOCAL ... = $1` catch).
- New ADR capturing the RLS-as-backstop enforcement decision and the "schema everywhere now, RLS proven in isolation, real enforcement deferred" sequencing call — this is a real architectural commitment worth the *why* surviving independent of chat history, same pattern as ADR-010.
- Edit `11 Roadmaps/Roadmap.md`: Phase 7's five sub-projects recorded (Multi-Tenancy in-progress — foundation done, full-rollout follow-up plan not yet scheduled; Identity & Access, Rate Limiting, HA & Scaling, Plugin Framework & SDK not started).
- Append to the current daily note: this session's work, the two scope negotiations (agents/findings ripple discovery, RLS-nowhere-yet decision), and the real bug/design catches (`SET` doesn't accept bind parameters; `GenerateToken`'s 21 call sites preserved via the additive-function pattern).

- [ ] **Step 4: Update Claude memory**

Edit `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\project_platform_roadmap_2026h2.md`: add Phase 7's five-sub-project breakdown; mark Multi-Tenancy's foundation done and explicitly flag the deferred full-rollout as the next piece of Phase 7 Multi-Tenancy work (not yet a separate scheduled item — needs its own brainstorm cycle when picked up, per this plan's own precedent). Update the `MEMORY.md` index line.

- [ ] **Step 5: Report completion**

Announce the feature is done, list the commits, and state plainly: **multi-tenancy is a foundation, not a finished feature** — no production handler enforces tenant isolation yet (`ListUsers`/`GetUser`/etc. are NOT tenant-filtered), and RLS is proven correct only against an isolated fixture table, never a real one. The follow-up plan (migrating `internal/api`'s ~24 handler files and the Phase 6 aggregator packages, table by table, enabling RLS as each is proven safe) is unscheduled and needs its own brainstorm cycle before it starts.

---

## Self-Review

**Spec coverage:**
- `tenants` table + `users.tenant_id` nullable-with-default → Task 1. ✓
- Data classification (13 global unscoped, 48 tenant-scoped across all three schema files) → Tasks 2-4. ✓
- `WithTenant` + RLS-as-backstop mechanism, proven correct → Task 5 (proven against a fixture table per the RLS-nowhere-yet scope negotiation — a deliberate, flagged narrowing of the spec's literal "prove it on agents+findings," reconciled with the user directly before writing this plan). ✓
- Tenant-aware JWT claims + `GenerateToken` signature preservation → Task 6. ✓
- Login wiring → Task 7. ✓
- Tenant-management API (`POST/GET /api/tenants`, `PATCH /api/tenants/{id}`), platform-admin-only via a new orthogonal middleware, RBAC-matrix drift coverage → Task 8. ✓
- Migration path for existing single-tenant installs (`DEFAULT 'default'` backfill everywhere) → Tasks 1-4, verified by Task 10's full-suite regression. ✓
- Error handling (missing tenant context rejected, not silently permissive) → Task 9's `CreateUser` switch statement's `default` case; Task 6's `RequirePlatformAdmin`. ✓
- Out of scope (SSO/SCIM/RBAC expansion, rate limiting, HA, plugin framework, billing, tenant branding, cross-tenant aggregate reporting, self-service signup) → none of these are touched by any task; explicitly restated in "Deliberately deferred." ✓
- Capture (vault feature note, new ADR, roadmap, daily note, memory) → Task 10. ✓

**Placeholder scan:** no TBD/TODO; every code step carries complete code; every command has an expected result. Task 7's test and seed helpers were grounded directly against the real `auth_handlers_test.go`/`testmain_test.go` (found via `grep`, read, and reused — `loginReq`, `seedUser`) rather than left for the implementer to discover. Task 8 Step 1 still includes a grounding *command* (not a guess) for the implementer to run immediately before editing `routes.go`, since that exact insertion point depends on file state this plan's author already read once but which could drift by execution time.

**Type consistency:** `Claims.TenantID *string` / `Claims.IsPlatformAdmin bool` (Task 6) used identically in Tasks 7, 8, 9. `auth.GenerateTenantToken`'s 6-arg signature is identical everywhere it's called (Tasks 6, 7 via `Login`, 8's test, 9's test). `db.WithTenant`'s 5-arg signature (Task 5) is not yet called by any later task in this plan (by design — no handler is migrated to it here) but is the exact signature the deferred follow-up plan will consume. `Tenant` struct (Task 8) fields match exactly between the handler and its test's `json.Unmarshal` target.

**Grounding corrections already applied (from reading real code before writing tasks, same discipline as every prior slice this session):** discovered `agents`/`findings` are consumed by 5+ non-`internal/api` packages, prompting the RLS-scope renegotiation with the user rather than silently either over- or under-building. Discovered `SET LOCAL ... = $1` is invalid SQL (not a bind-parameter-capable statement) — corrected to `set_config()`, the standard safe pattern, before it could become a runtime bug. Discovered `GenerateToken` has 21 existing call sites across 9 files — chose the additive-function pattern specifically to avoid touching any of them, rather than a signature-breaking change that would have cascaded far outside this plan's real scope. Discovered `internal/db` cannot import `internal/testutil` (import cycle) — resolved via Go's external `_test` package convention for Task 5's test file. Confirmed `TestRBACMatrix_NoDrift` is purely path/method-based (no tier-specific logic to account for). Confirmed exact table counts (34/5/8 = 47, plus `users` handled specially = 48) against real `grep` output of all three schema files, not estimated.
