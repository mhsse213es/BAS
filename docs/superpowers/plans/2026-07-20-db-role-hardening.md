# DB-Role Hardening Implementation Plan (Spec 1: role only)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in DB-role hardening that demotes the orchestrator's runtime Postgres role to `NOSUPERUSER`/`NOBYPASSRLS` (so RLS can enforce later) after creating a `bas_breakglass` recovery superuser. RLS is enabled on no table.

**Architecture:** New `db.HardenRuntimeRole(ctx, pool, breakGlassPassword)` called from `main.go` after schema setup. No-op when the password (from `BAS_DB_BREAKGLASS_PASSWORD`) is empty. Idempotent: a run short-circuits the moment `current_user` is already non-superuser, because a demoted role can no longer manage the break-glass superuser. Spec: `docs/superpowers/specs/2026-07-20-db-role-hardening-design.md`.

**Tech Stack:** Go (`internal/db`, `config`, `cmd/server`), Postgres, Docker Compose.

## Global Constraints
- **Docker-gated tests.** `harden_test.go` uses `sharedDB.RunWithPool` (real Postgres via testcontainers) and **cannot run on the Windows build host** (rootless Docker unsupported). Windows verifies with `go build ./...`, `go vet`, `gofmt -l`; the container tests run on the VM. Never claim a Docker test passed on Windows.
- **Never demote the harness's own role.** Tests demote a *disposable* `harden_probe` role via a dedicated pool (mirroring `tenant_test.go`'s `probePool`), never the shared container's connection — demoting the harness role would break every sibling test.
- Every task ends with `gofmt -l <touched files>` empty and `go build ./...` + `go vet ./internal/db/... ./config/...` clean.
- Run `cd`-relative commands from `orchestrator/`.
- Do NOT enable RLS/`FORCE` on any table, change `DATABASE_URL`, or add a second DB role (all Spec 2 / out of scope).

---

### Task 1: `db.HardenRuntimeRole` + tests (TDD)

**Files:**
- Create: `orchestrator/internal/db/harden.go`
- Create: `orchestrator/internal/db/harden_test.go`

**Interfaces:**
- Produces: `HardenRuntimeRole(ctx context.Context, pool *pgxpool.Pool, breakGlassPassword string) error`, called by `main.go` in Task 3.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/db/harden_test.go`:
```go
package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

// hardenProbePool creates a disposable LOGIN SUPERUSER role and returns a pool
// connected as it, so HardenRuntimeRole demotes THAT role, never the shared
// test container's own connection (which would break every sibling test).
// Mirrors tenant_test.go's probePool discipline.
func hardenProbePool(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	mustExec(t, admin, `DO $$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'harden_probe') THEN
			CREATE ROLE harden_probe LOGIN SUPERUSER PASSWORD 'harden_pw';
		END IF;
	END $$`)
	t.Cleanup(func() {
		// bas_breakglass is created by HardenRuntimeRole; drop both so the
		// shared container stays clean for other tests.
		_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS bas_breakglass`)
		_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS harden_probe`)
	})

	cfg := admin.Config().Copy()
	cfg.ConnConfig.User = "harden_probe"
	cfg.ConnConfig.Password = "harden_pw"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("harden probe pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestHardenRuntimeRole_DemotesAndCreatesBreakGlass(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		probe := hardenProbePool(t, pool)
		ctx := context.Background()

		if err := db.HardenRuntimeRole(ctx, probe, "break-glass-secret"); err != nil {
			t.Fatalf("HardenRuntimeRole: %v", err)
		}

		var rolsuper, rolbypassrls bool
		if err := pool.QueryRow(ctx,
			`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'harden_probe'`).Scan(&rolsuper, &rolbypassrls); err != nil {
			t.Fatalf("read harden_probe attrs: %v", err)
		}
		if rolsuper || rolbypassrls {
			t.Fatalf("harden_probe should be NOSUPERUSER/NOBYPASSRLS, got super=%v bypassrls=%v", rolsuper, rolbypassrls)
		}

		var bgSuper bool
		if err := pool.QueryRow(ctx,
			`SELECT rolsuper FROM pg_roles WHERE rolname = 'bas_breakglass'`).Scan(&bgSuper); err != nil {
			t.Fatalf("read bas_breakglass: %v", err)
		}
		if !bgSuper {
			t.Fatal("bas_breakglass should exist as a superuser")
		}

		// Idempotent: a second call on the already-demoted role is a clean no-op
		// (and must NOT error trying to manage break-glass without privilege).
		if err := db.HardenRuntimeRole(ctx, probe, "break-glass-secret"); err != nil {
			t.Fatalf("second HardenRuntimeRole (idempotent) errored: %v", err)
		}
		if err := pool.QueryRow(ctx,
			`SELECT rolsuper FROM pg_roles WHERE rolname = 'harden_probe'`).Scan(&rolsuper); err != nil {
			t.Fatalf("re-read harden_probe: %v", err)
		}
		if rolsuper {
			t.Fatal("harden_probe was re-promoted — not idempotent")
		}
	})
}

func TestHardenRuntimeRole_NoopWhenPasswordEmpty(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		// Empty password on the harness pool must be a pure no-op — it must NOT
		// demote the shared container's connecting superuser.
		if err := db.HardenRuntimeRole(ctx, pool, ""); err != nil {
			t.Fatalf("empty-password HardenRuntimeRole should be nil, got %v", err)
		}
		var rolsuper bool
		if err := pool.QueryRow(ctx,
			`SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&rolsuper); err != nil {
			t.Fatalf("read current_user: %v", err)
		}
		if !rolsuper {
			t.Fatal("empty-password call must not demote the connecting role")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

On a Docker host: `cd orchestrator && go test ./internal/db/... -run TestHardenRuntimeRole -v`
Expected: FAIL — `db.HardenRuntimeRole` undefined (compile error).
On Windows (no Docker): `cd orchestrator && go vet ./internal/db/...` → fails to compile for the same reason. That confirms the anchor before implementing.

- [ ] **Step 3: Implement `HardenRuntimeRole`**

Create `orchestrator/internal/db/harden.go`:
```go
package db

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// breakGlassRole is the emergency superuser created before the runtime role is
// demoted, so a superuser always remains to re-promote it if needed:
//
//	ALTER ROLE bas_user SUPERUSER;   -- run as bas_breakglass
const breakGlassRole = "bas_breakglass"

// HardenRuntimeRole demotes the current database role to NOSUPERUSER/NOBYPASSRLS
// so Row-Level Security can enforce against it, after first ensuring a
// break-glass superuser (breakGlassRole) exists for recovery.
//
// It is a no-op when breakGlassPassword is empty (hardening not opted into) and
// idempotent across restarts: once the runtime role is already non-superuser it
// can no longer manage the break-glass role anyway, so a repeat run short-
// circuits before touching anything.
//
// It MUST be called after all superuser-requiring schema setup (EnsureSchema),
// because ALTER ROLE ... NOSUPERUSER drops this session's superuser privileges.
func HardenRuntimeRole(ctx context.Context, pool *pgxpool.Pool, breakGlassPassword string) error {
	if breakGlassPassword == "" {
		log.Println("[db] role hardening inactive (BAS_DB_BREAKGLASS_PASSWORD unset) — runtime role unchanged")
		return nil
	}

	// Short-circuit if already hardened. This MUST come first: a demoted
	// (non-superuser) role cannot CREATE or ALTER the break-glass superuser, so
	// attempting those on a second run would error. Checking rolsuper up front
	// is what makes repeat runs clean no-ops.
	var isSuper bool
	if err := pool.QueryRow(ctx,
		`SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&isSuper); err != nil {
		return fmt.Errorf("check current_user superuser: %w", err)
	}
	if !isSuper {
		log.Println("[db] runtime role already NOSUPERUSER — hardening is a no-op")
		return nil
	}

	// Still a superuser → ensure the break-glass recovery superuser, then demote.

	// 1. Create the break-glass role if absent.
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)`, breakGlassRole).Scan(&exists); err != nil {
		return fmt.Errorf("check break-glass role: %w", err)
	}
	if !exists {
		if _, err := pool.Exec(ctx, `CREATE ROLE `+breakGlassRole+` LOGIN SUPERUSER`); err != nil {
			return fmt.Errorf("create break-glass role: %w", err)
		}
		log.Printf("[db] created break-glass superuser %q for RLS recovery", breakGlassRole)
	}

	// 2. Set its password from the env value, kept in sync each hardened boot.
	//    format(%I, %L) escapes the identifier and literal server-side —
	//    CREATE/ALTER ROLE take no bind parameters, so this is the safe path.
	var alterStmt string
	if err := pool.QueryRow(ctx,
		`SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text)`,
		breakGlassRole, breakGlassPassword).Scan(&alterStmt); err != nil {
		return fmt.Errorf("build break-glass password stmt: %w", err)
	}
	if _, err := pool.Exec(ctx, alterStmt); err != nil {
		return fmt.Errorf("set break-glass password: %w", err)
	}

	// 3. Demote the current (runtime) role — the last superuser-requiring step.
	//    CURRENT_USER is resolved server-side; no role name is interpolated.
	if _, err := pool.Exec(ctx, `ALTER ROLE CURRENT_USER NOSUPERUSER NOBYPASSRLS`); err != nil {
		return fmt.Errorf("demote runtime role: %w", err)
	}
	log.Println("[db] runtime role demoted to NOSUPERUSER/NOBYPASSRLS — RLS can now enforce once enabled")
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass (Docker host)**

Run: `cd orchestrator && go test ./internal/db/... -run TestHardenRuntimeRole -v`
Expected: PASS (both tests). On Windows, instead: `cd orchestrator && go vet ./internal/db/...` → compiles clean; defer the run to the VM and say so.

- [ ] **Step 5: Build, vet, format**

Run: `cd orchestrator && gofmt -l internal/db/harden.go internal/db/harden_test.go && go build ./internal/db/... && go vet ./internal/db/...`
Expected: no gofmt output; build/vet clean.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/db/harden.go orchestrator/internal/db/harden_test.go
git commit -m "feat(multitenancy): db.HardenRuntimeRole — opt-in NOSUPERUSER/NOBYPASSRLS demotion + break-glass"
```

---

### Task 2: Config field + env override

**Files:**
- Modify: `orchestrator/config/config.go` (`Config` struct + `Load` env overrides)

**Interfaces:**
- Produces: `cfg.DBBreakGlassPassword`, read by `main.go` in Task 3.

- [ ] **Step 1: Add the struct field**

In `orchestrator/config/config.go`, find:
```go
	// Air-gapped threat-intel: dir holding a signed ti-bundle.json (bundle floor;
	// live MISP/OpenCTI above overlay on top when configured).
	TIBundleDir string `json:"ti_bundle_dir,omitempty"`
}
```
Replace with:
```go
	// Air-gapped threat-intel: dir holding a signed ti-bundle.json (bundle floor;
	// live MISP/OpenCTI above overlay on top when configured).
	TIBundleDir string `json:"ti_bundle_dir,omitempty"`

	// DB role hardening (opt-in): when set, the orchestrator demotes its runtime
	// Postgres role to NOSUPERUSER/NOBYPASSRLS at startup (so RLS can enforce)
	// after creating a bas_breakglass recovery superuser with this password.
	// Unset = hardening inactive (default). Env: BAS_DB_BREAKGLASS_PASSWORD.
	DBBreakGlassPassword string `json:"db_breakglass_password,omitempty"`
}
```

- [ ] **Step 2: Add the env override**

In the same file, find:
```go
	if v := os.Getenv("DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}
```
Replace with:
```go
	if v := os.Getenv("DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}
	if v := os.Getenv("BAS_DB_BREAKGLASS_PASSWORD"); v != "" {
		cfg.DBBreakGlassPassword = v
	}
```

- [ ] **Step 3: Build, vet, format**

Run: `cd orchestrator && gofmt -l config/config.go && go build ./config/... && go vet ./config/...`
Expected: no gofmt output; build/vet clean.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/config/config.go
git commit -m "feat(multitenancy): add DBBreakGlassPassword config + BAS_DB_BREAKGLASS_PASSWORD env"
```

---

### Task 3: Wire hardening into startup

**Files:**
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `db.HardenRuntimeRole` (Task 1), `cfg.DBBreakGlassPassword` (Task 2).

- [ ] **Step 1: Call `HardenRuntimeRole` after schema setup**

In `orchestrator/cmd/server/main.go`, find:
```go
	if err := db.EnsureContentSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] content schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")
```
Replace with:
```go
	if err := db.EnsureContentSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] content schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")

	// ── DB role hardening (opt-in) ────────────────────────────────────────
	// Demote the runtime role to NOSUPERUSER/NOBYPASSRLS so RLS can enforce.
	// No-op unless BAS_DB_BREAKGLASS_PASSWORD is set. MUST run after all schema
	// DDL above — it drops this session's superuser privileges.
	if err := db.HardenRuntimeRole(context.Background(), pool, cfg.DBBreakGlassPassword); err != nil {
		log.Fatalf("[FATAL] db role hardening: %v", err)
	}
```

- [ ] **Step 2: Build, vet, format**

Run: `cd orchestrator && gofmt -l cmd/server/main.go && go build ./... && go vet ./cmd/...`
Expected: no gofmt output; whole-module build clean.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/cmd/server/main.go
git commit -m "feat(multitenancy): call HardenRuntimeRole after schema setup in startup"
```

---

### Task 4: Compose + .env plumbing

**Files:**
- Modify: `packaging/compose/docker-compose.yml`
- Modify: `packaging/compose/.env.example`

**Interfaces:**
- Consumes: `BAS_DB_BREAKGLASS_PASSWORD` (Task 2's env override).

- [ ] **Step 1: Pass the var into the orchestrator service**

In `packaging/compose/docker-compose.yml`, find:
```yaml
      JWT_SECRET:       ${JWT_SECRET}
      AGENT_SECRET:     ${AGENT_SECRET:-}
```
Replace with:
```yaml
      JWT_SECRET:       ${JWT_SECRET}
      AGENT_SECRET:     ${AGENT_SECRET:-}
      # DB role hardening (opt-in): set to a strong password to demote the
      # orchestrator's Postgres role to NOSUPERUSER/NOBYPASSRLS at startup and
      # create a `bas_breakglass` recovery superuser with this password. Blank =
      # inactive (role unchanged).
      BAS_DB_BREAKGLASS_PASSWORD: ${BAS_DB_BREAKGLASS_PASSWORD:-}
```

- [ ] **Step 2: Document the var in .env.example**

In `packaging/compose/.env.example`, find:
```
POSTGRES_PASSWORD=CHANGE_ME_STRONG_PASSWORD
```
Replace with:
```
POSTGRES_PASSWORD=CHANGE_ME_STRONG_PASSWORD

# Optional — DB role hardening. Set a strong password to demote the orchestrator's
# Postgres role (bas_user) to NOSUPERUSER/NOBYPASSRLS at startup so Row-Level
# Security can enforce, and to create a `bas_breakglass` recovery superuser with
# this password. Recovery: connect as bas_breakglass and run
#   ALTER ROLE bas_user SUPERUSER;
# Leave blank to keep hardening inactive (default).
BAS_DB_BREAKGLASS_PASSWORD=
```

- [ ] **Step 3: Sanity-check compose syntax**

Run: `cd packaging/compose && docker compose config >/dev/null && echo "compose OK"` (on a host with Docker Compose). If unavailable, visually confirm YAML indentation matches the surrounding `environment:` entries (6-space keys). Do not claim it validated if the tool wasn't run.

- [ ] **Step 4: Commit**

```bash
git add packaging/compose/docker-compose.yml packaging/compose/.env.example
git commit -m "feat(multitenancy): plumb BAS_DB_BREAKGLASS_PASSWORD through compose + .env.example"
```

---

### Task 5: Full validation + capture

**Files:**
- Modify (memory): `project_platform_roadmap_2026h2.md`
- Modify (vault, outside repo): daily note + `04 Features/Multi-Tenancy.md`

- [ ] **Step 1: Whole-module validation (Windows OK)**

Run:
```bash
cd orchestrator
gofmt -l internal/db/harden.go internal/db/harden_test.go config/config.go cmd/server/main.go
go build ./...
go vet ./internal/db/... ./config/... ./cmd/...
```
Expected: no gofmt output; build/vet clean.

- [ ] **Step 2: Container-backed run (Docker host / VM only)**

Run on the VM: `cd orchestrator && go test ./internal/db/... -run TestHardenRuntimeRole -v`
Expected: PASS. If Docker is unavailable where this runs, record it explicitly and defer to the VM — do not claim it passed.

- [ ] **Step 3: Manual VM smoke test (recommended)**

On the VM: deploy with `BAS_DB_BREAKGLASS_PASSWORD` set in `.env`, `docker compose up`, and confirm: the orchestrator boots ("runtime role demoted…" log line appears), login works, listing users / running a scenario / rendering a report all work as the now-demoted role, and a restart logs the idempotent "already NOSUPERUSER" no-op. Flag in the daily note if not performed.

- [ ] **Step 4: Update roadmap memory**

In `project_platform_roadmap_2026h2.md` (Multi-Tenancy section), record: DB-role hardening (Spec 1) done — commits, the opt-in `BAS_DB_BREAKGLASS_PASSWORD` gate, break-glass recovery role, RLS still off everywhere; next piece is Spec 2 (enable RLS on `users` + migrate the ~8 users-touching paths). Update the "Resume by" line to point at Spec 2.

- [ ] **Step 5: Vault capture**

Update (for user review) the daily note and `04 Features/Multi-Tenancy.md`: role hardening done, the opt-in/break-glass design, the idempotency-ordering detail, and the Docker-gated test status.

- [ ] **Step 6: Push**

```bash
git push
```

## Self-Review

- **Spec coverage:** opt-in gate → Task 2 (env) + Task 1 (empty-password no-op); break-glass creation + password → Task 1 Step 3 (1,2); guarded demotion → Task 1 Step 3 (short-circuit + step 3); startup wiring → Task 3; compose/.env → Task 4; tests (disposable role, idempotent, no-op) → Task 1 Step 1; recovery doc → Task 4 Step 2.
- **Placeholders:** none — every code step is complete.
- **Type consistency:** `HardenRuntimeRole(ctx context.Context, pool *pgxpool.Pool, breakGlassPassword string) error` defined in Task 1, called identically in Task 3; `cfg.DBBreakGlassPassword` field (Task 2) matches the call site (Task 3); `pool.Config().Copy()` + `cfg.ConnConfig.User/Password` + `pgxpool.NewWithConfig` mirror the proven `tenant_test.go` pattern.
- **Ordering safety:** the `rolsuper` short-circuit precedes any break-glass management, so repeat runs never attempt privileged ops without privilege; demotion is the final DB statement of startup.
