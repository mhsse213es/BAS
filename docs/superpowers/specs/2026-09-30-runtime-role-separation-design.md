# Runtime Role Separation (bas_user / bas_app) Design

**Status:** Approved for planning
**Author:** investigation + design session, 2026-09-30
**Relates to:** C1 — MSSP Multi-Tenant Isolation Not Enforced (security review finding, GROUP C)

## Problem

The orchestrator connects to PostgreSQL as `bas_user` for everything — schema
bootstrap and all runtime traffic alike. `bas_user` is also the value of
`POSTGRES_USER` in `packaging/compose/docker-compose.yml`, which makes it the
Postgres **bootstrap role** (the role `initdb` creates when the official
Postgres image starts, always `oid=10`).

This was previously believed fixable by demoting `bas_user` at startup via
`internal/db/harden.go`'s `HardenRuntimeRole` (opt-in via
`BAS_DB_BREAKGLASS_PASSWORD`, `ALTER ROLE CURRENT_USER NOSUPERUSER
NOBYPASSRLS`). Two facts, both empirically verified against a real
`postgres:16-alpine` container matching the deployed image, rule that out:

1. **PostgreSQL 16 refuses to remove `SUPERUSER` from the bootstrap role,
   under any circumstances.** Verified two ways: `bas_user` demoting itself
   (`ALTER ROLE CURRENT_USER NOSUPERUSER NOBYPASSRLS`, exactly what
   `harden.go:78` runs) and a separate superuser (`bas_breakglass`, created
   moments earlier by the same code path) attempting `ALTER ROLE bas_user
   NOSUPERUSER NOBYPASSRLS` by name. Both fail identically:
   `permission denied to alter role — DETAIL: The bootstrap user must have
   the SUPERUSER attribute.` `cmd/server/main.go:275-277` wraps this call in
   `log.Fatalf`, so any operator who ever sets `BAS_DB_BREAKGLASS_PASSWORD`
   on a standard install would crash-loop the orchestrator forever — it can
   never reach a running state.
2. **Even a successfully non-superuser role that owns its own tables still
   bypasses RLS**, unless every table has `FORCE ROW LEVEL SECURITY` set
   individually. `internal/db/postgres.go:1269-1294` already has a dormant
   SP7 pilot (`CREATE POLICY tenant_isolation ON users`, created idempotently
   every boot) whose `ENABLE`/`FORCE ROW LEVEL SECURITY` lines are commented
   out, explicitly gated on the `bas_user` hardening this spec shows is
   impossible.

A full privilege audit of the DDL/DML surface run by `EnsureSchema` and the
six other `Ensure*Schema` functions (`EnsureContentSchema`, `EnsureIOCSchema`,
`EnsureIOCEnrichmentSchema`, `EnsureAgentGroupSchema`,
`EnsureAgentUninstallSchema`, `EnsureExerciseSchema` — all in
`orchestrator/internal/db/`) found that **none of it requires superuser**.
Every statement shape present (`CREATE TABLE`, `ALTER TABLE ADD COLUMN`,
`CREATE`/`DROP INDEX`, `CREATE EXTENSION "pgcrypto"`, `CREATE POLICY`,
`ALTER TABLE ... RENAME COLUMN`, seed `INSERT ... ON CONFLICT`, dedup
`DELETE ... USING`) was verified empirically to need only `CREATE` on the
database and on schema `public`, held by an ordinary role that owns what it
creates. `pgcrypto` is a *trusted* extension in PostgreSQL 16 — confirmed by
creating it successfully under a plain `NOSUPERUSER` role granted only
database-level `CREATE`.

This means the fix isn't "make demotion work" — it's "stop running the
application as the bootstrap role at all."

## Goals

- Give the orchestrator's normal runtime traffic a database identity
  (`bas_app`) that is unconditionally `NOSUPERUSER`/`NOBYPASSRLS` and owns no
  tables — a prerequisite RLS enforcement can safely build on later.
- Make it structurally hard for future code to acquire the privileged
  bootstrap connection for ordinary application work.
- Retire the `HardenRuntimeRole` mechanism, which is now both non-functional
  (root cause 1) and conceptually superseded (a role born non-superuser needs
  no runtime demotion).
- Fix `EnsureExerciseSchema`'s call-site ordering
  (`cmd/server/main.go:544`, currently *after* the old hardening call site at
  line 275 — already inconsistent with `harden.go`'s own documented
  contract).

## Explicit non-goals

- **No RLS activation.** `ENABLE`/`FORCE ROW LEVEL SECURITY` on `users` (or
  any other table) is not part of this change. The dormant SP7 policy
  creation may remain (it's inert without `ENABLE`), but stays inert.
- **No tenant-context audit.** `Login`/`ChangePassword`/bootstrap paths that
  query `users` without tenant context are a known, separate problem —
  turning on `FORCE ROW LEVEL SECURITY` before that audit would trade a
  security gap for an authentication outage.
- **No cross-tenant enforcement testing.** Follows from the above.

This is Phase 1 of two. Phase 2 (tenant-context audit, RLS activation,
cross-tenant isolation proof) is out of scope here and gets its own spec once
this phase has shipped and been verified in a real deployment.

## Architecture

```
                 PostgreSQL
                    │
        ┌───────────┴───────────┐
        │                       │
    bas_user                 bas_app
    bootstrap                runtime
    SUPERUSER                NOSUPERUSER
    schema owner             NOBYPASSRLS
        │                    owns nothing
        │                       │
        ↓                       ↓
DATABASE_ADMIN_URL        DATABASE_URL
        │                       │
        ↓                       ↓
schema/bootstrap          normal application
  (startup only)             (everything else)
```

`bas_user` keeps its existing role exactly as today (bootstrap, superuser,
owns every table it creates) — nothing about it changes. `bas_app` is new:
created with `NOSUPERUSER NOBYPASSRLS` **at role-creation time**, never
granted ownership of anything, granted only the DML it needs to operate.

## Credential handling

Two different kinds of secret, following two patterns this codebase already
uses (`packaging/compose/install.sh`):

- `DB_PASSWORD` (→ `bas_user`) stays exactly as today: operator-supplied,
  required in `setup.conf`/CLI args, install fails if missing
  (`install.sh:263`).
- `BAS_APP_DB_PASSWORD` (→ `bas_app`) is new, and follows the
  `JWT_SECRET`/`AGENT_SECRET` pattern instead
  (`install.sh:289-303`): auto-generated via `openssl rand -hex 32` when not
  already present, read from the existing deployed `.env` first on upgrade
  (never regenerated once set — regenerating would break `bas_app`'s stored
  password against the already-provisioned role), never operator-facing.

## Connection separation

Today there is one DSN, `DATABASE_URL`, built from `POSTGRES_USER`/
`POSTGRES_PASSWORD` (`docker-compose.yml:136`). This becomes two:

- **`DATABASE_URL`** → repointed to `bas_app`. This keeps the familiar name
  on the connection ordinary code is meant to use — the deliberate choice
  that makes accidentally grabbing the privileged connection *harder*, not
  easier.
- **`DATABASE_ADMIN_URL`** → new, `bas_user`, used only during the startup
  bootstrap phase. Never held by the application past startup; never passed
  to the long-lived runtime pool.

`config/config.go` changes, mirroring the existing `DatabaseURL string`
field (`config.go:12`) and its `Load()` wiring (`config.go:201-202`):

```go
DatabaseURL      string `json:"database_url"`       // bas_app — runtime pool
DatabaseAdminURL string `json:"database_admin_url"` // bas_user — bootstrap only
```

```go
if v := os.Getenv("DATABASE_ADMIN_URL"); v != "" {
    cfg.DatabaseAdminURL = v
}
```

Both are required at `Load()` (mirroring the existing
`database_url required` check at `config.go:365-366`) — the app cannot boot
without both connections available, since bootstrap always runs.

`docker-compose.yml` builds both DSNs from the container's Postgres
credentials:

```yaml
DATABASE_ADMIN_URL: "postgres://${POSTGRES_USER:-bas_user}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-bas_platform}?sslmode=prefer"
DATABASE_URL:       "postgres://bas_app:${BAS_APP_DB_PASSWORD}@postgres:5432/${POSTGRES_DB:-bas_platform}?sslmode=prefer"
```

## Startup sequence

```
1. Connect as bas_user (DATABASE_ADMIN_URL)
       ↓
2. Run EnsureSchema + all six other Ensure*Schema functions
   (EnsureExerciseSchema moves here — see "EnsureExerciseSchema ordering"
   below — no longer called later at cmd/server/main.go:544)
       ↓
3. Provision bas_app: idempotent CREATE ROLE IF NOT EXISTS-equivalent,
   sync its password from BAS_APP_DB_PASSWORD every boot (same idempotent
   "keep in sync" pattern harden.go:63-74 used for bas_breakglass)
       ↓
4. Grant bas_app its runtime privileges (idempotent GRANTs — see
   "Provisioning bas_app" below)
       ↓
5. Close the bootstrap (bas_user) connection
       ↓
6. Open the runtime pool as bas_app (DATABASE_URL)
       ↓
7. Assert runtime identity (see "Runtime identity assertion" below)
       ↓
8. Start HTTP/WS/application runtime, using only the bas_app pool from
   here on
```

### EnsureExerciseSchema ordering

`EnsureExerciseSchema` is currently called at `cmd/server/main.go:544`,
inside the Exercise Engine initialization block, well after the old
`HardenRuntimeRole` call site at line 275 — already violating
`harden.go`'s own documented contract ("MUST be called after all
superuser-requiring schema setup"). Under this design it moves next to the
other six `Ensure*Schema` calls (`cmd/server/main.go:251-268`), all running
against the bootstrap connection before step 3 above. The Exercise Engine
initialization at line 543 onward (`exStore := exercise.NewStore(pool)` etc.)
continues to run later, using the runtime (`bas_app`) pool like everything
else — only the schema call moves, not the store construction.

## Provisioning bas_app

Runs once per boot, idempotently, as part of step 3/4 above (a new function,
e.g. `db.EnsureAppRole`, in `internal/db/`, following the same idempotent,
`log`-observable style as `harden.go`):

```sql
-- Idempotent role creation
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bas_app') THEN
    CREATE ROLE bas_app LOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;

-- Password kept in sync every boot (mirrors harden.go:63-74's pattern for
-- bas_breakglass — format(%I, %L) escapes server-side, no bind params on
-- ALTER ROLE)
-- executed as: SELECT format('ALTER ROLE %I PASSWORD %L', 'bas_app', $1)

GRANT CONNECT ON DATABASE bas_platform TO bas_app;
GRANT USAGE ON SCHEMA public TO bas_app; -- no CREATE: verified below that
  -- bas_app never needs to issue DDL

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bas_app;
ALTER DEFAULT PRIVILEGES FOR ROLE bas_user IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bas_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bas_app;
ALTER DEFAULT PRIVILEGES FOR ROLE bas_user IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO bas_app;

-- audit_logs is documented as "immutable, append-only" (postgres.go:547-549)
-- — carve out UPDATE/DELETE at the DB layer for defense-in-depth, not just
-- app-code discipline:
REVOKE UPDATE, DELETE ON audit_logs FROM bas_app;
```

**Why a blanket `ALL TABLES IN SCHEMA public` grant, not a hand-enumerated
per-table list:** the codebase has 90+ tables across the schema functions and
grows continuously; a hand-maintained per-table GRANT list would silently
drift out of sync with every future `CREATE TABLE IF NOT EXISTS` added to any
of the seven `Ensure*Schema` functions. `ALTER DEFAULT PRIVILEGES` closes
that gap — any table `bas_user` creates from this point forward is
automatically covered, with no separate GRANT statement to remember. This is
deliberately **not** `GRANT ALL` (which would include `TRUNCATE`,
`REFERENCES`, `TRIGGER` — ownership-adjacent privileges `bas_app` has no
legitimate use for): it's an itemized `SELECT, INSERT, UPDATE, DELETE`,
matching exactly what ordinary application DML needs.

**Sequences need their own grant.** Verified empirically: table-level
`INSERT` privilege does **not** implicitly grant permission to call
`nextval()` on a `bigserial` column's backing sequence (`audit_logs`,
`agent_op_logs`, `agent_sec_logs`, `agent_telemetry` all use `bigserial`
primary keys). Without the sequence grant, every `INSERT` into one of these
tables fails with `permission denied for sequence ..._id_seq`. Confirmed
both failure and fix against a real container.

**No DDL privilege for bas_app.** Verified by grepping the full module for
`CREATE TABLE`/`CREATE EXTENSION`/`CREATE INDEX` outside the seven schema
files: the only matches are the schema files themselves (which run under
`bas_user`) and two test files exercising throwaway test-container schemas
under test credentials, not `bas_app`. No runtime code path issues DDL, so
`bas_app` gets `USAGE` on schema `public` only, never `CREATE` — strictly
less privilege than a first pass might grant defensively.

## Runtime identity assertion

Per explicit requirement: configuration alone is not proof. After step 6
above (opening the runtime pool as `bas_app`), before step 8 (starting the
application), assert the connected identity:

```go
var rolsuper, rolbypassrls bool
err := runtimePool.QueryRow(ctx,
    `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
).Scan(&rolsuper, &rolbypassrls)
if err != nil {
    log.Fatalf("[FATAL] runtime identity check: %v", err)
}
if rolsuper || rolbypassrls {
    log.Fatalf("[FATAL] runtime DB connection is privileged (rolsuper=%v rolbypassrls=%v) — "+
        "refusing to start the application on a bypassing identity", rolsuper, rolbypassrls)
}
```

This fails startup loudly and immediately if a future deployment or
configuration mistake ever points `DATABASE_URL` back at `bas_user` or any
other privileged role — the assertion is unconditional, not gated behind an
opt-in flag (unlike the old `HardenRuntimeRole`, whose opt-in nature was
itself part of why this problem went unnoticed).

## Retire HardenRuntimeRole

Remove entirely, not deprecate-in-place:

- `internal/db/harden.go` (the whole file — `HardenRuntimeRole`,
  `breakGlassRole` constant, `bas_breakglass` creation logic)
- `internal/db/harden_test.go` (or wherever its tests live)
- The `BAS_DB_BREAKGLASS_PASSWORD` config field (`config.go:66-67`),
  its env wiring (`config.go:204-205`), and its `Load()`-time handling
- The call site at `cmd/server/main.go:275-277`
- `BAS_CONFIRM_...`-adjacent references specific to break-glass hardening in
  `packaging/compose/docker-compose.yml`
- `install.sh`/documentation references to `BAS_DB_BREAKGLASS_PASSWORD`

**Upgrade tolerance:** an existing deployment's `.env` may already contain
`BAS_DB_BREAKGLASS_PASSWORD` (unlikely to be *set* to a non-empty value,
given it was never auto-generated and effectively unusable per root cause 1
— but the key may exist, empty or not). The installer/config loader must not
fail if it's present; either ignore it silently or strip it during upgrade.
No new installation depends on it.

## Upgrade path (existing deployments)

This must work against an already-populated database, not just a fresh one:

1. `install.sh`, on upgrade, generates `BAS_APP_DB_PASSWORD` if not already
   present in the existing `.env` (same priority-order as `JWT_SECRET`).
2. On the next boot, the bootstrap phase (steps 1-5 above) runs against the
   existing schema exactly as `EnsureSchema` already does today — every
   statement is `IF NOT EXISTS`/idempotent, so this is a no-op for existing
   tables and only provisions what's missing (`bas_app` itself, its grants).
3. `bas_app` must be fully provisioned and granted **before** the
   application switches to using `DATABASE_URL` as `bas_app` — steps 3-4
   must complete before step 6. This is already the natural order of the
   startup sequence above; call it out explicitly so an implementer doesn't
   reorder it for convenience.
4. No migration step drops or alters existing data. `bas_user` retains
   ownership of every existing table exactly as before — only a new,
   additional role is introduced.

## Testing

- Unit/integration: `db.EnsureAppRole` — role gets created idempotently,
  password syncs on repeat calls, grants are idempotent (running twice
  produces no errors).
- Integration: a fresh bootstrap-to-runtime boot sequence against a real
  Postgres container (matching this session's verification method) —
  `bas_app` ends up `rolsuper=false`, `rolbypassrls=false`, owns zero tables,
  and can successfully `SELECT`/`INSERT`/`UPDATE`/`DELETE` against a
  representative sample of tables from each of the seven schema functions,
  including a `bigserial`-keyed table (sequence grant) and `audit_logs`
  (confirming `INSERT`/`SELECT` succeed, `UPDATE`/`DELETE` are rejected).
- Integration: the runtime identity assertion actually fails startup when
  pointed at a superuser or `BYPASSRLS` role (regression test against a
  future accidental config mistake).
- Upgrade scenario: boot against a Postgres volume that already has the
  pre-this-change schema (created purely under `bas_user`, no `bas_app`
  existing yet) and confirm the app reaches a running state using only
  `bas_app` afterward.

## Acceptance criteria

- `bas_app.rolsuper = false`, `bas_app.rolbypassrls = false` (verified via
  `pg_roles`, both by test and by the startup assertion).
- `bas_app` owns zero tables (verified: `SELECT COUNT(*) FROM
  pg_tables WHERE tableowner = 'bas_app'` returns 0).
- The application's runtime pool never connects as `bas_user` after startup
  completes.
- `bas_user`'s schema/bootstrap operations (all seven `Ensure*Schema`
  functions) continue to succeed unchanged.
- `HardenRuntimeRole`, `harden.go`, and `BAS_DB_BREAKGLASS_PASSWORD` are
  fully removed from the codebase, config, and deployment artifacts.
- A fresh install and an upgrade of an existing deployment both reach a
  running application state using `bas_app` as the runtime identity.
