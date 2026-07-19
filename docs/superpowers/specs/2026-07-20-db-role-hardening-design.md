# DB-Role Hardening (Spec 1: role only, RLS stays off) — Design

**Date:** 2026-07-20
**Status:** approved (design), ready for planning
**Phase:** 7, Sub-project 1 (Multi-Tenancy) — enforcement prerequisite
**Predecessors:** `docs/superpowers/specs/2026-07-18-phase7-multi-tenancy-design.md` (foundation), `docs/superpowers/specs/2026-07-19-multitenancy-users-pilot-design.md` (users pilot), ADR-011.
**Successor:** Spec 2 (enable RLS on `users` + migrate the ~8 users-touching paths) — NOT part of this spec.

## Purpose

The orchestrator connects to Postgres as `bas_user`, which the official
`postgres:16-alpine` image provisions as the cluster's **only superuser** and
the **owner of every table** (all created by `EnsureSchema`). Postgres
superusers bypass Row-Level Security unconditionally, so RLS can never enforce
while the app connects as a superuser — exactly the trap ADR-011 flagged and
the `users` pilot deferred to.

This spec removes that blocker and nothing more: it makes the runtime role
`NOSUPERUSER`/`NOBYPASSRLS` so RLS *can* enforce in a later spec. **No RLS is
enabled on any table here.** Hardening the role is a real security win on its
own (it removes the superuser blast radius — an injection or bug can no longer
read `pg_authid`, touch other databases, or bypass RLS) and is safely
separable from the behavior-critical work of enabling RLS on `users`.

## Constraints that shape the design

- **Existing installs.** Postgres data lives in a named volume
  (`audspect-postgres-data`); client PROD already has `bas_user` as
  superuser+owner. Any change must apply in-place on an existing database, not
  only at fresh-volume init. There is no `docker-entrypoint-initdb.d` hook.
- **Last superuser.** With `POSTGRES_USER=bas_user`, the image creates no
  separate `postgres` role — `bas_user` is the only superuser. Demoting it
  naively leaves no role able to re-promote it except heavyweight single-user
  mode. Recoverability must be designed in.
- **`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`** runs every boot
  (`postgres.go:28`). It is superuser-gated but a no-op once installed, and
  pgcrypto is a *trusted* extension a database owner may install even when not a
  superuser.
- **Single connection.** The app uses one `pgxpool.Pool` from `DATABASE_URL`,
  runs `EnsureSchema` at startup, then serves. This spec does not change that.

## Design

### Opt-in gate

Hardening runs only when a new environment variable
**`BAS_DB_BREAKGLASS_PASSWORD`** is set and non-empty. When unset, the app skips
hardening entirely and logs a single line that hardening is available but
inactive.

Rationale: this makes the change **opt-in and non-surprising** — existing
deployments upgrade with zero behavior change until the operator deliberately
sets the variable, which also proves they hold the recovery credential before
any demotion happens. It is the only new configuration; `DATABASE_URL` is
unchanged.

### `db.HardenRuntimeRole(ctx, pool, breakGlassPassword string) error`

A new function in `internal/db`, called from `main.go` immediately after
`EnsureSchema` succeeds. It returns nil immediately when `breakGlassPassword`
is empty. Otherwise it performs, in order:

1. **Ensure the break-glass superuser.**
   - If `bas_breakglass` does not exist (`SELECT 1 FROM pg_roles WHERE rolname =
     'bas_breakglass'`), create it: `CREATE ROLE bas_breakglass LOGIN
     SUPERUSER`.
   - Always (re)set its password from the env var so the credential stays in
     sync with `.env`. The password is applied without string concatenation:
     ```
     SELECT format('ALTER ROLE bas_breakglass PASSWORD %L', $1)
     ```
     is run with the password bound as `$1`; `format(…, %L)` performs correct
     SQL literal escaping server-side, and the returned statement is then
     executed. This is the only safe way to set a dynamic role password
     (`CREATE`/`ALTER ROLE` accept no bind parameters directly).

2. **Guarded demotion of the runtime role.**
   - Read `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`.
   - If `current_user` is still a superuser, run
     `ALTER ROLE <current_user> NOSUPERUSER NOBYPASSRLS`. The role name is taken
     from `current_user` server-side (not interpolated from client input) and
     quoted with `quote_ident`.
   - If already not a superuser, this is a no-op — the function is idempotent
     across restarts.

   This runs as the **last** database step of startup. Even though a session's
   superuser status is re-evaluated after `ALTER ROLE … NOSUPERUSER`, nothing
   superuser-requiring runs after it in that boot, so mid-session demotion is
   harmless.

### Why every install path stays working

| Path | Fresh install (boot 1) | Existing install (first hardened boot) | Every later boot |
|---|---|---|---|
| `CREATE EXTENSION pgcrypto` | `bas_user` still superuser (demotion is last) → OK | already installed → `IF NOT EXISTS` no-op | already installed → no-op |
| `EnsureSchema` DDL | owner → OK | owner → OK | owner (non-super) → OK |
| Runtime DML/serving | owner → OK | owner → OK | owner (non-super) → OK |

`bas_user` remains the table **owner**, so it keeps every privilege on its own
objects with no GRANT management. (Because the owner still owns the RLS-target
tables, Spec 2 will need `FORCE ROW LEVEL SECURITY` — noted, out of scope here.)

### Recovery

If the demoted role misbehaves, an operator connects as `bas_breakglass`
(superuser) and runs `ALTER ROLE bas_user SUPERUSER` to restore the prior
state. This is documented in the spec and in `.env.example` next to the new
variable.

## Configuration changes

- `packaging/compose/.env.example`: add `BAS_DB_BREAKGLASS_PASSWORD=` (blank,
  commented with what it does and the recovery note).
- `packaging/compose/docker-compose.yml`: pass
  `BAS_DB_BREAKGLASS_PASSWORD: ${BAS_DB_BREAKGLASS_PASSWORD:-}` into the
  orchestrator service environment (mirrors the existing optional-var style).
- No change to `DATABASE_URL`, the postgres service, or any connection string.

## Testing

Container-backed, so Docker-gated (run on the VM; compile+vet only on the
Windows build host — the standing SP4/SP6 constraint).

1. **Demotes a disposable role.** Create a throwaway `LOGIN SUPERUSER` role,
   open a separate pool as it, call `HardenRuntimeRole` with a test password,
   and assert via `pg_roles` that the role is now `rolsuper=false`,
   `rolbypassrls=false`, and that `bas_breakglass` exists with `rolsuper=true`.
   Critically, the test operates on a **dedicated disposable role, never the
   harness's own connection role**, so it cannot demote the shared test
   container's superuser and break sibling tests (same discipline as
   `tenant_test.go`'s `rls_probe_user`).
2. **Idempotent.** A second `HardenRuntimeRole` call on the already-demoted role
   is a clean no-op (still `NOSUPERUSER`, no error).
3. **No-op when unconfigured.** `HardenRuntimeRole(ctx, pool, "")` returns nil
   and changes nothing.
4. **Manual VM verification.** Deploy with `BAS_DB_BREAKGLASS_PASSWORD` set;
   confirm the orchestrator boots and core flows (login, list users, run a
   scenario, render a report) work as the demoted role. Flagged in the daily
   note if not performed.

## Files touched

- Create: `orchestrator/internal/db/harden.go`
- Create: `orchestrator/internal/db/harden_test.go`
- Modify: `orchestrator/cmd/server/main.go` (read `BAS_DB_BREAKGLASS_PASSWORD`,
  call `HardenRuntimeRole` after `EnsureSchema`)
- Modify: `packaging/compose/docker-compose.yml`, `packaging/compose/.env.example`

## Explicit non-goals

- Enabling RLS or `FORCE ROW LEVEL SECURITY` on any table (Spec 2).
- The two-role owner/app split, GRANT or `ALTER DEFAULT PRIVILEGES` management.
- Any `DATABASE_URL` / runtime connection change.
- Migrating `Login`/`ChangePassword`/`ResetPassword`/`CreateUser`/SSO/SCIM/
  bootstrap to `WithTenant` (Spec 2).
- Rotating or vaulting the break-glass credential beyond reading it from env.

## Definition of done

- With `BAS_DB_BREAKGLASS_PASSWORD` set, the runtime role becomes
  `NOSUPERUSER`/`NOBYPASSRLS` on first hardened boot and the break-glass
  superuser exists; the app still boots and serves.
- With the variable unset, behavior is unchanged and a single informational log
  line notes hardening is inactive.
- `HardenRuntimeRole` is idempotent across restarts.
- New tests pass on a Docker-capable host; `go build ./...`, `go vet`, `gofmt`
  clean.
- Roadmap memory + vault updated: role hardening done, RLS-enable (Spec 2) is
  the next piece.
