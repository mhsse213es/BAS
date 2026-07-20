# Multi-Tenancy Spec 2: Enable RLS on `users` — Design

**Date:** 2026-07-20
**Status:** approved (design), ready for planning
**Phase:** 7, Sub-project 1 (Multi-Tenancy) — first enforcing RLS wave
**Predecessors:**
- `docs/superpowers/specs/2026-07-18-phase7-multi-tenancy-design.md` (foundation)
- `docs/superpowers/specs/2026-07-19-multitenancy-users-pilot-design.md` (users pilot — app-layer scoping + dormant policy)
- `docs/superpowers/specs/2026-07-20-db-role-hardening-design.md` (Spec 1 — role demotion, the enforcement prerequisite)
- ADR-011.
**Successor:** later waves — remaining ~23 `internal/api` handlers + 5 Phase-6 aggregator packages migrate to `WithTenant`, one self-contained group per wave. NOT part of this spec.

## Purpose

The `users` pilot did two things: it tenant-scoped `ListUsers`/`UpdateUser`/`DeleteUser`
in the application layer (`WHERE tenant_id` inside `db.WithTenant`), and it created
a **dormant** `tenant_isolation` RLS policy on `users` — created but with
`ENABLE`/`FORCE ROW LEVEL SECURITY` left commented out, so Postgres never enforced it.
Spec 1 then demoted the runtime role to `NOSUPERUSER`/`NOBYPASSRLS` (opt-in, via
`BAS_DB_BREAKGLASS_PASSWORD`) so that RLS *can* enforce.

This spec flips the switch: it **enables RLS on `users`** and migrates the remaining
users-touching code paths to run inside `db.WithTenant`, so a tenant caller can only
ever see and mutate its own users — enforced by the database, not just by application
`WHERE` clauses. This is the first table where tenant isolation becomes a database
invariant rather than a coding convention.

Defense-in-depth is the whole point: the app-layer `WHERE tenant_id` from the pilot
stays. RLS is a second, independent wall so that a *missed* `WHERE` clause in any
current or future users-query leaks nothing — the database returns zero rows instead.

## Scope

**In scope**
1. Migrate every remaining `users`-touching code path to run its query inside
   `db.WithTenant` with the correct tenant context (inventory below).
2. Enable RLS on `users`: `EnsureSchema` flips the dormant policy to
   `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY`. Policy body unchanged.
3. Update the pilot's `TestUsersRLSPolicyDormant` to assert RLS is now **on**.
4. Add a non-superuser integration harness that proves isolation actually enforces
   (a superuser test connection would bypass RLS and hide a missed `WithTenant`).

**Non-goals (explicitly out)**
- **No RLS on any other table.** Only `users`. Other tables stay app-layer-only until
  their own waves.
- **No change to the username model.** `username` stays globally `UNIQUE NOT NULL`.
  (This is what makes the pre-auth Login lookup safe under platform-admin context —
  see below.)
- **No login-UX change.** The login form, token shape, and session flow are unchanged.
- **No new platform-admin-creation flow.** Bootstrap/seed paths keep working as-is,
  just wrapped in platform-admin context.
- **No change to the hardening opt-in.** RLS is inert on un-hardened installs
  (superuser bypass) and enforces once `BAS_DB_BREAKGLASS_PASSWORD` hardening is applied.
  This spec does not make hardening mandatory.

## Path inventory — what gets wrapped in `WithTenant`

Every path that reads or writes `users` must run inside `db.WithTenant(ctx, pool, tenantID, isPlatformAdmin, fn)`
or it will silently return/affect zero rows once RLS is forced. Grounding located these:

| Path | File | Tenant context | Rationale |
|---|---|---|---|
| `ListUsers` / `UpdateUser` / `DeleteUser` | `internal/api/handlers.go` | caller (`callerTenant`) | **Already done** in the pilot. |
| `Login` (username SELECT + password-upgrade UPDATE + last_login UPDATE) | `internal/api/handlers.go` | **platform-admin** (`"", true`) | Pre-auth system lookup — the caller has no tenant yet. Safe because `username` is globally UNIQUE, so the lookup resolves to exactly one row regardless of tenant. Issued token is still scoped to the user's own tenant. |
| `CreateUser` | `internal/api/handlers.go` | caller (`callerTenant`) | A tenant admin creates users in its own tenant; platform-admin can target any. |
| `ChangePassword` | `internal/api/handlers.go` | caller's tenant | Self-service; the row must be in the caller's tenant. |
| `ResetPassword` | `internal/api/handlers.go` | caller's tenant | Admin action within the caller's tenant. |
| SSO JIT provisioning (lookup + insert/update) | `internal/api/sso_login_handlers.go` | resolved tenant | The SSO connection resolves the tenant; JIT user is created/looked-up in it. |
| SCIM user CRUD | `internal/api/scim_handlers.go` | token tenant | SCIM bearer token is issued per-tenant; all CRUD scoped to it. |
| Startup bootstrap first-run seed | `internal/api/handlers.go` (COUNT/INSERT) | **platform-admin** (`"", true`) | Runs before any request context; seeds the `default` tenant admin. |
| `ensureAdminUser` startup seed | `cmd/server/main.go` | **platform-admin** (`"", true`) | Same — boot-time upsert of the default admin. |

`callerTenant(r)` (pilot helper) already returns `(tenantID, isPlatformAdmin)`:
platform-admin → cross-tenant; otherwise `claims.TenantID` or `'default'`.

## RLS enablement

The dormant policy from the pilot (in `internal/db/postgres.go`, guarded `DO $$…$$`)
stays byte-for-byte identical:

```sql
CREATE POLICY tenant_isolation ON users
  USING (
    tenant_id = current_setting('app.tenant_id', true)
    OR current_setting('app.is_platform_admin', true)::boolean
  );
```

- `USING` doubles as `WITH CHECK` when no separate `WITH CHECK` is given, so the same
  predicate governs reads, updates, and inserts. A tenant caller cannot write a row
  with someone else's `tenant_id`; platform-admin is the write escape hatch.
- What changes: `EnsureSchema` runs `ALTER TABLE users ENABLE ROW LEVEL SECURITY` and
  `ALTER TABLE users FORCE ROW LEVEL SECURITY`. `FORCE` is required because `bas_user`
  owns the table and table owners bypass RLS unless forced.
- **Inert until hardened.** On an un-hardened install `bas_user` is still a superuser
  and bypasses RLS entirely, so enabling the policy is a no-op there — no behavior
  change for clients who haven't opted into hardening. Once hardening is applied,
  the same schema enforces.
- Idempotent: `ENABLE`/`FORCE` are safe to re-run; the policy `CREATE` stays inside its
  existing `DO`-block existence guard.

## Login runs in platform-admin DB context

`Login` is a pre-authentication system lookup: it receives a username and must find the
user before any tenant is known. Under forced RLS a tenant-less query returns zero rows,
so Login would always fail. Two facts make platform-admin context the right, safe choice:

1. `username` is globally `UNIQUE` — the lookup resolves to exactly one row, so
   "search all tenants" cannot return an ambiguous or cross-tenant match.
2. The token minted from that row is still scoped to the user's own `tenant_id`
   (`GenerateTenantToken(id, role, tenantID, tenantID==nil, …)`), so every *subsequent*
   request is tenant-bound. Platform-admin context is confined to the credential check
   and the two bookkeeping UPDATEs (password-hash upgrade, last_login) on that same row.

No login-UX change results.

## Verification — non-superuser integration harness

**The core risk:** the existing app test suite connects as the Postgres superuser, which
bypasses RLS. A path with a *missing* `WithTenant` would still pass those tests but break
in hardened production. So the primary verification is an integration harness that connects
as a **non-superuser** role with RLS enforcing — the same conditions as hardened prod.

Harness shape (mirrors `internal/db` probe-pool patterns — `probePool`/`hardenProbePool`):
- Create a disposable role `users_rls_probe` — `NOSUPERUSER NOBYPASSRLS`, granted
  `SELECT/INSERT/UPDATE/DELETE` on `users` (and any sequences it needs).
- Build a `Handler` on a `pgxpool` connected as that role, against a schema where
  RLS is enabled+forced on `users`.
- Drive the real handlers end-to-end and assert isolation:
  - `Login` → issues a correctly tenant-scoped token (proves platform-admin Login works
    under RLS).
  - `CreateUser` in tenant A, then list/get as tenant B → not visible.
  - `ChangePassword` / `ResetPassword` targeting a row in another tenant → 404 / zero rows.
  - `ListUsers` / `UpdateUser` / `DeleteUser` cross-tenant → zero rows (regression guard
    over the pilot).
  - One SSO JIT path and one SCIM CRUD path exercised under the probe role.
- **Negative control:** temporarily strip one `WithTenant` wrapper in a throwaway check and
  confirm the harness catches it (documented in the plan, not shipped).

Plus:
- **No-regression:** the existing superuser suite keeps passing (proves the wrapping
  didn't break the default single-tenant `default` path).
- **Manual VM smoke:** deploy with `BAS_DB_BREAKGLASS_PASSWORD` set; confirm boot log
  "runtime role demoted…", then login / create user / list / run / report all work, and
  a second tenant cannot see the first's users.

All container-backed tests are Docker-gated (testcontainers) and run on the VM, not the
Windows build host.

## Risk & recovery

This is **auth-critical**: a mistake can lock users out of login. Mitigations:
- The non-superuser harness reproduces hardened-prod conditions, so a missed wrapper fails
  CI rather than prod.
- RLS is inert on un-hardened installs, so the blast radius at ship time is limited to
  installs that have explicitly opted into hardening.
- Break-glass recovery (from Spec 1) still applies: as `bas_breakglass`, run
  `ALTER ROLE bas_user SUPERUSER` (restores superuser bypass → RLS inert) or
  `ALTER TABLE users DISABLE ROW LEVEL SECURITY` to fully back the change out without a
  redeploy.

## Definition of done

- All inventory paths run inside `db.WithTenant` with the tenant context in the table above.
- `EnsureSchema` enables + forces RLS on `users`; policy body unchanged; idempotent.
- `TestUsersRLSPolicyDormant` updated to assert `relrowsecurity` **and**
  `relforcerowsecurity` are true (rename accordingly).
- Non-superuser integration harness passes on the VM; existing superuser suite still green.
- Manual VM smoke confirms login + isolation + break-glass recovery.
- Build / vet / gofmt clean on Windows.
