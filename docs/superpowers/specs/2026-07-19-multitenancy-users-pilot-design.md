# Multi-Tenancy `users`-Table Pilot — Design

**Date:** 2026-07-19
**Status:** approved (design), ready for planning
**Phase:** 7, Sub-project 1 (Multi-Tenancy) — first rollout wave
**Predecessor:** `docs/superpowers/specs/2026-07-18-phase7-multi-tenancy-design.md` (foundation), ADR-011 (RLS as enforcement backstop, not yet enforced)

## Purpose

The Multi-Tenancy foundation shipped the schema (`tenants` table, `tenant_id`
on ~48 tables), the `db.WithTenant` transaction seam, tenant-aware JWT claims,
and platform-admin middleware — but **no production handler enforces tenant
isolation yet**. This pilot is the first rollout wave: it makes the `users`
table's read/update/delete handlers tenant-aware, end-to-end, as the proven
pattern the remaining ~23 handlers and 5 aggregator packages will follow in
later waves.

`users` was chosen as the pilot because it is self-contained: none of the five
Phase-6 aggregator packages (`dashboard`, `exposure`, `predict`, `reporting`,
`ticketing`) query it, so enforcing isolation here cannot silently break them.

## The gap being closed

Three handlers in `orchestrator/internal/api/handlers.go` operate on `users`
with no tenant scoping whatsoever:

- **`ListUsers`** (`SELECT … FROM users ORDER BY created_at ASC`) — any
  Admin-tier user on any tenant sees every user across every tenant.
- **`UpdateUser`** (`UPDATE users SET … WHERE id = $2`) — a tenant admin can
  change the role or active-status of a user in *another* tenant by ID.
- **`DeleteUser`** (`DELETE FROM users WHERE id = $1`) — same cross-tenant
  reach for deletion.

`CreateUser` is already correctly tenant-scoped (from the foundation slice) and
is **not** touched by this pilot.

## Deliberately out of scope

- **DB-role hardening.** `bas_user` (the orchestrator's `DATABASE_URL` role,
  `POSTGRES_USER` in `packaging/compose/docker-compose.yml`) is the Postgres
  bootstrap superuser. Superusers bypass RLS unconditionally, so RLS cannot
  enforce in production until this role is changed to `NOSUPERUSER`/
  `NOBYPASSRLS`. That is its own deliberate follow-up (must first check whether
  anything — extensions, `EnsureSchema` DDL — needs superuser).
- **Enabling RLS.** See "RLS policy: written but dormant" below.
- **Login, SSO, SCIM, bootstrap, `ChangePassword`.** These also touch `users`
  but are either already tenant-scoped (SSO/SCIM) or must remain tenant-agnostic
  (Login queries by username with no tenant context). Untouched here.
- The other ~23 `internal/api` handlers and the 5 aggregator packages — later
  rollout waves, each proven safe before its RLS table is activated.

## Architecture — three prongs

### Tenant context derivation

Each of the three handlers derives its tenant context once, from the caller's
JWT claims (`auth.ClaimsFrom(r.Context())`, already populated by auth
middleware):

| Caller | `claims.IsPlatformAdmin` | `claims.TenantID` | Behaviour |
|---|---|---|---|
| Platform admin | `true` | `nil` | Cross-tenant: no `WHERE` filter; `WithTenant("", true)` |
| Tenant user | `false` | non-nil | Scoped: `WHERE tenant_id = *claims.TenantID`; `WithTenant(*claims.TenantID, false)` |
| Neither | — | — | `403` (defense-in-depth; should not occur post-auth) |

### Prong 1 — App-layer `WHERE tenant_id` filtering (real protection, live today)

This is the prong that actually enforces isolation in production **now**,
independent of RLS or the DB role.

- `ListUsers`: tenant users run `SELECT … FROM users WHERE tenant_id = $1
  ORDER BY created_at ASC`; platform admins run the existing unfiltered query.
- `UpdateUser` / `DeleteUser`: append `AND tenant_id = $N` to the statement's
  `WHERE` for tenant users, then inspect the command tag's `RowsAffected()`.
  Zero rows affected → `404 Not Found`. A cross-tenant target thus becomes
  indistinguishable from a nonexistent one (no information leak about other
  tenants' user IDs). This also repairs a latent bug: both handlers currently
  discard the `Exec` result — `DeleteUser` returns `204 No Content` even when it
  deleted nothing.

Self-modification guards already present in these handlers (cannot change own
role, cannot deactivate/delete own account) are preserved exactly.

### Prong 2 — `db.WithTenant` wrapping (forward-prep, inert today)

Each handler's database work runs inside:

```go
err := db.WithTenant(r.Context(), h.db, tenantID, isPlatformAdmin, func(tx pgx.Tx) error {
    // tx.Query / tx.Exec here
})
```

`h.db` is a `*pgxpool.Pool` (handlers.go:53), so this drops in directly.
`WithTenant` sets `app.tenant_id` and `app.is_platform_admin` as
transaction-local session variables. Today nothing reads them (RLS is off), so
this is functionally inert — its sole purpose is that when RLS is eventually
activated (with the role-hardening follow-up), these three handlers already
carry the correct session context and need **no second migration**.

### Prong 3 — RLS policy: written but dormant

In `orchestrator/internal/db/postgres.go`, alongside the existing
`attackpath_asset_tags`/schema DDL, add — idempotently, guarded by a `DO` block
that checks `pg_policies` so it is safe to run on every boot:

```sql
CREATE POLICY tenant_isolation ON users
  USING (
    tenant_id = current_setting('app.tenant_id', true)
    OR current_setting('app.is_platform_admin', true)::bool
  );
```

The `USING` clause uses `current_setting(…, true)` (the `true` = "missing_ok",
returns NULL instead of erroring when the variable is unset) so it never throws
for a connection that never called `WithTenant`.

**`ALTER TABLE users ENABLE ROW LEVEL SECURITY` is deliberately NOT executed** —
it is present only as a commented line with a comment block explaining that
activation is gated on the `bas_user` → `NOSUPERUSER`/`NOBYPASSRLS`
role-hardening follow-up, and that Login/`ChangePassword`/bootstrap must be
routed through a platform-admin `WithTenant` context *before* it is enabled
(otherwise Login's tenant-agnostic username lookup would match zero rows).

The policy is therefore real and reviewed, but enforces nothing until a future,
deliberate migration uncomments the `ENABLE` line. Creating a policy without
enabling RLS on the table has no runtime effect.

## Error handling

- Missing/!ok claims → `403` (no caller identity).
- `WithTenant`/query errors → `500` with the error message, matching the
  existing handlers' behaviour.
- Zero rows affected on update/delete → `404` (see Prong 1).
- Self-modification attempts → `400` (existing behaviour, unchanged).

## Testing

All tenant-isolation tests are container-backed (`sharedDB.RunWithPool`, real
Postgres via testcontainers) and live in
`orchestrator/internal/api/user_handlers_test.go`. **These require Docker and
cannot run on the Windows build host** (rootless Docker unsupported) — they must
be verified on a Docker-capable Linux host (the VM), the same known constraint
SP4/SP6/the detection connectors hit.

Test cases:

1. **`ListUsers` scopes to caller's tenant** — seed users in tenant A and
   tenant B; a tenant-A admin's `ListUsers` returns only tenant-A users.
2. **`ListUsers` platform-admin sees all** — a platform admin (nil tenant)
   sees users from every tenant.
3. **`UpdateUser` cross-tenant → 404 + no mutation** — tenant-A admin targets a
   tenant-B user's ID; response is `404` and the tenant-B user's role/active
   status is unchanged in the DB.
4. **`DeleteUser` cross-tenant → 404 + row survives** — tenant-A admin targets a
   tenant-B user's ID; response is `404` and the row still exists.
5. **Same-tenant update/delete still works** — tenant-A admin acts on a tenant-A
   user successfully (regression guard so the tenant predicate doesn't over-block).
6. **RLS-stays-dormant guardrail** — assert `pg_class.relrowsecurity = false`
   for `users` (RLS is NOT enabled) *and* that the `tenant_isolation` policy row
   exists in `pg_policies`. Prevents an accidental future activation from
   slipping in unnoticed through this pilot.
7. **Existing guards intact** — the self-role-change and self-delete tests
   already in `user_handlers_test.go` continue to pass unchanged.

## Files touched

- `orchestrator/internal/api/handlers.go` — `ListUsers`, `UpdateUser`,
  `DeleteUser` (Prongs 1 + 2).
- `orchestrator/internal/db/postgres.go` — dormant RLS policy (Prong 3).
- `orchestrator/internal/api/user_handlers_test.go` — new isolation tests.

No UI change (the Users admin panel already renders whatever `ListUsers`
returns), no API-shape change (same request/response JSON), no new dependency.

## Definition of done

- All three handlers filter by tenant for tenant users and remain unfiltered for
  platform admins.
- Cross-tenant update/delete returns `404` with no mutation.
- The dormant policy exists; RLS remains disabled on `users`.
- New tests pass on a Docker-capable host; `go build ./...` and `go vet ./...`
  clean; `gofmt` clean.
- Roadmap memory + vault updated: this pilot done, remaining waves still pending.
