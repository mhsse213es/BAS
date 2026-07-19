# Phase 7, Sub-project 2 (Identity & Access) — Part 3: SCIM Provisioning Design

**Status:** Approved, pending spec review.

## Goal

Let a customer's IdP (Okta, Azure AD, OneLogin) push user lifecycle events to Audspect automatically via SCIM 2.0, so that removing someone from the IdP deprovisions them in Audspect immediately — instead of relying on SSO's reactive JIT provisioning, which only creates users on first login and never proactively deactivates anyone.

This is the third and final piece of Phase 7's Identity & Access sub-project, after [[RBAC Permission Expansion]] and [[SSO (OIDC)]].

## Decisions

- **Users only, no Groups.** SCIM 2.0 defines both User and Group resources. Audspect's role model is flat (viewer/analyst/admin) with no group concept to sync group membership into, and SSO didn't introduce one either. Implementing the Group resource would add real RFC 7644 surface with no consumer.
- **Per-tenant static bearer token**, not an OAuth flow. Matches how every mainstream IdP's SCIM app config actually works (paste a base URL + a static secret) — not how Audspect's own SSO login works, which is a different problem (interactive user login vs. machine-to-machine provisioning push).
- **Token-only tenant resolution, flat URL** (`/scim/v2/Users`, not `/scim/v2/{tenantSlug}/Users`). Matches RFC 7644's conventional URL shape that IdP SCIM clients often hardcode assumptions around; the bearer token itself resolves to a tenant via `scim_configs.token_hash`.
- **Soft-deactivate only, never hard-delete.** Both `DELETE /Users/{id}` and `PATCH {"active": false}` (the operation Okta/Azure AD actually send more often in practice) set `users.is_active = false` — the same flag `Login`/`SSOCallback` already enforce. No row is ever removed via SCIM; too many tables (`audit_logs`, `scenario_runs`, `findings`, `campaigns`) reference `users.id`.
- **Role source: tenant-wide default role**, same pattern as SSO's `sso_configs.default_role`. SCIM's core User schema has no role field (that's normally a Group-membership concern, which is out of scope here). `scim_configs.default_role` sets every SCIM-provisioned user's starting role; an admin can still change it afterward in Audspect's own Users UI.
- **Separate `scim_configs` table**, not folded into `sso_configs`. Different protocol, different auth mechanism (static bearer token vs. OIDC), different admin action (rotate a token vs. configure an IdP issuer) — matches the existing one-table-per-integration convention (`sso_configs`, `detection_connectors`, `ticketing_configs`).
- **Practical RFC 7644 compliance for Okta/Azure AD**, not full spec coverage. Discovery endpoints (`ServiceProviderConfig`/`ResourceTypes`/`Schemas` — both IdPs fetch these during SCIM app setup and refuse to proceed without them) + full User CRUD + the one filter shape both IdPs actually send (`userName eq "value"`, used to check-before-create) + `startIndex`/`count` pagination on list. No support for SCIM's fuller filter grammar (`co`, `sw`, `gt`, boolean expressions, complex-attribute filters) — no IdP sends those for a Users-only sync.
- **Bearer token stored hashed (SHA-256), shown once at creation/rotation.** Same UX as a GitHub/Stripe API key. A DB compromise doesn't hand over a live, usable SCIM credential. Lost token → rotate for a new one; there is no "recover the old value" path.

## Data Model

```sql
CREATE TABLE IF NOT EXISTS scim_configs (
    id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id     text        NOT NULL REFERENCES tenants(id),
    token_hash    text        NOT NULL,
    default_role  text        NOT NULL DEFAULT 'viewer',
    enabled       boolean     NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT NOW(),
    updated_at    timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id)
);
```

No new `users` column. SCIM-provisioned users get `auth_source = 'sso'` — the same "IdP-managed identity, not a local password" bucket SSO JIT-provisioned users already use. If a tenant runs SCIM without SSO configured, those users have no login path at all until an admin manually intervenes (resets to `auth_source='local'` and sets a password) — a safe-by-default outcome worth stating explicitly, not a gap to rediscover later.

## Auth Mechanism

A `scimAuth` middleware, entirely separate from the JWT chain:

1. Extract `Authorization: Bearer <token>`. Missing/malformed → `401`, SCIM-shaped error body.
2. Hash the presented token (SHA-256) and look up `scim_configs` by `token_hash`. No match, or `enabled=false` → `401` — a disabled config is treated identically to no token at all (fail closed).
3. On match, inject the resolved `tenantID` into the request context via a small dedicated context key (not `auth.Claims` — there's no user identity or role here, only a tenant), retrievable by the SCIM handlers the same way `auth.ClaimsFrom` works for JWT handlers.

This mirrors how agent-facing endpoints (`/api/agents/enroll`, `/api/heartbeat`) already sit outside the JWT/RBAC system on their own auth mechanism (`routes.go:32-43`).

## SCIM Protocol Coverage

| Endpoint | Method | Purpose |
|---|---|---|
| `/scim/v2/ServiceProviderConfig` | GET | Discovery — capabilities Audspect's SCIM implementation supports |
| `/scim/v2/ResourceTypes` | GET | Discovery — declares the User resource type |
| `/scim/v2/Schemas` | GET | Discovery — the User schema definition |
| `/scim/v2/Users` | POST | Create a user |
| `/scim/v2/Users` | GET | List users, with `filter=userName eq "..."` and `startIndex`/`count` pagination |
| `/scim/v2/Users/{id}` | GET | Fetch one user |
| `/scim/v2/Users/{id}` | PUT | Full replace |
| `/scim/v2/Users/{id}` | PATCH | Partial update — the operation IdPs use for `active: false/true` |
| `/scim/v2/Users/{id}` | DELETE | Deprovision — soft-deactivate, per the Decisions section |

## Data Flow

1. Tenant admin calls `POST /api/scim/config` (JWT-authenticated, `sso:...`-style permission-gated) → Audspect generates a random token, returns it in the response **exactly once**, stores only its hash.
2. Admin pastes the base URL (`https://<host>/scim/v2`) and token into their IdP's SCIM app config.
3. IdP performs discovery (`ServiceProviderConfig`/`ResourceTypes`/`Schemas`) before allowing the app config to be saved.
4. On each sync, before creating a user the IdP checks for an existing one via `GET /scim/v2/Users?filter=userName eq "person@example.com"`. If found, it `PATCH`es that resource instead — standard SCIM client behavior, so Audspect needs no special dedup logic beyond honoring the filter and a normal `UNIQUE(tenant_id, username)` constraint.
5. New assignment → `POST /scim/v2/Users` → row created with `scim_configs.default_role`, `auth_source='sso'`, `is_active=true`. A `POST` for a `userName` that already exists in the tenant (e.g. previously SSO-JIT-provisioned) correctly `409`s — the IdP was expected to have filtered first.
6. Unassignment/termination → `DELETE` or `PATCH {"active": false}` → `is_active = false`. Next login attempt (local or SSO) is rejected the same way a manually-deactivated user already is. Existing unexpired JWTs (24h TTL) remain valid until they expire — the same limitation every other deactivation path in Audspect has today, not a new gap introduced here.
7. Re-assignment → `PATCH {"active": true}` (or a fresh `POST`) flips it back on.

## Components & Files

- `orchestrator/internal/db/postgres.go` — `scim_configs` table (see Data Model).
- `orchestrator/internal/scim/` (new package):
  - `types.go` — SCIM resource JSON shapes (`User`, `ListResponse`, `Error`, `ServiceProviderConfig`, `ResourceType`, `Schema`), matching RFC 7644's wire format (`schemas` array, `meta`, etc.) exactly — IdPs validate this strictly.
  - `translate.go` — the only place SCIM's schema and Audspect's `users` table meet: SCIM User → Audspect fields and back.
  - `filter.go` — parses exactly the one supported shape (`userName eq "<value>"`); anything else returns a SCIM-shaped `400`, never a crash or a silently-empty result.
- `orchestrator/internal/api/scim_token.go` — token generation (`crypto/rand`) + SHA-256 hashing, shared by config creation/rotation and the auth middleware.
- `orchestrator/internal/api/scim_auth_middleware.go` — `scimAuth` (see Auth Mechanism).
- `orchestrator/internal/api/scim_handlers.go` — the RFC 7644 endpoints, reading tenant from `scimAuth`'s context.
- `orchestrator/internal/api/scim_config_handlers.go` — JWT-authenticated admin CRUD (`GetSCIMConfig`/`CreateSCIMConfig`/`RotateSCIMConfig`/`DeleteSCIMConfig`), same tenant-resolution pattern as SSO's `effectiveSSOTenantID`.
- `orchestrator/internal/auth/permissions.go` — 2 new Admin-only permissions: `CanViewSCIMConfig` (`"scim:config:view"`), `CanManageSCIMConfig` (`"scim:config:manage"`).
- `orchestrator/internal/api/routes.go` — `/scim/v2/*` mounted in its own `r.Group` with `scimAuth`, outside the JWT group; 4 new admin routes inside the existing JWT+permission-gated group.
- `orchestrator/internal/api/rbac_matrix_test.go` — 4 new `tierPermission` entries for the admin routes; `/scim/v2/*` added to `publicRoutes` (exempt from JWT-tier expectations, same treatment as `/api/agents/enroll` — authenticated by a different mechanism, tested separately).

## Error Handling

- Missing/invalid/disabled bearer token → `401`, RFC 7644 error body (`{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401","detail":"..."}`). Fails closed.
- Malformed SCIM payload (bad JSON, missing `userName`) → `400`, same error shape.
- `POST` with an already-existing `userName` for that tenant → `409` (correct SCIM semantics, not an error condition to prevent).
- Unknown `id` on `GET`/`PUT`/`PATCH`/`DELETE` → `404`.
- Unsupported filter expression → `400` with a clear `detail` — an IdP misconfiguration should be visible.
- Admin config API (`/api/scim/config`) uses Audspect's normal `jsonError` convention — it's JWT-authenticated, not part of the SCIM-error-shape surface.

## Testing Strategy

- `internal/scim` unit tests: `translate.go` round-trips; `filter.go` accepts the one supported shape and rejects everything else cleanly.
- Docker-backed handler tests (`sharedDB.RunWithPool`, same pattern as SSO):
  - Full lifecycle: create (verify `default_role`/`auth_source='sso'`/`is_active=true`), get by id, get by filter, `PATCH{active:false}`/`DELETE` deactivate (row still present), `PATCH{active:true}` reactivates.
  - Duplicate `userName` within a tenant → `409`.
  - Cross-tenant isolation (mirrors `TestSSOConfig_CrossTenantIsolation`): tenant A's token never sees/filters/deactivates tenant B's users.
  - Discovery endpoints return valid RFC-shaped JSON.
  - Auth failures (missing/wrong/disabled token) → `401`.
  - Admin config API: token returned once on create, hash-only thereafter; `Rotate` invalidates the old token and issues a new one; cross-tenant isolation on the config endpoints.
- `rbac_matrix_test.go`: 4 admin routes verified via the existing boundary/drift/method-confusion suite; `/scim/v2/*` excluded via `publicRoutes`.

## Out of Scope

- SCIM Group resource / group-to-role mapping.
- SCIM's fuller filter grammar (`co`/`sw`/`gt`/boolean expressions/complex-attribute filters) — only `userName eq "..."` is supported.
- OAuth-based SCIM authentication (bearer-token-only, per the Decisions section).
- Session/JWT revocation on deactivation — existing unexpired tokens remain valid until natural expiry, unchanged from every other deactivation path in Audspect today.
- Per-user role assignment via SCIM attributes or extensions — role comes solely from the tenant's `default_role`.
