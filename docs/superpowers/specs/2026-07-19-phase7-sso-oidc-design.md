# Phase 7, Sub-project 2 (Identity & Access) — Part 2: SSO (OIDC) — Design

**Status:** approved
**Date:** 2026-07-19

## Context

Identity & Access has 3 independent pieces: RBAC expansion (done 2026-07-18/19, see `2026-07-18-phase7-rbac-permission-expansion-design.md`), SSO, and SCIM provisioning. SSO is next per explicit user choice, ahead of SCIM — SCIM typically auto-provisions identities that then log in *via* SSO, so building SCIM first would mean designing against a login mechanism that doesn't exist yet.

The platform's auth today is entirely local: `POST /api/auth/login` checks `username`/`password_hash` and mints a tenant-aware JWT via `auth.GenerateTenantToken` (built in the Multi-Tenancy slice). This spec adds OIDC as a second, parallel way to reach that same token-minting seam — SSO is additive, never a replacement for local login (no lockout risk, and platform-admin accounts — which don't belong to any single tenant — always keep local login as a break-glass path regardless of any tenant's SSO config).

## Decision

**OIDC only, per-tenant IdP configuration, JIT user provisioning, tenant-slug-based IdP discovery, real tenant-scoped query enforcement on the new config table.** Each decision below was made explicitly during brainstorming, not assumed:

- **OIDC, not SAML.** SAML requires XML signing/canonicalization and a much larger, higher-risk implementation. OIDC covers Entra ID, Okta, and self-hosted Keycloak/ADFS (modern versions) — the realistic IdP set for on-prem/air-gapped BFSI clients — with a fraction of the implementation and audit surface. SAML is explicitly deferred to its own future slice if a specific client's legacy ADFS-only setup requires it.
- **Per-tenant OIDC config**, not one platform-wide IdP. Matches the MSSP reality: each client organization brings their own identity source. Same architectural shape as the existing `siem_configs`/`ticketing_configs`/`detection_connectors` per-connector-config tables.
- **JIT (just-in-time) provisioning.** First successful SSO login creates the user row automatically if no matching account exists, with role from a per-tenant configurable default (not full IdP-group-to-role claim mapping — that's real scope for a future slice). Full lifecycle management (deprovisioning on offboarding, pre-provisioning, group sync) stays SCIM's job.
- **Tenant-slug URL discovery**, not email-domain lookup. `GET /login/{tenantSlug}/sso` — simple, no domain-ownership-verification concerns, matches how the platform already identifies tenants.
- **Real tenant-scoped query enforcement for `sso_configs`**, ahead of the rest of the still-deferred Multi-Tenancy rollout. Justified by blast radius: an SSO config row holds a client secret and defines who an IdP trusts as "this tenant" — a tenant-B admin reading or editing tenant-A's SSO config is a materially worse outcome than the same gap on, say, a ticketing config. This is a small, contained piece of real enforcement, not a reopening of the full-rollout scope decision from the Multi-Tenancy slice.

## Side-fix: `detection_connectors.tenant_id` naming collision

While grounding this spec's `sso_configs` table design against the existing connector-config tables, a real bug surfaced: `detection_connectors` (built in SP1, 2026-07-14) already had a `tenant_id text NOT NULL DEFAULT ''` column meaning **the Azure AD tenant ID** for that connector's OAuth (sits beside `client_id`/`client_secret`) — unrelated to Audspect's own multi-tenancy. Multi-Tenancy's Task 2 migration (`ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`) silently no-op'd on this table because the column already existed under `IF NOT EXISTS` — so `detection_connectors` never actually got Audspect's tenant-scoping column. This went undetected because the schema is unenforced everywhere (no test exercises the value), so nothing failed.

**Fix, folded into this slice's plan as a small contained side-task** (touches the same migration file this slice needs to edit anyway):
1. `ALTER TABLE detection_connectors RENAME COLUMN tenant_id TO azure_tenant_id` (preserves existing data, zero data loss).
2. Update the 3 SQL statements in `internal/api/detectverify_handlers.go` that reference the `tenant_id` column to reference `azure_tenant_id` instead.
3. Add the real `ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'` — now a genuine add, not a no-op, matching the pattern (no FK constraint) every other Multi-Tenancy-migrated table already uses.
4. **Go-side field/JSON names are unchanged** — `detectverify.Config.TenantID` and the `"tenantId"` JSON field stay as-is (package context already disambiguates; renaming them is unnecessary churn for a fix that's really about the DB schema layer, where the two different `tenant_id` concepts could otherwise land in the same row).

## Data model

**New table `sso_configs`** (`internal/db/postgres.go`, same file/section as the other connector-config tables):

```sql
CREATE TABLE IF NOT EXISTS sso_configs (
    id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id     text        NOT NULL REFERENCES tenants(id),
    issuer_url    text        NOT NULL,
    client_id     text        NOT NULL,
    client_secret text        NOT NULL,
    default_role  text        NOT NULL DEFAULT 'viewer',
    enabled       boolean     NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT NOW(),
    updated_at    timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id)
)
```

`UNIQUE (tenant_id)` — one OIDC config per tenant for this slice (matches "per-tenant config", not "per-tenant, multiple IdPs"; multi-IdP-per-tenant is unnecessary complexity not asked for). `client_secret` is masked in API responses (`***` placeholder, same convention as `UpdateDetectionConnector`/`UpdateTicketingConfig` — a request that doesn't change the secret must omit or send the mask value, never blank it out).

**`users` gains one column**: `ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source text NOT NULL DEFAULT 'local'` — `'local'` or `'sso'`. `Login` (password flow) rejects with the same generic "invalid credentials" message (no user-enumeration signal) if `auth_source = 'sso'`, in addition to the existing password check — explicit defense-in-depth rather than relying solely on an unguessable JIT-provisioned placeholder hash being impractical to brute-force.

## Login flow

**`internal/oidcauth`** (new package, mirrors the `internal/detectverify` connector-package shape): wraps `github.com/coreos/go-oidc/v3` (OIDC discovery + ID-token verification) and `golang.org/x/oauth2` (Authorization Code exchange) — both are the de facto standard, widely-audited Go libraries for this (used by Kubernetes itself among many others), and the first new external dependency added since `golang-jwt/jwt/v5`.

Two new **public** (unauthenticated) endpoints in `routes.go`, alongside the existing `/api/auth/login`:

- **`GET /login/{tenantSlug}/sso`** — resolves the tenant by slug, loads its `sso_configs` row (404 if missing or `enabled = false`), generates a PKCE code-verifier and a signed short-TTL `state` value (using the existing `golang-jwt` signing key — no new crypto primitive) encoding `{tenantID, codeVerifierHash, expiresAt}`, and redirects to the IdP's authorization endpoint.
- **`GET /api/auth/sso/callback`** — one shared URL for every tenant's IdP (standard OIDC practice; each tenant's IdP client registration points here, not to a per-tenant URL). Validates and decodes `state` (rejects if expired or the signature doesn't verify — CSRF protection), recovers the tenant ID and PKCE verifier, exchanges the authorization code for tokens via `go-oidc`, verifies the ID token (signature, issuer, audience, expiry), and extracts the `email` claim.

**User resolution**: `SELECT ... FROM users WHERE username = $1 AND tenant_id = $2` using the email claim. If found, proceed to login as that user regardless of whether the row was originally created locally or by a prior SSO login (deliberate "linking by email" — a client migrating from local accounts to SSO doesn't get duplicate identities for the same person). If not found, JIT-provision: `INSERT INTO users (username, tenant_id, role, auth_source, password_hash) VALUES ($email, $tenantID, $config.default_role, 'sso', $randomPlaceholder)`, where `$randomPlaceholder` is a cryptographically random value run through the existing `auth.HashPassword` (never actually used for verification — password login is already explicitly blocked by `auth_source = 'sso'`, this is belt-and-suspenders since the column is `NOT NULL`). Either path ends by minting a token through the **same `auth.GenerateTenantToken`** call `Login` already uses — every RBAC permission check and tenant-scoping mechanism built in the last two slices works on an SSO session unmodified.

## Admin API

Tenant-scoped CRUD, following the `ticketing_configs`/`detection_connectors` pattern:

- `GET /api/sso/config` — returns the caller's tenant's config (secret masked), or `404` if none configured.
- `POST /api/sso/config` — create (400 if one already exists for this tenant, matching `UNIQUE (tenant_id)`).
- `PUT /api/sso/config/{id}` — update; omitted/masked `client_secret` preserves the existing value.
- `DELETE /api/sso/config/{id}` — remove (existing SSO-provisioned users are unaffected — `auth_source = 'sso'` blocks their password login regardless of whether a config still exists, so deleting the config just stops new SSO logins, doesn't retroactively touch existing accounts).
- `POST /api/sso/config/{id}/test` — round-trips OIDC discovery against the configured issuer (`go-oidc`'s discovery call) without a full login, same shape as the existing connector "test" endpoints.

**Two new permissions** (`internal/auth/permissions.go`, following the RBAC-expansion slice's naming convention): `CanViewSSOConfig` (`"sso:config:view"`) and `CanManageSSOConfig` (`"sso:config:manage"`) — granted to Admin only (new capability, not a route that existed before the RBAC-expansion migration, so it doesn't inherit an existing Group A/B grant).

**Tenant-scoping enforcement**: every handler does `WHERE tenant_id = $callerTenant` explicitly, where `$callerTenant` comes from `claims.TenantID` (already on every tenant-user's JWT). Platform-admins (`claims.TenantID == nil`) pass an explicit `?tenantId=` query param instead, since they have no tenant of their own to scope against — mirroring how `CreateUser` already requires platform-admins to specify a target tenant explicitly.

## Testing strategy

- `internal/oidcauth`: unit tests against `go-oidc`'s local fake-provider test helper (no real IdP needed) — covers discovery, PKCE generation, state signing/validation (valid, expired, tampered, wrong-tenant), and ID-token verification (valid, wrong issuer, wrong audience, expired).
- `internal/api`: Docker-backed tests for the callback handler's user-resolution/JIT-provisioning logic (existing-user-linked-by-email, new-user-JIT-provisioned-with-tenant-default-role, disabled-config-rejected, wrong-tenant-state-rejected) and the admin CRUD endpoints (create/read/update/delete, secret masking, cross-tenant isolation — a tenant-B admin token must get 404/403 on tenant-A's config).
- RBAC-matrix coverage for the 2 new permissions, same `tierPermission` drift-detection mechanism as the 85-route migration.
- Full `internal/api` + `internal/auth` + `internal/detectverify` regression (the last one because of the side-fix) at the end, same rigor as every prior slice.

## Out of scope

- **SAML** — its own future slice.
- **Full IdP-group-to-role claim mapping** — only the flat per-tenant `default_role` setting from this slice; group-based mapping is real additional scope.
- **Single Log-Out (SLO) / RP-initiated logout** — logout stays local-JWT-invalidation only, same as today; no round-trip to the IdP to terminate its own session.
- **IdP-initiated login flow** — only SP-initiated (user starts at our tenant-slug URL); an IdP-initiated `POST` to our callback with no prior `state` is rejected, not supported as an alternate entry point.
- **Email-domain-based IdP discovery** — tenant-slug URL only.
- **Multiple IdPs per tenant** — `UNIQUE (tenant_id)` in the schema enforces exactly one.
- **SCIM provisioning** — the third piece of Identity & Access, separately scoped, not started.
