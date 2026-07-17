# Phase 7, Sub-project 1 — Multi-Tenancy (design)

**Date:** 2026-07-18
**Status:** approved
**Module:** Multi-Tenancy — first of Phase 7's five sub-projects (Multi-Tenancy, Identity & Access, API Rate Limiting, HA & Horizontal Scaling, Plugin Framework & Connector SDK), per `project_platform_roadmap_2026h2`. Chosen to go first because it's foundational: retrofitting tenant-scoping into Identity & Access (SSO/SCIM/RBAC) after the fact would be far more expensive than building the other way around.

## Problem
Phase 7 names eight items (multi-tenancy, RBAC expansion, SSO/SAML/OIDC, SCIM provisioning, HA, horizontal scaling, API rate limiting, plugin framework, connector SDK) — too large for one spec, the same shape of problem Phase 6 hit before it was decomposed into three subsystems. This spec covers the first of five sub-projects grouped by what's actually coupled: Multi-Tenancy, Identity & Access (SSO+SCIM+RBAC), API Rate Limiting, HA & Horizontal Scaling, Plugin Framework & Connector SDK.

Today, Audspect has **no multi-tenancy of any kind**. The `tenant_id` columns that already exist (`detection_connectors`, `siem_configs`) are Azure AD's own tenant ID for Sentinel/Defender authentication — an unrelated, external concept, not Audspect's own data isolation. The platform's deployment model is one dedicated on-prem/air-gapped install per client. An MSSP wanting to run Audspect centrally for multiple client organizations has no way to keep those clients' data apart within a single deployment.

## Decisions
1. **Tenant = separate client organization, MSSP/partner model.** One central Audspect deployment serves multiple distinct companies. This is different from — and not to be confused with — a single client wanting internal business-unit segmentation; that need, if it ever arises, can be modeled as a degenerate case of the same mechanism (a "tenant" that happens to be a division rather than a company) without a redesign.
2. **Two-tier user model: platform-admin + tenant users.** `users.tenant_id` becomes nullable: non-null is a regular tenant user, scoped entirely within their tenant and using the existing three-tier RBAC (viewer/analyst/admin) unchanged; `NULL` marks a platform-admin — the MSSP's own staff, who belong to no single tenant and can act as any tenant via an explicit switch. Platform-admin is an orthogonal flag, not a fourth RBAC tier — it answers "which tenant" not "what permission level."
3. **Isolation strategy: shared schema, row-level `tenant_id`, not schema-per-tenant or DB-per-tenant.** Schema-per-tenant would require dynamic schema-qualified SQL (a real injection-surface risk given this codebase's raw-SQL-with-placeholders style) and per-schema migrations. DB-per-tenant gives the strongest physical isolation but breaks cheap cross-tenant reporting for the platform-admin and is, in effect, indistinguishable from what an MSSP can already do today by running N separate Audspect installs — it doesn't justify new app-level work. Shared schema with a `tenant_id` column on every operational table is the smallest surgery on the existing single-`pgxpool.Pool`, raw-SQL architecture.
4. **Enforcement: Postgres Row-Level Security (RLS) as a database-level backstop, not application discipline alone.** A cross-tenant data leak in a BFSI/regulated-industry platform is a severe bug class, not a cosmetic one — relying purely on every handler remembering a `WHERE tenant_id` clause is not an acceptable guarantee. RLS policies enforce isolation even when a query is malformed or a filter is forgotten. This is a new pattern for the codebase (no RLS used today) but does not otherwise change the existing raw-SQL style.
5. **Content library stays global; operational data is tenant-scoped.** This is the same boundary the Threat Intel pipeline already established for bundled/seeded reference content (ATT&CK, ART, CVE/EPSS, OWASP) — extending it to tenancy rather than inventing a new one. A small number of tables sit at the boundary (`scenarios`, `scenario_techniques`, `exercise_templates`, `openaev_bundles`, `payload_families`) where "library item" and "tenant-owned instance" are both plausible; **default rule: bundled/seeded content stays global, anything created or cloned via the UI/API becomes tenant-owned.** Exact per-table classification for the boundary cases is finalized during planning, grounded against the real schema — not guessed here, consistent with every prior slice's practice.
6. **Migration for existing single-tenant client installs is additive, not disruptive.** A bootstrap `default` tenant plus `DEFAULT 'default'` on every new `tenant_id` column means an existing on-prem client's database upgrades with zero behavior change — they simply become a single-tenant instance whose one tenant happens to be id'd `default`, and never see any multi-tenant UI unless a platform-admin explicitly provisions a second tenant (unusual for a client's own dedicated install; this feature is really for the MSSP's own central instance).

## Architecture

### New table: `tenants`
```sql
CREATE TABLE IF NOT EXISTS tenants (
    id         text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name       text NOT NULL,
    slug       text NOT NULL UNIQUE,
    status     text NOT NULL DEFAULT 'active', -- active | suspended
    created_at timestamptz NOT NULL DEFAULT NOW()
)
```
Bootstrap row: `('default', 'Default Tenant', 'default', 'active', NOW())`, inserted by the migration alongside the `tenant_id` backfill.

### `users.tenant_id` becomes nullable
`ALTER TABLE users ALTER COLUMN tenant_id DROP NOT NULL` (only if the column doesn't already exist as such — `users` does not currently have a `tenant_id` column at all, so this is `ADD COLUMN tenant_id text REFERENCES tenants(id)`, nullable, no default). Existing users get backfilled to `'default'` as part of the same migration that backfills every other table, so no currently-authenticated user's access changes.

### Data classification
**Global, unscoped (13 tables, unambiguous)** — the existing TI-pipeline-managed catalog: `techniques`, `tactics`, `art_atomic_raw`, `art_atomic_tests`, `art_content_meta`, `art_payloads`, `cves`, `cve_epss`, `technique_cve_relationships`, `technique_cves`, `owasp_risks`, `technique_owasp`, `relationship_evidence`.

**Tenant-scoped, gets `tenant_id` (48 tables)** — everything else across `postgres.go`, `content_schema.go`, and `exercise_schema.go`: `agents`, `agent_op_logs`, `agent_sec_logs`, `agent_telemetry`, `attackpath_asset_tags`, `attackpath_collection_history`, `attackpath_collections`, `attackpath_jobs`, `attackpath_schedule`, `audit_logs`, `campaigns`, `campaign_variant_summary`, `compliance_snapshots`, `dashboard_snapshots`, `detection_connectors`, `finding_tickets`, `findings`, `openaev_config`, `openaev_scenarios`, `report_log`, `run_events`, `scenario_runs`, `scenario_variant_results`, `scenario_variant_technique_summary`, `siem_configs`, `siem_correlations`, `tamper_events`, `ticketing_configs`, `users`, `variant_findings`, `variant_run_steps`, `variant_runs`, `verification_evidence`, `verification_evidence_blob`, `verification_history`, `threat_readiness_history`, `exercise_events`, `exercise_evidence`, `exercise_executions`, `exercise_plans`, `exercise_step_executions`, `exercise_track_tokens`, `exercise_webhook_calls`, plus five boundary-case tables from Decision 5 (`scenarios`, `scenario_techniques`, `exercise_templates`, `openaev_bundles`, `payload_families`) whose exact global-vs-tenant split *within* the table (not whether the table gets the column — all five do) is finalized at planning time.

### Enforcement: RLS + session-scoped context
Every tenant-scoped table gets a policy:
```sql
ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON <table>
    USING (
        tenant_id = current_setting('app.tenant_id', true)
        OR current_setting('app.is_platform_admin', true) = 'true'
    );
```
`pgxpool` pools and reuses connections across requests, so there is no clean per-connection hook that maps to "one request." Instead, tenant-scoped handlers go through a single new wrapper — `internal/db` gains a `WithTenant(ctx, pool, fn func(tx pgx.Tx) error) error` helper (name finalized at planning) that opens a transaction, issues `SET LOCAL app.tenant_id = $1` and `SET LOCAL app.is_platform_admin = $2` (sourced from the request context's resolved auth claims), then runs the caller's queries inside that transaction. `SET LOCAL` is transaction-scoped, so it can't leak into a pooled connection's next, unrelated use — this is the standard safe pattern for RLS session variables under connection pooling. This is one seam that every tenant-scoped handler must be migrated through, not a change scattered ad hoc across ~48 tables' worth of call sites; the migration plan enumerates every handler file touching a tenant-scoped table.

### Auth & API
JWT gains two claims, resolved once at login from the `users` row: `tenant_id` (nullable) and `is_platform_admin` (bool). `internal/auth` middleware resolves both into the request context alongside the existing role-tier resolution; the two systems are orthogonal (RBAC tier still gates *what*, tenant context now gates *whose data*).

New endpoints, platform-admin only (new RBAC tier check, e.g. `tierPlatformAdmin`, distinct from `tierAdminOnly` which is a tenant's own admin):
- `POST /api/tenants` — create.
- `GET /api/tenants` — list all.
- `PATCH /api/tenants/{id}` — rename/suspend.

**Tenant switcher:** a platform-admin selects a tenant to act as; the server issues a short-lived, scoped follow-up token (or session field) carrying that tenant's id for the duration of the switch. Every downstream handler treats a "platform-admin acting as tenant X" request identically to a real tenant-X user's request — no handler needs a third code path for this case. Existing tenant-scoped endpoints need no shape changes; the `WithTenant` wrapper is where scoping happens, transparent to handler logic. Regular tenant users obviously see no switcher — their tenant is fixed at login.

## Error handling
- A request whose auth context has no resolvable `tenant_id` and is not a platform-admin is rejected (401/403) — never silently treated as "sees everything" or "sees nothing," since either is a security-relevant ambiguity in a multi-tenant system.
- A platform-admin who has not selected a tenant to act as gets an explicit "select a tenant" response from any tenant-scoped endpoint, not an empty or misleading result.
- A suspended tenant's users can't authenticate (checked at login, before a JWT with that `tenant_id` is ever issued).
- The RLS policy itself is the last line of defense: even a hand-written or malformed query against a tenant-scoped table without a `WHERE tenant_id` clause returns only the current session's tenant rows (or all rows, only for a verified platform-admin session) — never another tenant's data, regardless of application-layer bugs.

## Testing (TDD)
- **RLS isolation tests (Docker-backed, the centerpiece):** seed two tenants with overlapping data — e.g., two `agents` rows with the same hostname under different `tenant_id`s — then assert a session scoped to tenant A cannot retrieve tenant B's row **even via a deliberately unscoped raw query issued directly against the test connection**, proving enforcement lives in Postgres, not just in application code that happens to filter correctly.
- **Platform-admin bypass test:** the same seed, but a session with `app.is_platform_admin = 'true'` and no matching `tenant_id` can see both tenants' rows.
- **Migration/backfill test:** run the migration against a fixture representing an existing pre-multi-tenancy single-tenant install; assert every row backfills to `tenant_id = 'default'`, the `default` tenant row exists, and every existing (pre-migration) query pattern still returns the same results it did before — the single-tenant upgrade path must be provably behavior-preserving.
- **`WithTenant` wrapper unit/integration tests:** `SET LOCAL` scoping doesn't leak across transactions on a reused pooled connection (two sequential calls with different tenant contexts on the same underlying connection must not cross-contaminate).
- **Handler-level tests** extend the existing `testutil.MustSharedTestDB()` pattern with a tenant-aware seed helper, covering the new `/api/tenants` CRUD (platform-admin only — a tenant-scoped admin attempting these gets 403, mirroring the existing RBAC-matrix drift-test discipline) and the tenant-switcher flow end to end.
- Manual: browser spot-check of the tenant-switcher UI — flagged as a known gap in the plan, same honest gap every prior slice has carried (no browser tool available in this environment).

## Out of scope
Identity & Access — SSO/SAML/OIDC, SCIM provisioning, RBAC expansion beyond the existing three tiers (Phase 7's second sub-project, its own brainstorm cycle; tenant *identity* is a separate design from tenant *data isolation*, which is all this slice covers). API rate limiting, HA & horizontal scaling, plugin framework & connector SDK (separate Phase 7 sub-projects). Billing/metering. Tenant branding/theming. A cross-tenant aggregate-reporting UI for the platform-admin (switching into one tenant at a time is in scope; a roll-up dashboard across all tenants is a defensible fast-follow, not core to isolation). Tenant self-service signup — all tenants are platform-admin-provisioned only, consistent with an MSSP-operated model, no public signup flow. Internal business-unit segmentation for a single client's own dedicated install (Decision 1 — the same mechanism could support it later without a redesign, but it is not a driver for this slice).

## Capture
Vault: new `Multi-Tenancy` feature note under `04 Features`; new ADR for the RLS-as-backstop enforcement decision (a real architectural commitment future contributors will need the *why* for, same pattern as ADR-010's honesty stance); Roadmap Phase 7 gets its five-sub-project breakdown recorded with Multi-Tenancy marked in-progress; daily note. This spec's own scope-decomposition (naming all five Phase 7 sub-projects) should be captured in the roadmap regardless of how far this slice gets, so the next session doesn't have to re-derive the grouping.
