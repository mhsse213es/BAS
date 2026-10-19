# Run and Evidence Tenant Isolation — Design

Status: DRAFT for review. No schema or handler changes made yet.
Date: 2026-10-19
Blocks: existing-run grading and new-dispatch integration for Phishing BAS (see `docs/phishing-mastery-qa-log.md`).

## 1. Current state (verified in code)

**Identity model.** `auth.Claims` carries `TenantID *string` and `IsPlatformAdmin bool`
(`internal/auth/jwt.go:19-30`). A nil `TenantID` means platform admin, but the
explicit `IsPlatformAdmin` flag is the authoritative signal and must be read as such.

**Tenant scoping exists only in some domains.** Users, SCIM configs and one
list query in `handlers.go` filter by `tenant_id` from the caller's claims.
Run and evidence domains do not.

**Run and evidence read paths ignore tenant ownership.** Confirmed for:

| Surface | Routes | Tenant filter |
|---|---|---|
| Scenario runs | `GET /api/scenarios/runs`, `/{runId}/report`, `/report.json`, `/attackflow`, `/variant-coverage`, `/export` | none |
| EmailGW runs | `GET /api/emailgw-runs`, `/summary`, `/{id}`; `GET /api/emailgw/metrics` (aggregate) | none |
| Phishing runs | `GET /api/phishing-runs`, `/{id}`, `/{id}/report` | none |
| Cloud runs | `GET /api/cloud-runs`, `/{id}` | none |
| Exercise executions | `GET /api/exercises/executions`, `/{id}`, `/{id}/evidence`, `/evidence/verify`, `/events`, `/report.json` | none |
| Evidence download | `GET /api/evidence/{id}/download` | none |

Any authenticated caller with the baseline read permission can read any run
and its evidence, regardless of which tenant created it. **This is a current
cross-tenant exposure, independent of the phishing work.**

**Existing `tenant_id` columns and their meaning differ:**

- `scenario_runs.tenant_id`, `run_events.tenant_id`, `report_log.tenant_id`,
  `payload_families.tenant_id`, `openaev_config.tenant_id` are all
  `NOT NULL DEFAULT 'default'` (`internal/db/postgres.go:~1316-1320`). No read
  path uses them for scoping. Their `'default'` value is **fabricated
  ownership** and must not be trusted or backfilled into authority.
- `cloud_runs.tenant_id` is the **cloud provider's** tenant (Azure AD tenant
  etc.), per `internal/db/cloudrun_store.go`. It is not Audspect's tenant.
- `email_gw_runs`, `phishing_runs`, `exercise_executions`, `evidence` tables
  have no tenant column.

**Tenant table.** `tenants(id, name, slug, status, created_at)` exists
(`internal/db/postgres.go:34`).

## 2. Target access model

| Row state | Access |
|---|---|
| `tenant_id IS NULL` (legacy, unknown ownership) | Platform administrators only |
| `tenant_id = T` | Callers whose authenticated scope is T; platform administrators with authorized admin access |
| `tenant_id` unresolved or invalid (references no tenant) | Denied to tenant callers; surfaced for remediation |

Rules:

1. **Scope comes from claims only.** A tenant identifier supplied in a request
   body, query string or path never widens scope. A tenant user's scope is
   always `claims.TenantID`.
2. **Platform admin is explicit.** Admin access requires `claims.IsPlatformAdmin`.
   A nil `TenantID` alone is not sufficient. Missing claims → deny.
3. **NULL is never unrestricted.** Every query that filters by scope must treat
   NULL as "platform admin only", enforced in the SQL predicate or the
   authorization layer, not in the UI.
4. **New runs.** A tenant user's run is assigned their claims tenant. A
   platform admin creating a tenant-owned run must name the tenant explicitly;
   a platform-wide operation (no tenant) is an explicit, separately named mode.
5. **Operator assignment.** Legacy rows are reassigned only by an explicit
   operator action (admin endpoint or CLI) that records who assigned what and
   when. No automatic backfill.

## 3. Schema and migration

Applied via the existing idempotent `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
pattern in `internal/db`, consistent with `EnsureEmailGWRunSchema` etc.

- `email_gw_runs`: `ADD COLUMN IF NOT EXISTS tenant_id text REFERENCES tenants(id)`
  (nullable, **no default**).
- `phishing_runs`: same.
- `cloud_runs`: add `audspect_tenant_id text REFERENCES tenants(id)` (nullable,
  no default). Leave the existing provider `tenant_id` column untouched and
  unrenamed.
- `scenario_runs`: **do not** reuse the existing `tenant_id DEFAULT 'default'`
  column for authority. Options, to decide (see §7): (a) drop the default and
  treat existing values as untrusted, or (b) add a new nullable column and
  deprecate the old one.
- `exercise_executions`: add nullable `tenant_id REFERENCES tenants(id)`.
- Child records: `exercise_evidence`, `exercise_events`, `exercise_step_executions`,
  `run_events`, plus any evidence download target. Each child either carries its
  parent's tenant via a join at read time (preferred, no duplication) or a
  denormalized column enforced by a trigger. **Decision needed (§7).**

**Backfill rule.** Existing rows get `tenant_id = NULL`. Nothing is assigned
automatically. After migration, rows are visible only to platform admins until
an operator assigns them.

**Constraints and indexes.**
- `REFERENCES tenants(id)` foreign keys on each new column (nullable FKs are
  allowed; NULL means unowned).
- `CREATE INDEX IF NOT EXISTS idx_<table>_tenant ON <table> (tenant_id)` for each
  scoped table; for `run_events` and evidence, indexes on the join key.
- Do not add `CHECK (tenant_id IS NOT NULL)`: legacy NULL rows must remain valid.

**Recovery.** The migration is additive (new nullable columns), so rollback is
dropping the new columns. Operator assignment is reversible by setting the
column back to NULL. Each assignment is audit-logged.

## 4. Query and authorization layer

- A single helper, e.g. `tenantScope(claims) (scope, error)`, returns one of:
  `Platform` (admin, all rows), `Tenant(T)` (exact match), or `Deny`. Every run
  handler calls it; none reads tenant from request input.
- SQL predicate for tenant callers: `tenant_id = $n` (never `tenant_id IS NULL
  OR ...`). For platform admins with no explicit filter: no predicate. NULL rows
  are returned only under `Platform`.
- Aggregates (`/api/emailgw/metrics`, `/api/emailgw-runs/summary`, factory
  analytics) must apply the same predicate, or be restricted to platform admins.
  Per-tenant aggregates are a follow-up, not a shortcut.
- Report and export paths (`/report`, `/report.json`, `/export`, evidence
  download) re-check scope on the parent row before rendering child data.
- Mutations (cancel, abort, approve, inject-evidence, verify) check scope on the
  target row, returning **404 not 403** for out-of-scope rows to avoid leaking
  existence.

## 5. Related records

A parent run being scoped is insufficient if child evidence is independently
retrievable. Every child endpoint (`/evidence`, `/evidence/verify`, `/events`,
`/evidence/{id}/download`) resolves the parent and enforces its scope first.
Evidence download by ID must not bypass the parent check.

## 6. Test plan (negative tests required)

For each surface in §1:

1. Tenant A caller cannot list Tenant B's runs.
2. Tenant A caller cannot retrieve, report, export, or read child evidence of
   Tenant B's run (expect 404).
3. Tenant A caller cannot cancel, abort, approve, inject into, or verify Tenant
   B's run (expect 404, no state change).
4. Platform admin can read Tenant A and Tenant B rows; NULL rows visible to
   platform admin only.
5. Tenant A caller cannot see NULL legacy rows.
6. Missing claims → 401; a tenant claim with an unknown or deleted tenant → deny.
7. A request body or query `tenant_id` that differs from claims is ignored (or
   rejected), and never widens scope.
8. Aggregates (metrics, summary) exclude other tenants' rows for tenant callers.
9. Migration: running `Ensure*Schema` twice is a no-op; existing rows become NULL.

Each test uses the real `sharedDB.RunWithPool` harness and real routes through
`mountTestRouter`, per the codebase convention.

## 7. Open decisions (for review)

1. **`scenario_runs` and the `'default'` columns.** Keep the `'default'` value
   as untrusted and ignore it, or change the default to NULL and migrate
   existing `'default'` values to NULL? Recommendation: change to NULL and
   reassign to NULL, since the value was never enforced.
2. **Child records: join or denormalize?** Recommendation: join to the parent
   at read time (single source of truth, no drift), with a trigger only if a
   child is ever queried without its parent.
3. **Platform-admin tenant selection.** The exact API shape (required
   `tenantId` on create vs. a separate platform-wide mode).
4. **Scope of this change.** The current cross-tenant read exposure exists for
   scenario runs and exercise data as well as the three phishing-adjacent
   tables. Recommendation: fix all surfaces in §1 in one coordinated change,
   since partial fixes leave child-record leaks.

## 8. Sequencing

1. Review and decide §7.
2. Schema migration (additive, idempotent) + `tenantScope` helper + unit tests.
3. Enforce scope on read paths, then mutations, then report/export, then child
   evidence, each with negative tests.
4. Operator assignment endpoint with audit log.
5. Only after 1–4 are verified: resume existing-run grading and new dispatch.

Until then, phishing grading and dispatch stay unregistered, and the eight
verified PH→EmailGW mappings remain groundwork only.

## 9. Scope finding (recorded before the migration slice)

- Every installation is its own database (confirmed 2026-10-19), so no currently
  shared database serves multiple customers. No emergency read restriction is
  required; the coordinated fix proceeds on its normal path. Tenant isolation
  remains required within one database for the planned MSSP mode.
- The `'default'` tenant column is not limited to the five tables in §7.1.
  `internal/db/postgres.go` adds `tenant_id text NOT NULL DEFAULT 'default'` to
  **47 operational tables**, including `agents`, `audit_logs`, `findings`,
  `campaigns`, `siem_configs`, `ticketing_configs`, and the `exercise_*` and
  `scenario_*` families. Converting all 47 to NULL would hide agents, audit
  logs and findings from every non-platform-admin user on every installation.
  **Decision needed:** convert only the run, evidence, report-artifact and
  child-record family, and classify the rest explicitly as a follow-up.
- Dropping the default changes behavior for every run-creating insert: a run
  created without an explicit tenant becomes NULL-owned and visible only to
  platform administrators. Insert sites to update, each assigning the tenant
  from authenticated claims: `scenario_runs` (`handlers.go`,
  `remediation_dispatch.go`, `variant_handlers.go`), `run_events`
  (`event_handlers.go`), `report_log` (`report_handlers.go`), `payload_families`
  (`variant_handlers.go`, `db/postgres.go`), `openaev_config`
  (`openaev_handlers.go`), `email_gw_runs` (`emailgwrun_store.go`),
  `phishing_runs` (`phishingrun_store.go`), `cloud_runs` (`cloudrun_store.go`),
  `exercise_executions` (`exercise/store.go`).
- **Operational impact on upgrade:** existing non-platform-admin users of an
  installation currently own their runs via the `'default'` tenant. After the
  NULL conversion, those users stop seeing their own historical runs until an
  operator reassigns them. The reassignment action must ship in the same change
  and be documented in upgrade notes.
