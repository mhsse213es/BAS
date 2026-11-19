# Customer authorization record (Phase 4, step 2)

Status: built and tested, including against a real PostgreSQL 16. Controlled execution remains **disabled**. No action is
classified Controlled, so no current run is affected. This record is permission to run within a defined scope. A separate
per-run approval is still required for each exact execution. Both are needed.

## Record

| Field | Meaning |
|---|---|
| `id` | `k8sa-…`, assigned by the server |
| `clusterId` | Registry ID of the cluster (must exist in `k8s_clusters`) |
| `customerRef` | ID of an **active tenant** in the `tenants` registry. Checked in the same statement that stores the record. Up to 128 characters, no control characters |
| `authorizedBy` | Administrator who created the record, from the authenticated identity |
| `authorizedAt` | Creation time (server clock) |
| `expiresAt` | Expiry. Must be in the future and at most 90 days after creation. A shorter expiry is always allowed |
| `scenarios` | Explicit list of action IDs from the action catalogue. At least one. No wildcards. Unknown IDs are rejected |
| `namespaces` | Explicit list of Kubernetes namespace names. At least one. No wildcards |
| `revokedAt`, `revokedBy` | Set once by revoke. A revoked record is never reactivated |

`state` is computed when read: `active`, `expired` (at or after `expiresAt`), or `revoked`.

Listing a scenario in a record does not make it executable. Only actions classified Controlled-eligible by step 3 can run.

## Schema and migration

Table `k8s_customer_authorizations`, created by `EnsureK8sAuthorizationSchema` at startup, after the cluster schema.
Idempotent (`CREATE TABLE IF NOT EXISTS`).

- `cluster_id` references `k8s_clusters(id)`, so a record cannot name an unregistered cluster.
- `CHECK (cardinality(scenarios) > 0)` and `CHECK (cardinality(namespaces) > 0)`: an empty list cannot be stored.
- `CHECK (expires_at > authorized_at)`.
- Index on `cluster_id`.
- No delete path in the store. Records are revoked, never removed.
- The runtime role receives the table's grants through the existing default privileges, so no change to role setup
  was needed.

## Atomicity: record and audit event

Creation and revocation each run in **one database transaction** that writes the change and its `audit_logs` row:

- **Create** (`InsertWithAudit`): the insert, guarded by `EXISTS (active tenant)`, and the creation audit row. If either
  fails, the transaction rolls back. The API then returns 500 and says nothing was recorded. There is never an active
  authorization without its creation event.
- **Revoke** (`RevokeWithAudit`): the conditional update and the revoke audit row. If the audit write fails, the record
  stays active.

The audit row is written by the same writer the scenario engine uses, through a shared interface that accepts either the
pool or a transaction. No separate outbox was needed, because the audit table is in the same database.

## API contract

All routes require `k8s-scenarios:approve` (administrator). Responses are JSON.

| Method | Path | Body / query | Success | Refusals |
|---|---|---|---|---|
| POST | `/api/k8s-scenarios/authorizations` | `{clusterId, customerRef, scenarios[], namespaces[], expiresAt}` | 201 record | 400 invalid scope, time, or customer (not an active tenant); 401 no identity; 403 cluster class does not allow Controlled; 404 unknown cluster; 500 not stored (nothing recorded); 503 not configured |
| GET | `/api/k8s-scenarios/authorizations` | optional `?clusterId=` | 200 list, newest first | 503 not configured |
| GET | `/api/k8s-scenarios/authorizations/{id}` | | 200 record | 404 |
| POST | `/api/k8s-scenarios/authorizations/{id}/revoke` | none | 200 record with `state: revoked` | 404; 409 already revoked; 401 no identity; 500 not revoked (nothing changed) |

Unknown JSON fields are refused (400).

## Enforcement

`enforceCustomerAuthorization` runs at two points:

1. **Plan** (`POST /api/k8s-scenarios/runs`): after the cluster is looked up by ID and the class check passes.
2. **Execute** (`POST /api/k8s-scenarios/runs/{id}/execute`): after the cluster is resolved by display name, and the class
   check passes. Execution re-checks, so a revocation made after planning takes effect.

For any profile other than `controlled` it does nothing. For `controlled` it requires an active record where the cluster
ID, the action ID and the namespace all match exactly. An empty record, an expired record, a revoked record, a missing
store, or a read error all deny. A denial returns 403 and writes a `k8s.authorization.denied` audit event. That event is
written on a best-effort basis, but the denial happens regardless of whether the event is recorded.

No action is classified Controlled yet (`controlledActions` is empty, and a test asserts this). The check is dormant until
step 3.

## Audit events

| Event | When | Fields | Outcome |
|---|---|---|---|
| `k8s.authorization.created` | in the creation transaction | requester, authorizationId, clusterId, cluster, customerRef, authorizedBy, scenarios, namespaces, expiresAt | ok |
| `k8s.authorization.revoked` | in the revoke transaction | same fields, with the revoking administrator as requester | ok |
| `k8s.authorization.denied` | a Controlled request is refused by enforcement | requester, clusterId, cluster, scenario, namespace, reason | denied |
| `k8s.profile.refused` | a profile is refused for the cluster's class | action, clusterId, class, profile, requester | denied |

Reads are not audited.

## Decisions (resolved in review)

1. **90-day maximum term.** Fixed cap. Shorter expiry is allowed.
2. **Scenario references.** Catalogue actions may be listed before step 3. Listing does not make an action executable.
   Unknown IDs are rejected at creation.
3. **Audit ordering.** Creation and revocation are transactional with their audit rows. A failed audit write means no
   change, so an authorization never exists without its creation event.
4. **`customerRef` is validated against the tenant registry.** It must name an active tenant. The `tenants` table
   already exists in the codebase (multi-tenancy phase), so no new customer source was introduced.
5. **Cluster ID on runs.** Approved for step 4. Not done in this step. Execution still resolves the cluster by display
   name, which is unique, and this is not used for authorization decisions beyond that lookup.

Open for later steps: revocation does not stop a run that is already executing (step 4, cancellation). The
`k8s.profile.refused` audit row in the plan path is still written after the refusal, not in a transaction with it.

## Tests

- `internal/k8sscenario/authorization_test.go`: validation (empty lists, wildcards, unknown or malformed names,
  duplicates, blank customer, expiry past or beyond 90 days, production refused); exact matching (other cluster, scenario,
  namespace, namespace prefix, empty lists, expiry boundary); revocation; state; and a test that no action is classified
  Controlled.
- `internal/api/k8sauthorizations_test.go`: create stores with its creation event; **an audit failure leaves no
  authorization**; an unknown tenant is refused; production and bad scope refused with nothing stored; identity required;
  revoke once, second revoke conflicts, revoker recorded; **an audit failure leaves the record active**; inspect and list
  with state and filtering; enforcement for non-Controlled (no-op), no record, mismatched namespace, revoked, exact match,
  and missing store (fail closed).
- `internal/db/k8s_authorizations_store_test.go`: **run against PostgreSQL 16 (passed).** Covers: a record and its event
  written together; a forced audit failure (a NUL byte, which `jsonb` rejects) leaves no record; unknown and suspended
  tenants store nothing; the database refuses an empty scope and an unregistered cluster; a revoke applies once; a forced
  revoke-audit failure leaves the record active.
- RBAC drift matrix updated for the four routes.
