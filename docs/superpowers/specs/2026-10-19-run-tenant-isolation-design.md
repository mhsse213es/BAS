# Run and Evidence Authorization — Design (revised)

Status: REVISED DRAFT for review. No schema or handler changes made yet.
Date: 2026-10-19
Supersedes: the earlier draft of this file (multi-tenant coordinated isolation).
Blocks: Phishing BAS existing-run grading and new dispatch
(`docs/phishing-mastery-qa-log.md`).

## 0. Two separate problems

The earlier draft treated two different problems as one. They are split here.

**Tier A — Installation security (current scope).** One Audspect installation
equals one customer equals one database. Users inside that installation have
roles: `admin`, `analyst` (views all reports), `viewer` (read-only, views reports
and agents) (`internal/auth/jwt.go:14-16`). The question is whether those roles
are enforced on every read, report, export and download path, and whether
ownership fields mislead anyone about what is authorized.

**Tier B — Shared-database multi-tenancy (future, deferred).** Several customers
on one database, or the planned MSSP mode. Deferred until it is an actual
requirement. Nothing in Tier A should introduce tenant columns, tenant scoping
or `audspect_tenant_id` for this purpose.

Separate databases isolate customers from each other. They do not stop an
unauthorized user inside one installation from reading runs, reports or
evidence. Tier A exists for that second problem.

## 1. Current state (verified in code)

**Role model is intentional.** `viewer` and `analyst` may read reports and
runs; `admin` manages users and config. Permission constants in
`internal/auth/permissions.go` gate most mutations (`CanRunScenario`,
`CanInjectExerciseEvidence`, `CanDeleteEvidence`, `CanExport`,
`CanViewVariantRun`, ...).

**Read paths and their gates are inconsistent.** Mutations are generally
permission-gated; many read paths are baseline-authenticated only. Confirmed
baseline-only reads, from `internal/api/routes.go`:

| Surface | Routes | Permission gate |
|---|---|---|
| Scenario runs | `GET /api/scenarios/runs`, `/{runId}/report`, `/report.json`, `/attackflow`, `/variant-coverage`, `/export` | baseline only |
| EmailGW runs | `GET /api/emailgw-runs`, `/summary`, `/{id}`; `GET /api/emailgw/metrics` | baseline only |
| Phishing runs | `GET /api/phishing-runs`, `/{id}`, `/{id}/report` | baseline only |
| Cloud runs | `GET /api/cloud-runs`, `/{id}` | baseline only |
| Exercise executions | `GET /api/exercises/executions`, `/{id}`, `/{id}/evidence`, `/evidence/verify`, `/events`, `/report.json` | baseline only |
| Evidence download | `GET /api/evidence/{id}/download` | baseline only |

**Open question for the Tier A audit:** whether `viewer` should be able to
download raw evidence and export run JSON, or only view rendered reports. The
existing `CanExport` permission suggests export is meant to be gated; the audit
must confirm the intent before tightening, and the answer decides whether the
change is a read-gate fix or no change at all.

**Ownership columns are misleading.** Tables with `tenant_id NOT NULL DEFAULT
'default'` (47 tables, `internal/db/postgres.go`) contain a value that no code
path uses for authorization. It is not proof of anything. Under Tier A the
correct treatment is to stop treating it as ownership, not to enforce it:
- Do not add tenant scoping predicates using it.
- Do not convert it to NULL or reassign it. In a single-tenant installation a
  `'default'` value is simply the installation, and converting it would hide
  historical runs from non-admin users with no security benefit.
- Document it as installation-scoped and leave the values in place.

**Row-level security is not active.** The only policy is on `users`, and it is
commented out pending a role-hardening follow-up (`internal/db/postgres.go:~1361`).
No database-level enforcement exists. Authorization is application-level only.

## 2. Tier A goals

1. Every read, report, export and download path enforces an explicit permission
   consistent with the role model. No route serves run or evidence data on
   baseline authentication alone if the data is sensitive.
2. Permission decisions are made from authenticated claims, never from
   request-supplied identifiers.
3. Child records (events, evidence, step executions, report artifacts,
   downloads) are authorized through their parent run's gate. Authorizing a
   parent must not leave a child endpoint open.
4. No new fabricated ownership. Existing `'default'` values remain as
   historical, installation-scoped data.
5. Each route in §1 has a negative test: a `viewer` can read reports but gets a
   denial for any route the audit classifies as mutation or raw-evidence access.

## 3. Tier A design

- Permission per surface, decided by the audit in §4 and recorded in the
  route matrix (`internal/api/rbac_matrix_test.go`), so `TestRBACMatrix_NoDrift`
  enforces it.
- Rendered report routes: `viewer` and up, matching the existing "viewer can
  view reports" role contract.
- Raw evidence download and run JSON export: gated by `CanExport` or a new
  dedicated permission, pending the §1 open question.
- Parent-derived gating for child endpoints: the child handler resolves the
  parent run and applies the same permission check. No child endpoint is
  reachable with a permission the parent does not require.
- No `tenant_id` predicates, no migration, no NULL conversion in Tier A.

## 4. Tier A audit (next step, read-only)

Before any change, classify every route under `/api/scenarios/runs`,
`/api/emailgw-runs`, `/api/phishing-runs`, `/api/cloud-runs`,
`/api/exercises/executions`, `/api/evidence`, and every report and export route,
as one of: rendered report, raw data, raw evidence, mutation, child record. Record
the intended permission for each and whether it is currently enforced. The
audit output becomes the implementation checklist.

## 5. Tier B (deferred, not in this change)

Recorded here so it is not forgotten, not built now:
- Shared-database multi-tenancy requires `tenant_id` ownership across the run
  family, creation-time assignment from claims, system-initiated run inheritance
  from verified triggering records, and database-level enforcement.
- Activating RLS needs the bas_user to NOSUPERUSER/NOBYPASSRLS role-hardening
  first (`internal/db/postgres.go:~1361`). Until then, RLS must not be described
  as defense in depth.
- The earlier draft's 47-table migration belongs here, not in Tier A.

## 6. Test plan (Tier A)

1. RBAC matrix: every route in §4's classification has an explicit tier; drift
   test passes.
2. Negative: `viewer` denied on each mutation and each raw-evidence/export route
   the audit classifies as gated; allowed on rendered reports.
3. Child records: a child endpoint returns the same denial as its parent for the
   same caller.
4. Claims: a request-supplied `tenantId` or similar field has no effect on the
   decision.
5. Regression: existing report and run list behavior for `analyst` and `admin`
   is unchanged.

## 7. Open decisions

1. Should `viewer` be able to download raw evidence and export run JSON? (§1)
2. Should a new dedicated permission (e.g. `CanViewRawEvidence`) be introduced
   for evidence download, or should `CanExport` cover it?
3. Confirm the Tier A / Tier B split: Tier A proceeds now, Tier B is deferred
   until an MSSP or shared-database requirement exists.

## 8. Sequencing

1. Approve this revised spec (§7).
2. Tier A audit (§4), read-only, written as a checklist in this spec.
3. Implement permission gates and route-matrix entries per surface, each with
   negative tests.
4. Verify with the full phishing-run suite and RBAC drift test.
5. Only then resume the phishing existing-run grader and new dispatch, which
   then sit on a consistently authorized foundation.

Until then, phishing grading and dispatch stay unregistered, and the eight
verified PH→EmailGW mappings remain groundwork.
