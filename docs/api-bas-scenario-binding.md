# API BAS scenario binding

Status: first tranche, 9 November 2026. Code: `orchestrator/internal/apibas/binding`, `runner.NoState`, route
`POST /api/apibas/targets/{id}/binding/plan`. Builds on [OpenAPI import and inventory](api-bas-openapi-import.md).

## Why

Catalogue scenarios are written against the lab's routes and fixtures. A customer's API has other routes, so an imported
inventory lists the API but cannot assess it. Binding writes concrete scenarios from an inventory operation, identities the
customer supplies credentials for, and objects each identity owns.

## What it does

Given an inventory and test data (`Spec`), `binding.Bind` generates, for each object-level `GET` operation that has objects owned by
two or more identities, one cross-identity read scenario per object: the owner reads their object (baseline), another identity
requests the same object (attack). It also builds the fixture the runner needs. Each scenario passes `contract.Scenario.Validate`,
is `READ_ONLY`, takes an id from `API-BAS-AUTHZ-901` to `999`, and is graded by the existing grader: the attack must be refused
(403 or 404) and return none of the protected values the customer supplied.

The plan also lists every object-level operation it did **not** bind, with the reason, and the limits of what a bound result means.

The preview route returns that plan for the target's stored inventory. It stores nothing, starts no job, contacts nothing, and
receives only credential *names*.

## What it does not do

- **No write operations.** A change to state needs an independent check that state did not change, and a customer's API offers
  none. `runner.NoState` returns an empty snapshot, so it can never show a change; the runner refuses to run any scenario that is not
  `READ_ONLY` with it (tested). Write operations are reported as skipped.
- **Response evidence only.** A pass proves the attack was refused and leaked none of the protected values supplied. It cannot see a
  leak of a value the customer did not supply, and says nothing about other objects, roles or parameters.
- Running a plan as a job is covered in "Running stored test data as a job" below.
- No function-level, property-level, data-exposure, resource or SSRF binding. List endpoints and multi-step flows are not bound.
- No detection and no regulatory mapping on bound scenarios.

## Safety

- Path parameter values are limited to `[A-Za-z0-9._~-]`, 1 to 128 characters, so a value cannot add a segment, a query or a
  traversal. Identity names and credential references are validated; two identities may not share a credential.
- Protected values are 4 to 200 characters on one line (the contract's distinctiveness rule).
- The binder never sees a credential value, reads no database and uses no network.
- At most 99 scenarios per plan.

## Calls made (the owner delegated design calls; change if wrong)

1. Read-only object-level only, because that is the one class gradable honestly without target-side state.
2. The attacker is the first other identity (by name) that owns an object on the same operation, so it is a real user of that route.
3. The preview uses the existing "view API BAS" permission since it changes nothing.
4. Bound ids use 901-999 so they cannot collide with the catalogue.

## Next steps

1. (Done) Persist a binding spec on a target, and run it through the orchestrator's job path.
2. Console: store, run and show bound jobs (the page still previews typed data only).
3. A target-side state check (a customer-provided read endpoint) so write operations can be bound.


## Stored test data (added 10 November 2026)

A target keeps one binding spec, so the test data is entered once. Table `apibas_target_bindings` (one row per target, removed with the
target), routes `PUT|GET|DELETE /api/apibas/targets/{id}/binding`, all requiring the manage-targets permission.

- **Saving validates.** The spec is bound against the newest inventory before it is stored; a spec that does not bind (unknown owner,
  bad path value, unknown operation, shared credential, unknown field) is refused and nothing changes. The inventory version it was
  checked against is stored.
- **Stale is reported, not hidden.** If a newer inventory has been imported since, `GET` returns `stale: true` with both versions.
  The spec is not re-validated or edited automatically; saving it again re-checks it against the newest inventory.
- **Reading needs the manage permission**, not the view permission, because the protected values can themselves be sensitive
  (a name, an address). The preview route still needs only view.
- **Preview from stored data:** `POST .../binding/plan` with an empty body uses the stored spec; with a body it previews that
  body without storing it. With neither it answers 400 saying so.
- **Audit** records `apibas.binding.save` (inventory version, counts of identities, objects, scenarios, skipped) and
  `apibas.binding.delete`. It never records names or values.
- Credential values are still never stored; the spec holds credential names only.

Not built: history of spec versions (saving replaces), and editing in the console (the page still previews a spec typed into it).

## Running stored test data as a job (added 10 November 2026)

`POST /api/apibas/targets/{id}/binding/jobs` with `{"key": "...", "approval_id": "..."}` (the run permission, like any job). It queues a
job from the target's stored test data and newest inventory and starts it in the background, through the same submission path as other
jobs: the target must be enabled, its environment permitted (production stays refused in this release), its host registered, only one
active job per target, and an approval for production. The caller chooses only the key; scenarios, fixture, credentials and scope come
from the target, its inventory and its stored test data.

- **Scenarios are generated, not catalogued.** The job's scenario ids are the bound ids (901 and up) and its fixture is
  `bound:<sha256 of the plan>`. The plan is the inventory and test data as they were at submission; it is stored with the job
  (`apibas_job_plans`), so a later edit of either cannot change what ran. Because an approval binds the fixture name, a production
  approval would bind the exact test data and inventory.
- **The runner rebuilds the scenarios itself.** The request carries the plan; the runner calls the same `binding.Bind`, checks the plan
  hashes to the fixture name and produces exactly the requested scenario ids, and refuses otherwise. A plan altered after submission,
  or a request whose fixture and plan disagree, fails the job with no report. Schema version is now 2.
- **Graded on the response alone.** Bound jobs run with `NoState` and no lab endpoints; only read-only scenarios exist in a plan.
- **Scope.** The target's registered allowed paths bound a bound job like any other (checked per scenario by the runner); a staging or
  production target must have them. The registered scenario list does not apply (bound scenarios are not in the catalogue).
- **Credentials.** Each identity's credential name must be one of the target's registered credential names, or the job is refused as
  outside the target's scope. The job reads secrets only through the target's existing secret-store references.
- **Stale data is refused (409).** If a newer inventory has been imported since the test data was saved, save it again first.
- **Audit** is the existing `apibas.job.submit` / `apibas.job.refused` / `apibas.job.finish` records, with the bound fixture and scenario ids.

Verified end to end with the real runner binary and a real database: a vulnerable spec-shaped API grades FAIL and a fixed one PASS for the
same bound scenarios; an unregistered credential, a path outside scope, an altered plan and a missing plan row are each refused with no
report. Not run on staging or against a real customer API.

Not built: results are in the job as for any job but the console does not show them; no scheduling; no write operations.
