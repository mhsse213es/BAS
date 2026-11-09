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
- **No job.** A plan is not yet persisted on a target or run through the orchestrator's job path. Running one today means calling the
  runner with `plan.Fixture`, `plan.Scenarios`, `NoState` and the credentials by hand, as the end-to-end test does.
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

1. Persist a binding spec on a target and run a plan through the orchestrator's job path (runner request carrying the bound
   scenarios and fixture, audited, approval-bound like other jobs).
2. A console page for the preview and for entering test data (the next item).
3. A target-side state check (a customer-provided read endpoint) so write operations can be bound.
