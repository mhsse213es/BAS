# API BAS OpenAPI import and endpoint inventory

Status: first tranche, 9 November 2026. Code: `orchestrator/internal/apibas/openapi`, command `orchestrator/cmd/apibas-inventory`.

## Why

API.txt makes discovery the first step of the engine ("OpenAPI specifications, approved endpoint discovery, protocols and API
versions") and lists "OpenAPI import" in Phase 1. Until now API BAS only ran scenarios written against its own lab. An inventory of
a customer's real specification says which parts of their API each class of scenario would apply to, which routes are described
but not seen in use, and which are in use but not described.

## What it does

- Imports OpenAPI 3.0 and 3.1, JSON or YAML, into an inventory of operations: method, path, operationId, tags, deprecated flag,
  effective authentication, path/query/header parameters, request body content types and field names, success response field names.
- Resolves local `$ref` (`#/...`) in parameters, request bodies, responses and schemas, to a bounded depth.
- Assigns **candidate test classes** from the shape of each operation (object-level, function-level and property-level authorization,
  unauthenticated access, sensitive data exposure, resource consumption, server-side request, file upload, lifecycle). Each class
  names the catalogue category whose scenarios test it.
- Suggests allowed path prefixes (whole segments, validated by the scope package) for a person to confirm.
- Compares the inventory with observed routes (one `METHOD /path` per line) and reports undocumented routes, specified routes not
  seen, and deprecated routes in use.

## What it does not do

- It does not contact anything. Servers named in the specification are recorded, never called; remote `$ref` is reported and not followed.
- It does not decide that anything is vulnerable. A class is a reason to test.
- It does not select or run scenarios. Catalogue scenarios are written against the lab's routes, so mapping a customer operation to
  a specific scenario needs a binding step that does not exist yet.
- It does not persist the inventory or attach it to a target, and there is no API endpoint or console page for it.
- It does not read Swagger 2.0 (reported with a clear error), SOAP/WSDL, GraphQL schemas, gRPC or AsyncAPI.
- It does not discover routes. Observed routes come from a file the user supplies.

## Safety (a specification is untrusted input)

- Document size is capped at 8 MiB, operations at 5000, reference depth at 32, schema depth at 6, and schema nodes visited at 50000
  per import (a document whose schemas fan out through shared references would otherwise grow exponentially).
- Example, default and enum values are never copied, so a specification that carries a real secret in an example does not leak it
  through the inventory or the report. Only names and shapes are kept.
- A reference loop or a recursive schema terminates and is reported, not fatal.

## Calls made (not discussed with the owner; change if wrong)

1. Parse-only package plus a CLI first; storing inventories on targets, an API and console come later.
2. Only OpenAPI 3.x; Swagger 2.0 is rejected rather than half-supported.
3. Class rules are name-and-shape heuristics (regular expressions on parameter, field and path-segment names). They will miss
   unusual naming and will flag benign fields. The privileged-action list (approve, settle, refund, disburse, release, override,
   impersonate) was extended after running the importer on the Aleef bank specification in the repo.
4. A health, docs, status or well-known path is not flagged as unauthenticated even when public.
5. A route that is the older of two versions (`/v1/x` beside `/v2/x`) is a lifecycle candidate, as is any deprecated operation.

## Use

    apibas-inventory -spec openapi.yaml
    apibas-inventory -spec openapi.yaml -observed gateway-routes.txt
    apibas-inventory -spec openapi.yaml -json

## Next steps, in order of value

1. Persist an inventory against a target and show it with the target (store, API, RBAC, audit).
2. A binding step from inventory operations to catalogue scenarios (which identities, which object IDs, which fixtures) so an
   imported API can be assessed, not only listed.
3. Run the importer's scope suggestion through the existing approval flow, so confirming it is an audited action.
4. Swagger 2.0, then GraphQL schema import.
