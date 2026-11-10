# API BAS OpenAPI import and endpoint inventory

Status: first tranche and target storage, 9 November 2026. Code: `orchestrator/internal/apibas/openapi`, command `orchestrator/cmd/apibas-inventory`.

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
- There is no console page for inventories yet (the API below is the interface).
- It reads OpenAPI 3.x, Swagger 2.0 and GraphQL schemas (see below). It does not read SOAP/WSDL, gRPC or AsyncAPI.
- It does not discover routes. Observed routes come from a file the user supplies.

## Safety (a specification is untrusted input)

- Document size is capped at 8 MiB, operations at 5000, reference depth at 32, schema depth at 6, and schema nodes visited at 50000
  per import (a document whose schemas fan out through shared references would otherwise grow exponentially).
- Example, default and enum values are never copied, so a specification that carries a real secret in an example does not leak it
  through the inventory or the report. Only names and shapes are kept.
- A reference loop or a recursive schema terminates and is reported, not fatal.

## Calls made (not discussed with the owner; change if wrong)

1. Parse-only package plus a CLI first; storing inventories on targets, an API and console come later.
2. OpenAPI 3.x and Swagger 2.x; other versions are rejected by name rather than half-supported.
3. Class rules are name-and-shape heuristics (regular expressions on parameter, field and path-segment names). They will miss
   unusual naming and will flag benign fields. The privileged-action list (approve, settle, refund, disburse, release, override,
   impersonate) was extended after running the importer on the Aleef bank specification in the repo.
4. A health, docs, status or well-known path is not flagged as unauthenticated even when public.
5. A route that is the older of two versions (`/v1/x` beside `/v2/x`) is a lifecycle candidate, as is any deprecated operation.

## Storage on targets (API)

An inventory is stored per target as numbered versions in `apibas_target_inventories` (created with the other API BAS tables by
`EnsureAPIBASJobSchema`). Only the parsed inventory and the source document's SHA-256 and size are stored. The raw document is
not, because a specification can carry a secret in an example. An identical re-import (same hash) writes nothing. A target keeps
its 50 newest versions. Importing locks the target row, so concurrent imports get distinct versions.

| Route | Permission | Purpose |
|---|---|---|
| `POST /api/apibas/targets/{id}/inventory` | manage targets | The body is the OpenAPI document (JSON or YAML, up to 8 MiB). Stores the next version and returns the class counts, warnings, the suggested scope, and what changed since the previous version (operations added, removed, or with changed authentication). Audited as `apibas.inventory.import` (hash, size and counts, never content). |
| `GET /api/apibas/targets/{id}/inventory` | view runs | The newest inventory, or `?version=N`. `?class=` keeps one candidate class. |
| `GET /api/apibas/targets/{id}/inventory/versions` | view runs | Version metadata, newest first. |
| `POST /api/apibas/targets/{id}/inventory/drift` | view runs | Body `{"observed":[{"method":"GET","path":"/x"}]}` (up to 20000 routes). Compares the stored inventory with the routes the caller observed. Requests nothing from the target. |

The suggested scope is shown and never applied: changing a target's allowed paths stays a separate, deliberate act.

## Use

    apibas-inventory -spec openapi.yaml
    apibas-inventory -spec openapi.yaml -observed gateway-routes.txt
    apibas-inventory -spec openapi.yaml -json

## Next steps, in order of value

1. A console page for a target's inventory, versions, changes and drift.
2. A binding step from inventory operations to catalogue scenarios (which identities, which object IDs, which fixtures) so an
   imported API can be assessed, not only listed.
3. Applying the scope suggestion to a target as an audited action (target update does not exist yet).
4. GraphQL mutations (they change state, so a repeated request cannot restore it) and union return types.

## Swagger 2.0

Added 10 November 2026. A document with `swagger: "2.0"` (or an unquoted `2.0`) is imported into the same inventory.

- The base URL is `schemes` (http and https only; https if none), `host` and `basePath`. Every path in a Swagger 2.0 document is relative to `basePath`, so the inventory keeps full request paths with `basePath` in front. A `basePath` that does not start with a slash is ignored with a warning, and with no `host` there are no servers.
- The request body is the `in: body` parameter's schema; `in: formData` parameters become body field names. Body content types come from the operation's `consumes`, else the document's, else JSON for a body and url-encoded for a form. A form with a file parameter is also multipart.
- Response fields come from the 2xx response's `schema`, through `definitions`, to the same depth limits as OpenAPI 3.
- Security uses the same rules (`security`, with `[]` meaning public). Default and example values are never kept, as with OpenAPI 3.
- Other `swagger` versions (1.2, 3.0) are rejected with the version named. Tests: `swagger_test.go`, fixture `testdata/shop_swagger2.yaml`, which also checks that the same API in either format gets the same classes and authentication.

## GraphQL schemas

Added 10 November 2026. A GraphQL schema is imported from SDL (a `.graphql` file) or from an introspection result (`{"data":{"__schema":...}}` or the bare `{"__schema":...}`) at the same import route. The importer only reads the document; it never contacts an API.

- A GraphQL API has one HTTP endpoint, so the inventory's operations are the root fields of Query, Mutation and Subscription (root types come from the `schema` block, else `Query`, `Mutation`, `Subscription`; `extend type` merges). Each field is one operation: `Method` is `QUERY`, `MUTATION` or `SUBSCRIPTION`, `Path` is `/graphql` (a schema does not say where it is served, and a warning says so), and the new `Field` property names the root field. The operation key is `QUERY /graphql#order`.
- Arguments are recorded by name as body fields, and the fields of input-object arguments are included, so a mutable field inside an input is seen. Response fields come from the return type (unions through their members), to the same depth and node limits as OpenAPI, cycles bounded. Default values and descriptions beyond a 200 character summary are never kept.
- Authentication is `unspecified` unless a field carries an auth-like directive (`@auth`, `@authenticated`, `@hasRole`, and similar), which makes it `required`. Because a schema declares nothing else, no GraphQL operation is flagged as public.
- Candidate classes use the same name rules as REST, applied to arguments and return fields: object-level (an id-like argument), function-level (a privileged word in the field name, split from camelCase or snake_case), property-level (a mutation with a mutable field), data exposure, resource consumption (a paging argument on a query), server-side request (a destination-like argument), lifecycle (`@deprecated`).
- Errors name the line for SDL. Limits: the document size, 1,000,000 tokens, 20,000 types, 200,000 fields, 5,000 operations.
- **Binding:** GraphQL queries can be bound to test data and run (see "GraphQL queries in the bound test data" in `api-bas-scenario-binding.md`); mutations and subscriptions are inventoried and classified only. Federation directives are read as ordinary directives. Query documents and fragments are refused (this is a schema import).
- Drift compares REST method and path, so documented GraphQL operations show as not observed against a route list.

Tests: `graphql_test.go`, fixture `testdata/shop.graphql`, the binding refusal in `binding_test.go`, and the API test `TestAPIBASInventoryImportsSwaggerAndGraphQL`.
