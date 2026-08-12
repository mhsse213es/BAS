# OpenAEV Exercise Sync + Sync-Result Visibility — Design

## Problem

The OpenAEV connector only syncs OpenAEV **Scenarios** (`GET /api/scenarios` +
`/api/scenarios/{id}/export`). A user reported the Exercises tab showing no
content despite OpenAEV being configured, enabled, and reporting `last_sync_status
= ok`. Root cause (confirmed against the real OpenAEV server source,
`openaev-main/`, and confirmed by the user): their content lives in OpenAEV
**Exercises** — a separate top-level object with its own REST API
(`GET /api/exercises`, `ExerciseApi.java:761`) that our connector never calls.
An OpenAEV Exercise does not require a parent Scenario (`Exercise.java:184-194`
— the relationship is an optional many-to-one via a join table), so users can
and do create Exercises directly without ever touching Scenarios.

Separately, `last_sync_status` only reflects whether the initial `List()` call
succeeded — a sync that legitimately found and imported nothing looks
identical to one that imported real content. This masked the above bug for
longer than it should have and is worth fixing at the same time, scoped to
OpenAEV only.

## Terminology note

Audspect already has its own **Exercise Plan** / **Execution** concepts
(`internal/exercise`, the "Exercise Plans"/"Executions" cards in the
Exercises tab), built today from an imported OpenAEV *Scenario* via
`CreateExercisePlanFromOpenAEV`. OpenAEV's own **Exercise** object is an
unrelated concept that happens to share the word — a standalone simulation,
not a reusable template. This design imports OpenAEV Exercises as a *second
content source* feeding the exact same Create-Exercise-Plan → Execution
pipeline Scenarios already feed. "Exercise Plan" and "Execution" keep meaning
what they mean today; "OpenAEV Exercise" refers to OpenAEV's object.

## Architecture

**Provider layer** (`internal/openaev`): add an Exercise-flavored provider
implementing the existing `ContentProvider` interface (`List`/`Fetch`),
pointed at `/api/exercises` and `/api/exercises/{id}/export`. Unlike Scenario
export (flat JSON), Exercise export returns a **ZIP archive**
(`ExportService.exportExerciseToZip`, confirmed in
`openaev-main/.../ExportService.java:54-72`) containing a `<name>.json`
manifest plus attachment files. The manifest entry is tagged with a distinct
zip entry comment (`EXPORT_ENTRY_EXERCISE`, set via `ZipEntry.setComment` in
the Java source) separate from attachment entries (`EXPORT_ENTRY_ATTACHMENT`)
— `Fetch()` unzips the response and selects the entry whose `Comment` field
(exposed by Go's `archive/zip` as `zip.File.Comment`) equals the literal
string `"Exercise"` (`EXPORT_ENTRY_EXERCISE`'s value, confirmed in
`openaev-main/.../service/ImportService.java:37`), not by filename/extension
matching, since an attachment could coincidentally also be a `.json` file.
Attachments are
discarded — they are not needed to build an Exercise Plan. The manifest shape
(`ExerciseFileExport.java`) is structurally close to Scenario's export
(`teams`, `objectives`, `injects`, `tags`, `documents`, `channels`,
`articles`, `lessonsCategories` — root key `exercise` instead of `scenario`),
so parsing is a variant of the existing parser, not a rewrite.

A `CompositeProvider` wraps both the Scenario and Exercise providers behind
one `ContentProvider`: `List()` calls both sub-providers and tags each
`ScenarioRef` with its origin (e.g. an `exercise:` ID prefix); `Fetch()`
routes to the correct sub-provider based on that tag. This means
`Importer.SyncAll`'s existing delta-check and per-item error isolation need
no changes — only how the connector is constructed changes (one composite
provider instead of one REST provider).

**Data model**: both content types are stored in the existing
`openaev_scenarios`/`openaev_bundles` tables — no new tables. A new
`source_type text NOT NULL DEFAULT 'scenario'` column on `openaev_scenarios`
distinguishes them (`'scenario'` | `'exercise'`); a migration backfills
existing rows to `'scenario'`. The Go `Scenario` struct gets a `SourceType`
field carried through DB → API → UI. `ParseBundle`/`Normalize` gain a variant
that reads the `exercise` root key instead of `scenario`; the rest of the
field mapping is shared.

**API**: `GET /api/openaev/scenarios` gains an optional `?type=` query param
(`scenario` | `exercise`, default `scenario` — preserves today's behavior for
existing callers with zero changes). `ListOpenAEVScenarios` filters `store.List`
by `source_type` when the param is present.

**UI**: a new "OpenAEV Exercises" card is added directly below "OpenAEV
Scenarios" in the Exercises tab, identical row template
(`Name/Category/Severity/Techniques/Injects/Synced`), fetched via
`?type=exercise`. Both cards' rows drive the same existing
`createPlanFromOpenAEV(id)` → `CreateExercisePlanFromOpenAEV` →
`openaev.BuildPlan` flow, unmodified — both content types normalize into the
same `Scenario`/`Detail` Go structs, so `BuildPlan` doesn't need to know
which source a given scenario/exercise came from.

**Sync-result visibility**: `openaev_config` gains four new integer columns —
`last_sync_created`, `last_sync_updated`, `last_sync_skipped`,
`last_sync_errored` — populated from `SyncResult` on every sync, both the
manual `POST /api/openaev/sync` path and the hourly background poller in
`cmd/server/main.go`. `GetOpenAEVConfig`/`GetOpenAEVStatus` return these
alongside `lastSyncStatus`. The frontend status badge (Integrations tab,
OpenAEV section) changes from a bare "OK" to e.g. **"OK — 5 created, 12
skipped"** or **"OK — 0 created, 0 updated"**, so a zero-result sync reads as
zero-result instead of indistinguishable from a healthy one. No new status
values — `ok`/`error`/`never` stay as they are.

## Error handling

Same isolation model as today: one failing scenario or exercise is logged
into `SyncResult.Errors` and counted in `Errored`, never aborts the rest of
the batch. A `CompositeProvider.Fetch()` failure for one sub-provider does
not affect the other's items — each item's fetch is independent, exactly as
it is today for Scenario-only syncing.

## Testing

- `internal/openaev`: provider test for the Exercise REST provider's zip
  unwrapping (fixture zip with a manifest + attachment entries → only the
  manifest bytes returned); parser/normalizer test for the `exercise` root
  key variant; `CompositeProvider` test proving `List` merges both sources
  and `Fetch` routes each ref to its origin provider.
- `internal/openaev/store_test.go`: `source_type` round-trips through
  `Upsert`/`List`, and `List` filtering by type returns only matching rows.
- `internal/api/openaev_handlers_test.go`: `?type=` query param filtering on
  `ListOpenAEVScenarios`; `GetOpenAEVConfig`/`GetOpenAEVStatus` return the new
  sync-count fields.
- Migration test: existing rows backfill to `source_type = 'scenario'`.

## Out of scope

- Importing OpenAEV Exercise attachments/documents.
- Applying the sync-result-visibility fix to MISP/OpenCTI/OTX (scoped to
  OpenAEV only, per this conversation).
- Any change to `BuildPlan`, `CreateExercisePlanFromOpenAEV`, or the
  Exercise Plan/Execution pipeline itself — both content types feed it
  unchanged.
