# OpenAEV Connector (Module 1) — Design Spec

**Status:** Approved by user 2026-07-15, proceeding to implementation plan.

## Context

This is Module 1 of a larger 3-module vision (Exercise Engine, Communication Injectors — both separate future brainstorm cycles, out of scope here). It is also the new top roadmap priority as of 2026-07-15, inserted ahead of the paused SP5 Threat Intelligence Pipeline brainstorm. See memory `project_openaev_exercise_vision` and `project_platform_roadmap_2026h2` for full context.

**OpenAEV** is Filigran's Adversary Emulation & Validation platform (the evolution of OpenBAS), Community Edition. Zero existing integration exists in this codebase today (confirmed via full-repo grep before this spec was written).

The user provided the actual OpenAEV source (`openaev-main/`, a Java/Spring Maven project) during brainstorming, which was inspected directly to ground this design in OpenAEV's real REST contract rather than assumptions:

> **Repo hygiene note (2026-10-07, Group J):** that 58MB source dump (`openaev-main/`) was left committed into this repo unused -- never built, never referenced by any connector code, Dockerfile, or CI step -- and has been removed. It was Filigran OpenAEV **Community Edition**, Apache-2.0 licensed (`openaev-main/LICENSE`, Copyright Filigran SAS), top-level Maven version `2.260710.0` (`openaev-main/pom.xml`), inspected only for its REST contract as described above. The `internal/openaev` connector (this spec's Module 1) targets an **external, separately-run** OpenAEV instance over that REST API; it has never depended on the vendored source.

- **Auth**: `Authorization: Bearer <token>` (Personal Access Token model), stateless — same shape the existing MISP/OpenCTI connectors (`internal/connector/misp.go`, `opencti.go`) already use.
- **List**: `GET /api/scenarios` (lightweight `ScenarioSimple[]`) or `POST /api/scenarios/search` (paginated). Each scenario carries `scenario_updated_at` (confirmed field on the `Scenario` JPA entity, `Scenario.java:250-255`), enabling cheap delta-sync.
- **Export (the "bundle")**: `GET /api/scenarios/{id}/export?isWithTeams=&isWithPlayers=&isWithVariableValues=` (`ScenarioApi.java:263-278`) streams a ZIP built by `ScenarioService.exportScenario` (`ScenarioService.java:507` onward): one JSON entry (`ScenarioFileExport`, `version=1`) containing the scenario, objectives, lessons categories/questions, variables, documents/attachments, injects (each optionally carrying an `InjectorContract` → MITRE ATT&CK attack-pattern mapping), articles/channels, challenges, and optionally teams/players/organizations.
- **Import**: `POST /api/scenarios/import` (multipart) accepts that same ZIP — but always creates a **new** scenario; there is no update-in-place. This confirms Audspect must own its own upsert/versioning rather than calling OpenAEV's import endpoint at all.

Because OpenAEV's own export/import already uses a well-defined ZIP+JSON bundle format, this design **adopts that format as-is** rather than inventing a separate "Audspect bundle" schema — a REST fetch and a manually-transferred file (air-gapped case) are byte-identical inputs to the same parser.

## Scope for V1: content library only

Module 1 syncs and stores OpenAEV scenario definitions — browsable in Audspect, version-tracked, technique-mapped. It does **not** execute them. Running a synced scenario is blocked until the Exercise Engine (a separate future module) exists to actually orchestrate OpenAEV's injects (phishing sends, multi-day waits, conditional branches, approval gates) — none of which fit today's synchronous agent-dispatch BAS execution model. This is a deliberate scope boundary, not a deferred afterthought: nothing built here becomes throwaway when the Exercise Engine lands, since this module's job is strictly acquisition and storage.

## Architecture

New package `internal/openaev`, sitting alongside `internal/scenario`, `internal/connector`, `internal/reporting` — not inside `internal/connector`, because that package's existing job (deriving synthetic BAS scenarios from MISP/OpenCTI threat-actor TTP profiles) is a different domain from importing pre-authored exercises verbatim.

```
ContentProvider interface {
    Name() string
    List(ctx context.Context) ([]ScenarioRef, error)      // id + name + source_updated_at — cheap
    Fetch(ctx context.Context, id string) ([]byte, error)  // raw bundle bytes — REST or file, transport-agnostic
}
  ├── RESTProvider   — GET /api/scenarios (list) + GET /api/scenarios/{id}/export (bundle), Bearer auth
  └── BundleProvider — wraps a single manually-uploaded ZIP's bytes (air-gapped path); List() is a no-op/unused here

Importer  — owns orchestration: scheduling, retries+backoff, metrics, logging, the per-scenario DB transaction.
  Importer.SyncAll(ctx, provider)     — full sync: List → per-ref delta-check → Fetch → process
  Importer.ImportOne(ctx, bytes)      — single-bundle path for the air-gapped upload endpoint

Parser      — unzips the bundle, decodes the JSON entry into a Go struct mirroring OpenAEV's ScenarioFileExport shape.
Normalizer  — maps the parsed struct into this package's own Scenario type (extracts technique_ids from each
              inject's injector-contract attack-pattern refs, tags, objectives, platforms, etc.)
Store       — Postgres upsert (openaev_bundles + openaev_scenarios), mirrors internal/scenario/content_import.go's
              idempotent-upsert pattern used for ART/CVE/EPSS seeding.
```

Scheduling reuses `internal/connector.Scheduler` as-is (ticker + manual-trigger channel + stop channel) — one more registered job, not a second scheduler implementation.

## Data model

```sql
-- Singleton config row, same shape as art_content_meta's id=1 CHECK pattern.
CREATE TABLE IF NOT EXISTS openaev_config (
    id                  int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    base_url            text        NOT NULL DEFAULT '',
    bearer_token        text        NOT NULL DEFAULT '',
    poll_interval_hours int         NOT NULL DEFAULT 24,
    enabled             boolean     NOT NULL DEFAULT false,
    last_sync_at        timestamptz,
    last_sync_status    text        NOT NULL DEFAULT 'never', -- 'ok' | 'error' | 'never'
    last_error          text        NOT NULL DEFAULT '',
    updated_at          timestamptz NOT NULL DEFAULT NOW()
);

-- Full parsed bundle content, kept separate from the metadata table so scenario
-- list views stay fast (never touch the potentially-large jsonb blob).
CREATE TABLE IF NOT EXISTS openaev_bundles (
    id                  text        PRIMARY KEY,   -- sha256(raw bundle bytes), hex
    openaev_scenario_id text        NOT NULL,
    bundle              jsonb       NOT NULL,        -- normalized Scenario struct (objectives, variables, injects, etc.)
    content_hash        text        NOT NULL,        -- same as id, kept as a named column for clarity in queries
    size_bytes          int         NOT NULL DEFAULT 0,
    source_version      int         NOT NULL DEFAULT 1, -- OpenAEV's own ScenarioFileExport.version field
    synced_at           timestamptz NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS openaev_scenarios (
    openaev_scenario_id text        PRIMARY KEY,
    name                text        NOT NULL,
    category            text        NOT NULL DEFAULT '',
    severity            text        NOT NULL DEFAULT '',
    platforms           text[]      NOT NULL DEFAULT '{}',
    technique_ids       text[]      NOT NULL DEFAULT '{}',
    tags                text[]      NOT NULL DEFAULT '{}',
    objectives_count    int         NOT NULL DEFAULT 0,
    injects_count       int         NOT NULL DEFAULT 0,
    source_updated_at   timestamptz NOT NULL,
    content_hash        text        NOT NULL DEFAULT '', -- denormalized copy of the current bundle's hash
    bundle_id           text        REFERENCES openaev_bundles(id),
    sync_revision       int         NOT NULL DEFAULT 1,   -- increments only when content_hash actually changes
    imported_at         timestamptz NOT NULL DEFAULT NOW(),
    updated_at          timestamptz NOT NULL DEFAULT NOW()
);
```

`objectives`, `prerequisites`, `cleanup`, `references` and other fields the user asked to preserve even though Audspect doesn't act on them today live inside `openaev_bundles.bundle` (the full normalized JSON), not as separate relational columns — avoids a wide table for fields with no query pattern yet, while keeping them available for the future Exercise Engine.

Multiple OpenAEV instances are explicitly **not** supported in V1 (singleton config, matching the user's own single-instance deployment diagram) — YAGNI; can become a multi-row table later without touching the provider/importer/parser/normalizer layers if ever needed.

## Sync flow

**Scheduled/manual REST sync** (`Importer.SyncAll`):
1. Load `openaev_config`; no-op if `enabled=false`.
2. `provider.List(ctx)` → `[]ScenarioRef{ID, Name, SourceUpdatedAt}`.
3. For each ref: compare `SourceUpdatedAt` against the stored `openaev_scenarios.source_updated_at`. Unchanged → skip (cheap, no fetch).
4. Changed or new → `provider.Fetch(ctx, ref.ID)` → raw bytes → `sha256` → compare against stored `content_hash`. If the hash is *also* unchanged (upstream no-op re-save bumped only the timestamp), skip normalization — just bump `source_updated_at` on the existing row.
5. Real content change → `Parser.Parse(bytes)` → `Normalizer.Normalize(parsed)` → `Store.Upsert(ctx, scenario, bundle)` in one transaction: upsert `openaev_bundles`, upsert `openaev_scenarios` (increment `sync_revision`).
6. Tally created/updated/skipped/errored. One bad bundle logs the error, counts it, and **does not abort the rest of the sync** — matches the ART reseed pattern's error-isolation.
7. On completion: update `openaev_config.last_sync_at/last_sync_status/last_error`; write an audit log entry (`h.auditLog(r, "openaev.sync", ...)`, same convention as `campaign.stop`/`scenario.cancel`).
8. Transient HTTP/DB errors get retried with backoff at the `Importer` level (per user's explicit "importer owns retries," not the provider).

**Air-gapped manual import** (`Importer.ImportOne`): skips List/delta-check entirely — the uploaded file *is* the one bundle to process. Same Fetch(already-in-hand bytes) → hash → Parse → Normalize → Store path.

## API surface

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/openaev/config` | Admin | Current config, `bearer_token` redacted in the response (same convention as other stored secrets) |
| PUT | `/api/openaev/config` | Admin | Update base_url/token/poll_interval/enabled |
| POST | `/api/openaev/config/test` | Admin | Pre-flight connectivity check (hits OpenAEV's health/scenarios-list endpoint with the given credentials) before saving |
| POST | `/api/openaev/sync` | Admin | Manual sync trigger (fires the scheduler's manual-trigger channel) |
| GET | `/api/openaev/status` | Viewer+ | last_sync_at/status/error, scenario counts |
| GET | `/api/openaev/scenarios` | Viewer+ | List (metadata table only — fast) |
| GET | `/api/openaev/scenarios/{id}` | Viewer+ | Detail (joins `openaev_bundles` for full objectives/injects/variables) |
| POST | `/api/openaev/import` | Admin | Air-gapped manual bundle upload (multipart) |

## UI

Lands under the existing greyed-out "Integrations" nav placeholder (Infrastructure group) in `wwwroot/index.html` (and its `cmd/server/wwwroot/index.html` hardlink mirror — both must be committed together, per the repo quirk noted in `project_report_redesign`/SP4 history) — this becomes that placeholder's first real content. Index table (name/category/severity/technique count/last synced) + a detail drawer (objectives, variables, injects list with technique badges, tags) + an Admin-only config/status card (edit connection, "Sync now" button, last sync status/error).

## Error handling

- Never fabricate a scenario from a partially-parsed bundle — a Parser failure on one scenario is isolated, logged, and counted as an error; the rest of the sync proceeds.
- `bearer_token` stored in plaintext in Postgres, redacted in API responses — matches this codebase's existing convention for other secrets (`agent_secret`, `JWT_SECRET`, connector API keys); no new encryption-at-rest mechanism introduced, since none exists elsewhere in this codebase and the trust boundary is DB-level access control, consistent with the rest of the platform.
- `POST /api/openaev/config/test` lets an admin validate connectivity/credentials before flipping `enabled=true`, rather than discovering a bad token only when the scheduler's first sync silently fails.

## Testing

Follows this session's established TDD precedent:
- `RESTProvider`: `httptest.Server`-backed fakes for List/Fetch, including a 401 (bad token) case and a malformed-response case.
- `BundleProvider`: in-memory byte fixtures.
- `Parser`/`Normalizer`: fixture ZIP(s) built from the real `ScenarioFileExport` JSON shape confirmed in `openaev-main`, asserting technique-ID extraction from injects' attack-pattern refs.
- `Store`: real Postgres via `sharedDB.RunWithPool`, asserting upsert idempotency, hash-based skip-on-unchanged, and `sync_revision` incrementing only on real content changes.
- `Importer`: fake `ContentProvider` fixture, asserting the skip/update/error-isolation/retry behavior without a real network call.
- API handlers: reuse existing test helpers (`withURLParam`, `startFakeAgent`-style patterns where relevant), `rbac_matrix_test.go` gets the new routes added at their correct tiers.

## Self-review

- **Placeholder scan**: no TBD/TODO markers; every requirement above has a concrete mechanism.
- **Internal consistency**: the "OpenAEV always wins" policy (user-selected) means no merge/diff UI is described anywhere above — checked, none is.
- **Scope check**: this spec covers Module 1 only. Modules 2 (Exercise Engine) and 3 (Communication Injectors), and the long-term Cyber Exposure Validation Platform pivot, are explicitly out of scope and will get their own future brainstorm cycles per `project_openaev_exercise_vision`.
- **Ambiguity check**: "conflict resolution" (from the original proposal) is resolved by the no-merge upsert policy — not ambiguous. "Version comparison" is resolved concretely via `source_updated_at` + `content_hash` double-check. "Health monitoring" is resolved via `openaev_config.last_sync_status/last_error` + the `/status` endpoint.
