# Generic TAXII 2.1 Connector — Phase 1 (Indicators → IOC Registry) — Design Spec

**Goal:** Add a generic, multi-instance TAXII 2.1 connector so on-prem BFSI deployments can ingest sector-specific ISAC feeds (FS-ISAC first; HC-ISAC/Auto-ISAC/any other TAXII 2.1 server the same way, since nothing about the transport is FS-ISAC-specific). Phase 1 scope is deliberately narrow: get STIX `indicator` objects flowing reliably, idempotently, and observably into the existing IOC Registry with `Origin=threat-feed` — a value that has existed in `iocregistry.Origin` since Phase B/C but has never had a producer. Threat-actor/intrusion-set/campaign/malware/tool routing is Phase 2/3, deferred by design (see Scope).

**Why now:** Prompted by the user's "how do I populate the IOC Registry" question earlier this session, which surfaced that `OriginThreatFeed` is defined but dead code, and by a follow-up proposal to integrate ISAC feeds for localized (India BFSI) threat vectors. TAXII 2.1 is the actual transport ISACs use — distinct from MISP's REST/JSON and OpenCTI's GraphQL, both already wired into `internal/connector`. This is new protocol-layer work, not an extension of either existing client.

## Scope

**In scope (Phase 1):**
- `internal/taxii`: a new package — TAXII 2.1 HTTP client (discovery → API root → collection → paginated object retrieval), a STIX 2.1 bundle parser, and a normalizer that routes `indicator` SDOs into `iocregistry`.
- A minimal STIX **pattern** parser covering single-observable comparisons only: `ipv4-addr:value`, `ipv6-addr:value`, `domain-name:value`, `url:value`, `file:hashes.'SHA-256'`/`'MD5'`/`'SHA-1'`. Boolean/composite patterns (`AND`/`OR`, multiple observables) are explicitly unsupported in Phase 1 — routed through the skip-and-log path below, never partially parsed.
- Multi-instance config: a new `taxii_connector_config` table + CRUD API + UI list (not the singleton `threat_intel_config` pattern MISP/OpenCTI/OTX use — this deployment may run zero, one, or several TAXII sources at once).
- Auth: `none` and `basic` only. mTLS columns are reserved in the schema (nullable, unused) but no client-cert code path exists yet — added only if a real target requires it.
- Idempotent ingestion via a new `taxii_ingested_objects` ledger keyed on `(connector_id, stix_id, modified)`.
- Ingestion telemetry: every poll records processed/skipped/malformed counts and the last error, surfaced through the config API — unsupported or malformed STIX objects are counted and logged, never silently dropped, and never abort the rest of the bundle.
- A new `SourceThreatFeed` value on `iocregistry.Source` and a new `StatusReported` value on `iocregistry.Status` (see Decisions — both are small, targeted additions to the existing enums, not new subsystems).
- Testing against a self-hosted, spec-compliant mock TAXII 2.1 server + STIX fixtures. No dependency on live FS-ISAC access.

**Explicitly out of scope (deferred to later phases/sub-projects):**
- Phase 2: routing `threat-actor`/`intrusion-set` SDOs into the existing `connector.Source`/`ThreatActor` pipeline (Threat Prioritization + scenario generation).
- Phase 3: routing `campaign`/`malware`/`tool` SDOs into the existing `IntelligenceSource` pipeline, mirroring OpenCTI.
- Phase 4 (design not started): preserving STIX `indicates` relationships (actor/malware → indicator) for Knowledge Graph display. `internal/threatgraph` is a read-only view over existing tables with no dead-storage to sync — but today's `ioc_sightings` model only expresses "observed during our own BAS run," not "intel-asserted association." That's new modeling, deliberately not bundled into Phase 1.
- mTLS client-certificate authentication.
- Cross-source dedup beyond the `(type, value)` uniqueness `iocs` already enforces — an indicator reported by both FS-ISAC and, say, MISP still produces one row with `sighting_count` bumped, exactly like today's behavior for any other repeat sighting.
- Wiring into `internal/connector.Scheduler` — Phase 1 has no `ThreatActor` output, so it runs its own independent poller (see Sync wiring). Phase 2 folds it into the shared scheduler once it does.

## Data model

```go
// internal/taxii/config.go
type ConnectorConfig struct {
    ID             string
    Name           string // operator-facing label, e.g. "FS-ISAC Production"
    ServerURL      string
    APIRoot        string
    CollectionID   string
    AuthType       string // "none" | "basic"
    Username       string
    Password       string // plaintext at rest, matching threat_intel_config.api_key's existing convention
    ClientCert     string // reserved, unused in Phase 1
    ClientKey      string // reserved, unused in Phase 1
    Enabled        bool
    LastPollAt     *time.Time
    LastPollStatus string // "never" | "ok" | "error"
    LastPollSummary PollSummary
    LastError      string
    CreatedAt      time.Time
    UpdatedAt      time.Time
}

type PollSummary struct {
    Processed int `json:"processed"` // indicator SDOs successfully written/updated
    Skipped   int `json:"skipped"`   // recognized-but-unsupported (composite pattern, non-indicator SDO type)
    Malformed int `json:"malformed"` // failed to parse as valid STIX
}
```

```sql
CREATE TABLE IF NOT EXISTS taxii_connector_config (
    id                text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name              text        NOT NULL,
    server_url        text        NOT NULL,
    api_root          text        NOT NULL DEFAULT '',
    collection_id     text        NOT NULL DEFAULT '',
    auth_type         text        NOT NULL DEFAULT 'none',
    username          text        NOT NULL DEFAULT '',
    password          text        NOT NULL DEFAULT '',
    client_cert       text        NOT NULL DEFAULT '', -- reserved, unused Phase 1
    client_key        text        NOT NULL DEFAULT '', -- reserved, unused Phase 1
    enabled           boolean     NOT NULL DEFAULT false,
    last_poll_at      timestamptz,
    last_poll_status  text        NOT NULL DEFAULT 'never',
    last_poll_summary jsonb       NOT NULL DEFAULT '{}',
    last_error        text        NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL DEFAULT NOW(),
    updated_at        timestamptz NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS taxii_ingested_objects (
    connector_id text        NOT NULL REFERENCES taxii_connector_config(id) ON DELETE CASCADE,
    stix_id      text        NOT NULL,
    modified     timestamptz NOT NULL,
    ioc_id       text        NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    ingested_at  timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (connector_id, stix_id, modified)
);
```

```go
// internal/iocregistry/types.go additions
const SourceThreatFeed Source = "threat_feed"
const StatusReported   Status = "reported" // intel-asserted, not yet operationalized -- distinct
                                            // from the execution-lifecycle statuses (Draft..Archived),
                                            // which all describe stages of OUR OWN scenario/run pipeline.
                                            // A TAXII-ingested indicator has gone through neither.
```

## TAXII client behavior

`internal/taxii/client.go`:
- `Discover(ctx) (Discovery, error)` — `GET {server_url}/taxii2/`, parses the `default` API root + `api_roots` list. Accept header `application/taxii+json;version=2.1`.
- `ListCollections(ctx, apiRoot) ([]Collection, error)` — `GET {api_root}/collections/`.
- `PollObjects(ctx, apiRoot, collectionID, addedAfter *time.Time, next string) (ObjectsPage, error)` — `GET {api_root}/collections/{id}/objects`, `Accept: application/taxii+json;version=2.1`, query params `added_after` (incremental polling) and `next` (pagination cursor from the previous page's response). Each returned object is one STIX SDO (or a `bundle` wrapping several, per the TAXII 2.1 spec's "objects" media type) — the client hands raw JSON to `internal/taxii/stix.go`, unparsed.
- Auth: `none` sends no `Authorization` header; `basic` sends `Authorization: Basic base64(username:password)` on every request. HTTP 401/403 responses are surfaced as a typed `ErrAuthFailed`, recorded verbatim into `last_error`.
- Timeouts/retries: single 30s-timeout client, one retry on transient network error, matching `MISPClient`'s existing precedent — no exponential backoff or circuit breaker in Phase 1 (unrequested complexity for a 24h-interval poller).

## STIX parsing scope

`internal/taxii/stix.go`:
- Unmarshals each object into a minimal typed envelope: `{id, type, modified, pattern, pattern_type}` — enough to route and parse, without a full STIX 2.1 SDO type hierarchy (YAGNI: Phase 1 only consumes `indicator`).
- `type != "indicator"` → classified `skipped` (Phase 2/3 will add branches here; Phase 1 counts and moves on).
- `type == "indicator"` but `pattern_type != "stix"` (e.g. a `snort`/`yara` pattern) → `skipped`.
- `type == "indicator"` with a STIX pattern → `parsePattern(pattern) (iocregistry.Type, string, ok bool)`. Recognizes exactly the single-comparison forms listed in Scope; anything containing `AND`/`OR`/multiple `[...]` groups → `skipped`, not partially matched.
- JSON that fails to unmarshal at all, or an `indicator` whose `pattern` fails the parser's grammar entirely → `malformed`.

## Ingestion pipeline & idempotency

`internal/taxii/normalize.go`, called once per polled object:

```
1. Unmarshal → malformed if it fails
2. Look up (connector_id, stix_id, modified) in taxii_ingested_objects
     - found → no-op (already ingested this exact version)
3. type/pattern routing (above) → skipped if not a simple indicator
4. iocregistry.upsertIOCFull(type, value, SourceThreatFeed, OriginThreatFeed, StatusReported, metadata)
     metadata = {"stixId": ..., "connectorName": ...}
5. INSERT INTO taxii_ingested_objects (connector_id, stix_id, modified, ioc_id)
6. processed++
```

Because `iocs` already enforces `(type, value)` uniqueness with an `ON CONFLICT` bump to `last_seen`/`sighting_count` (`upsertIOCFull`, unchanged), a *new* `modified` timestamp on an already-known `stix_id` — the feed re-issuing an updated version of the same indicator — still flows through step 4 and correctly bumps the existing IOC row rather than erroring or duplicating. Only a byte-identical `(stix_id, modified)` pair short-circuits at step 2, which is what makes repeated polling safe.

## Sync wiring

`internal/taxii/poller.go` — one `Poller` per enabled `taxii_connector_config` row, not a single shared instance:

```go
type Poller struct {
    cfg      ConnectorConfig
    client   *Client
    store    *Store   // taxii_connector_config + taxii_ingested_objects CRUD
    scheduler *exercise.PollScheduler
}

func (p *Poller) Tick(ctx context.Context) error {
    // Discover (cached after first success) → PollObjects with added_after = cfg.LastPollAt
    // → normalize each object → update taxii_connector_config's
    //   last_poll_at/last_poll_status/last_poll_summary/last_error
}
```

A `Manager` (`internal/taxii/manager.go`) owns one `Poller` + one `exercise.NewPollScheduler(24 * time.Hour)` per enabled config row, started at boot from `taxii.LoadEnabledFromDB` and reconciled whenever the config CRUD API adds/edits/removes/toggles a row — mirroring `connector.Scheduler.Reconfigure`'s existing live-reconfigure precedent, but keyed per-connector-id instead of a single global source list, since TAXII configs are independently enabled/disabled.

This intentionally does **not** touch `internal/connector.Scheduler` or its `Source` interface family in Phase 1 — that scheduler's contract is `Fetch() []ThreatActor`, which Phase 1 has nothing to return. Forcing a stub implementation just to reuse one scheduler would be worse than a second, purpose-built poller using the exact same `exercise.PollScheduler` primitive this session already used twice (`vexsweep`, `emsweep`). Phase 2 adds `Fetch()` and folds TAXII into the shared scheduler once there's real actor data to fetch.

## API + RBAC

```
GET    /api/taxii/connectors            -- list (secrets never included, matching GetThreatIntelConfig's precedent)
POST   /api/taxii/connectors            -- create
GET    /api/taxii/connectors/{id}       -- one
PUT    /api/taxii/connectors/{id}       -- update (empty password/clientCert/clientKey in the body keeps the stored value, matching PutThreatIntelConfig's precedent)
DELETE /api/taxii/connectors/{id}       -- delete (cascades taxii_ingested_objects via FK)
POST   /api/taxii/connectors/{id}/test  -- Discover() + ListCollections() only, no polling/writes -- mirrors TestThreatIntelConfig's existing "Test Connection" UX
POST   /api/taxii/connectors/{id}/sync  -- manual TriggerSync for that one connector's Poller
```

Reuses the existing `auth.CanViewConnectorStatus` (GET routes) and `auth.CanUpdateConnectorConfig` (POST/PUT/DELETE/test/sync) permissions — these are already connector-agnostic names (not `misp`/`opencti`-specific), so no new permission is needed.

## UI

A new "TAXII Connectors" section, styled as a real CRUD list (table + add/edit modal + delete confirm), modeled on the Scheduled Assessments list pattern — not the Integrations tab's fixed MISP/OpenCTI/OTX rows, since this is genuinely multi-instance. Each row shows name, server URL, enabled toggle, last poll status/time, and the last poll's processed/skipped/malformed counts. A "Test Connection" button next to the form calls the `/test` endpoint before save, matching the existing threat-intel config UX.

The IOC Registry tab's existing Origin filter dropdown gets one more `<option value="threat-feed">Threat feed</option>` (already listed as a *string* in the dropdown today — confirmed during the earlier IOC Registry conversation that it renders but nothing populates it; this spec is what finally wires it up). The Source filter dropdown gains `<option value="threat_feed">Threat feed</option>` alongside the existing four.

## Decisions

- **New enum values, not reuse of existing ones.** `SourceThreatFeed`/`StatusReported` are small, additive, and honest — forcing TAXII indicators into `SourceManual`/`StatusDraft` or `SourceDetectionAlert`/`StatusObserved` would misrepresent provenance (a manual import is a human typing a value in; a TAXII feed is automated; "observed" implies Audspect witnessed it in an execution, which intel-asserted data never was).
- **Plaintext secret storage**, matching `threat_intel_config.api_key`'s existing, unremarkable precedent — no new encryption-at-rest scheme invented for this one table. (An earlier version of this design used `_enc`-suffixed column names implying encryption; corrected during spec-writing after checking the actual `threat_intel_config` schema, which stores `api_key` as plain `text`.)
- **Per-connector poller/scheduler, not a shared one.** Each `taxii_connector_config` row gets its own `Poller` + `PollScheduler`, since configs are independently enabled/disabled/deleted at runtime — a single shared scheduler would need its own internal per-source enable/disable bookkeeping that `exercise.PollScheduler` doesn't provide, duplicating what `Manager` already does cleanly at the collection-of-pollers level.
- **24h default poll interval**, matching `internal/connector.Scheduler`'s existing default — TAXII feeds don't need tighter polling than MISP/OpenCTI already use, and `added_after` incremental polling keeps each poll cheap regardless of interval.

## Testing

- `internal/taxii/client_test.go`: a self-hosted, spec-compliant mock TAXII 2.1 HTTP server (via `httptest.Server`), exercising discovery, API-root discovery, collection discovery, successful polling, pagination (`next`), incremental polling (`added_after`), empty collections, HTTP errors, and auth failure (401/403 with both `none` and `basic` configs).
- `internal/taxii/stix_test.go`: bundle parsing + pattern parsing fixtures covering IPv4/IPv6/domain/URL/file-hash indicators, a composite/boolean pattern (→ skipped), a non-`indicator` SDO type (→ skipped), and malformed JSON (→ malformed) — each fixture built as realistic ISAC-shaped content, not FS-ISAC-specific.
- `internal/taxii/normalize_test.go`: idempotency — polling the same fixture twice produces one `iocs` row with `sighting_count` unchanged the second time (identical `stix_id`+`modified`); a bumped `modified` on the same `stix_id` produces a `sighting_count` bump; duplicate indicators within one bundle collapse via `iocs`' existing `(type,value)` constraint exactly as today.
- `internal/taxii/manager_test.go`: enabling/disabling/deleting a config row starts/stops/removes its `Poller` correctly (mirrors `vexsweep`/`emsweep` dispatcher test conventions already established this session).
- `internal/api/taxii_handlers_test.go`: CRUD + test + manual-sync endpoints, RBAC-gated, secrets never returned in GET responses.
- `internal/api/rbac_matrix_test.go`: 7 new route entries.
- Explicitly **not** tested against live FS-ISAC in this phase's automated suite — recorded as a manual QA item once real membership credentials are available (authentication, discovery, real collection/object structure, rate limits, pagination behavior against the real server).

## Self-review

- **Placeholder scan:** none — every section has concrete Go types, SQL, HTTP routes, or file paths.
- **Internal consistency:** the "no `connector.Scheduler` involvement" decision (Scope, Sync wiring) is upheld throughout — the API/UI sections describe a fully independent CRUD+poller stack, not an extension of the existing threat-intel config UI.
- **Scope check:** focused to a single implementation plan — one new package, two new tables, two new enum values, one new UI section. Phases 2-4 are named but explicitly not designed here.
- **Ambiguity check:** the exact idempotency key (`connector_id, stix_id, modified`), the exact set of supported STIX pattern forms, and the plaintext-secret-storage decision (corrected from an earlier draft) are all spelled out to avoid re-litigation during planning.
