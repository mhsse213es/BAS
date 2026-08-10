# Threat Intel Connector Config (MISP / OpenCTI / OTX) — Design

## Why

MISP, OpenCTI, and OTX are currently configured exclusively via `.env`
(`MISP_URL`/`MISP_API_KEY`, `OPENCTI_URL`/`OPENCTI_API_KEY`, `OTX_API_KEY`),
read once at process startup into `internal/connector.Scheduler`'s fixed
`sources []Source` slice. Changing a URL or rotating an API key means
editing `.env` and restarting the orchestrator container — real ops
overhead the user wants eliminated, matching how OpenAEV's connector
already works today: a DB-backed config with a real UI form, a Test
Connection button, and Save — no file editing, no restart.

## Existing reference implementation: OpenAEV

`openaev_config` (singleton row), `orchestrator/internal/api/openaev_handlers.go`:
- `GET /api/openaev/config` — Admin. Never returns the stored bearer token.
- `PUT /api/openaev/config` — Admin. If the submitted token is empty string,
  the existing stored token is kept (`CASE WHEN EXCLUDED.bearer_token = ''
  THEN openaev_config.bearer_token ELSE EXCLUDED.bearer_token END`) — the UI
  never has to display a secret back to prove it's set.
- `POST /api/openaev/config/test` — Admin. Builds a real provider from the
  submitted (not-yet-saved) values and does a live connectivity check.
- `POST /api/openaev/sync` — Admin. Manual trigger; builds a fresh provider
  from whatever's currently in the DB.

Frontend (`wwwroot/index.html`, Settings → Threat Intel Connector panel,
`loadOpenAEVConfig`): URL text input, password-type API-key input
(placeholder "leave blank to keep current"), Enabled checkbox, Test
Connection / Save / Sync Now buttons, inline pass/fail result text.

This is the pattern this spec replicates for MISP, OpenCTI, and OTX — with
one real architectural addition OpenAEV didn't need (see below).

## The architectural gap OpenAEV doesn't have

OpenAEV has no persistent background poll loop holding a stale reference —
every sync (manual or scheduled) builds a fresh provider from current DB
state at call time, so there's nothing to "reconfigure."

MISP/OpenCTI/OTX are different: `internal/connector.Scheduler` is a
long-lived object whose `sources []Source` field is set once in
`NewScheduler(...)` (called once, in `cmd/server/main.go`) and never
reassigned anywhere in the current code. A background goroutine
(`Scheduler.run()`) polls those exact source objects on a ticker forever.
Simply adding a DB-backed config UI on top of this, without more, would
still require a restart for a saved change to actually take effect — the
UI would lie about what "Save" accomplished.

OTX has a second wrinkle: its API key is independently consumed a *second*
time at startup, building a standalone `ioc.Provider` (`h.iocProvider`,
used by `LookupIOC`) — separate from its entry in `Scheduler.sources`. Both
consumers need to pick up a changed key for OTX reconfiguration to be real.

## Design

### Data model
One shared table (MISP/OpenCTI/OTX's config shapes overlap enough that
three near-identical tables would be pure duplication):

```sql
CREATE TABLE IF NOT EXISTS threat_intel_config (
    connector         text PRIMARY KEY,  -- 'misp' | 'opencti' | 'otx'
    base_url          text NOT NULL DEFAULT '',  -- unused for otx
    api_key           text NOT NULL DEFAULT '',
    enabled           boolean NOT NULL DEFAULT false,
    last_sync_at      timestamptz,
    last_sync_status  text NOT NULL DEFAULT 'never',
    last_error        text NOT NULL DEFAULT '',
    updated_at        timestamptz NOT NULL DEFAULT NOW()
);
```

Poll interval (`THREAT_INTEL_POLL_HOURS`) is explicitly **not** moved into
this table — it stays a shared, rarely-changed, env-configured cadence for
the one `Scheduler`, exactly as today. This wasn't the reported pain point
(URL/key rotation was), and splitting it per-connector would mean
restructuring one ticker into three independent ones for no requested
benefit — see Non-goals.

`api_key` is stored in plain text, matching `openaev_config.bearer_token`'s
existing precedent exactly (explicit decision — see Non-goals for why
encryption-at-rest is out of scope here).

### Startup migration (env → DB, one-time, per connector)
On boot, for each of `misp`/`opencti`/`otx`: if the DB row doesn't exist
yet, or exists with an empty `api_key`, **and** the matching env var(s) are
set, write them into the DB once (`base_url`/`api_key` from the env vars,
`enabled = true`). After that the DB row is authoritative for that
connector and the env var is never consulted again unless the row somehow
goes back to empty. This means an already-deployed instance (e.g. the HDFC
prod client, which may already have these set in `.env` today) keeps
working with zero manual action after upgrading — the UI will simply show
the migrated values, editable, with the API key field blank (per the
"never return the stored secret" rule) but Enabled already checked.

### Backend — generic handlers, not three copies
`orchestrator/internal/api/threat_intel_config_handlers.go` (new), all
parameterized by a `{connector}` URL param restricted to `misp|opencti|otx`
(any other value is a 400):

- `GET /api/threat-intel/{connector}/config` — `CanViewConnectorStatus`
  (existing permission, already Admin-only, already gates the read-only
  status cards this replaces). Returns `baseUrl`/`enabled`/
  `lastSyncStatus`/`lastError` — never `apiKey`.
- `PUT /api/threat-intel/{connector}/config` — new `CanUpdateConnectorConfig`
  permission (Admin-only, added via the same 4-const-site + 3-test-site
  pattern used earlier this session for `CanViewAgentGroups`/
  `CanTargetAllAgents`). Same "empty submitted key keeps the existing one"
  UPSERT pattern as `PutOpenAEVConfig`. After a successful write, triggers
  the live-reconfigure step below.
- `POST /api/threat-intel/{connector}/config/test` — `CanUpdateConnectorConfig`.
  Builds the real client (`connector.NewMISPClient`/`NewOpenCTIClient`, or
  an OTX equivalent) from the *submitted* (not-yet-saved) values and
  performs one lightweight live call, reporting ok/error — exact mirror of
  `TestOpenAEVConfig`.

The existing shared `POST /api/connector/sync` (`CanSyncConnector`) is
unchanged — it already triggers whatever's currently enabled across all
sources; no per-connector sync endpoint is added.

### Live reconfiguration (the actual restart-elimination mechanism)
`internal/connector.Scheduler` gains:
```go
func (s *Scheduler) Reconfigure(sources []Source) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.sources = sources
    // recompute s.status's per-connector Enabled flags from the new list,
    // exactly as NewScheduler's constructor loop already does today
}
```
Every successful `PUT .../config` call reads **all three** connectors'
current DB state (not just the one just saved — enabling MISP must not
accidentally drop an already-enabled OpenCTI), rebuilds the full
`tiSources` slice the same way `cmd/server/main.go` does at startup today,
and calls `scheduler.Reconfigure(tiSources)`.

For `connector == "otx"` specifically, the same save path also rebuilds
`h.iocProvider` (behind a mutex or atomic pointer swap, since it's read
concurrently by in-flight `LookupIOC` requests) so both OTX consumers stay
in sync with each other.

`cmd/server/main.go` changes to build its *initial* `tiSources`/
`iocProvider` by reading `threat_intel_config` (after the seed-from-env
step runs) rather than reading `cfg.MISPUrl`/`cfg.OpenCTIUrl`/
`cfg.OTXAPIKey` directly — the DB becomes the single source of truth from
boot onward, not just after the first UI save.

### Frontend
`wwwroot/index.html`, Settings → Threat Intel Connector panel. The three
existing read-only cards (`cs-misp-card`, `cs-opencti-card`, OTX's row in
`connector-status-card`) each gain an OpenAEV-style editable block —
inserted *above* their existing read-only stats (Events/Actors
extracted/Last Fetch etc. stay exactly as they are, still useful live
status info, not replaced):
- MISP/OpenCTI: URL text input + password-type API-key input + Enabled
  checkbox.
- OTX: password-type API-key input + Enabled checkbox only (no URL field —
  it's a single hosted service, not self-hosted like MISP/OpenCTI).
- Each gets its own Test Connection / Save button pair and inline
  pass/fail result text, matching `testOpenAEVConfig()`/
  `saveOpenAEVConfig()` exactly in structure (new `testConnectorConfig(name)`/
  `saveConnectorConfig(name)` functions parameterized by connector name,
  not three copy-pasted pairs).
- The existing shared "Sync Now" button (`triggerConnectorSync()`) is
  unchanged.

## Non-goals

- **No encryption-at-rest for API keys.** Explicit decision: match
  `openaev_config`'s existing plain-text precedent for all three new
  connectors rather than solving a broader secrets-management problem here
  (which would need its own encryption-key custody story — e.g. where does
  *that* key live, which risks reintroducing an env-var dependency for the
  one credential that protects all the others). If encryption-at-rest is
  ever pursued, it should cover OpenAEV's existing table too, as one
  separate piece of work, not be bolted onto this one unevenly.
- **No per-connector poll interval.** `THREAT_INTEL_POLL_HOURS` stays one
  shared, env-configured cadence for the single `Scheduler`. Not the
  reported pain point; splitting it into three independent tickers is a
  separate, unrequested piece of complexity.
- **No new per-connector Sync endpoint.** The existing shared
  `POST /api/connector/sync` already covers all enabled sources together;
  duplicating it three ways adds surface area with no behavioral gain.
- **`ThreatIntelSectors`/`ThreatIntelRegions`** (passed to
  `NewMISPClient`/`NewOpenCTIClient` today, sourced from other env vars)
  stay env-configured — out of scope, not mentioned in the original ask,
  and not part of the "API and URL" fields the user specifically asked to
  move into the console.
- **`.env` is not removed or deprecated as a deployment mechanism** —
  it remains the bootstrap path for a brand-new install (the seed-once
  logic explicitly depends on it existing for that case); this spec only
  removes the *requirement* to keep hand-editing it after initial setup.

## Testing plan

- Backend: table-driven tests for the generic config handlers per
  connector (get/put/test, empty-key-keeps-existing, invalid `{connector}`
  value → 400), the env-to-DB seed logic (row absent + env set → seeded;
  row present → not overwritten), `Scheduler.Reconfigure` (source list and
  status flags update correctly, concurrent-safe), and the OTX
  dual-consumer reconfiguration (both `Scheduler.sources` and
  `h.iocProvider` reflect a saved key change).
  `go test ./internal/connector/...`, `go test ./internal/api/...`.
- Frontend: manual browser QA (no automated suite for this file, per this
  project's established convention) — deferred to the existing Pending
  Manual QA Backlog pattern, not blocking implementation.
