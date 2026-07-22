# OTX Periodic Sync Job — Design Spec

**Goal:** give OTX a real periodic sync job by joining it to the existing MISP/OpenCTI/Bundle threat-intel scheduler as a fourth `connector.Source`, reusing sub-project 1's `Stats()`/`BySource` machinery instead of building a parallel sync mechanism. Sub-project 3 of 4 — see `docs/superpowers/specs/2026-07-22-connector-per-source-stats-design.md` (sub-project 1) and `docs/superpowers/specs/2026-07-22-connector-rich-status-cards-design.md` (sub-project 2) for the overall initiative context.

**Why now:** OTX today is on-demand-lookup-only (`internal/ioc/otx.go`'s `otxProvider`, used by `LookupIOC`) — it has zero periodic background job, unlike MISP/OpenCTI/Bundle which all sync on a schedule via `connector.Scheduler`. This sub-project gives OTX a real sync cycle; sub-project 4 will make that sync produce real threat actors (pulse → ATT&CK technique mapping), joining the scenario-generation pipeline.

---

## Scope

**In scope:**
- A new `connector.Source` implementation for OTX (`internal/connector/otx.go`), wired into `cmd/server/main.go`'s existing `tiSources` list alongside MISP/OpenCTI/Bundle.
- `Fetch()` calls OTX's `/pulses/subscribed` endpoint to get a real subscribed-pulse count, records it via `Stats()`, but returns **zero actors** — actor/technique extraction is sub-project 4's job, not this one.
- Shares the scheduler's single poll interval (`cfg.ThreatIntelPollHours`) — no new per-source interval config.

**Explicitly out of scope:**
- Mapping OTX pulses to ATT&CK techniques or threat actors — `Fetch()` returns `nil, nil` on success (no actors), deferred entirely to sub-project 4.
- Upgrading OTX's Settings UI row to a rich MISP/OpenCTI-style card — stays the existing simple "✓ Enabled / ✗ Not configured" row. A rich card showing "Actors extracted: 0" would read as broken rather than "not implemented yet"; revisit in sub-project 4 once that number is real.
- Any change to `Scheduler`, `ConnectorStatus`, or the `connectorStatusResponse` HTTP wrapper's structure — the existing `OTXEnabled: h.iocProvider != nil` field already reports the correct state (same underlying `cfg.OTXAPIKey != ""` gate) and needs no duplicate signal.
- A new `OTX_POLL_HOURS`-style config value — reuses the shared `cfg.ThreatIntelPollHours`.

## Design

### `OTXSource` (`orchestrator/internal/connector/otx.go`, new file)

A periodic-sync client, separate from `internal/ioc/otx.go`'s on-demand lookup client — matching this codebase's existing split between `internal/ioc` (on-demand indicator lookups) and `internal/connector` (periodic sync + scenario generation). The two clients share no code; each is a small, single-purpose HTTP client, consistent with how `MISPClient`/`OpenCTIClient` are each self-contained rather than sharing a base client abstraction.

```go
type OTXSource struct {
    apiKey     string
    httpClient *http.Client
    baseURL    string // overridden by tests; otxBaseURL in production
    lastStat   SourceStat
}

func NewOTXSource(apiKey string) *OTXSource {
    return &OTXSource{
        apiKey:     apiKey,
        httpClient: &http.Client{Timeout: 30 * time.Second},
        baseURL:    "https://otx.alienvault.com/api/v1",
    }
}

func (c *OTXSource) Name() string { return "otx" }

func (c *OTXSource) Fetch() ([]ThreatActor, error) {
    // GET {baseURL}/pulses/subscribed?limit=1, header X-OTX-API-KEY: {apiKey}
    // Decodes {"count": N, "results": [...]} (OTX's standard paginated-list
    // shape) — limit=1 keeps the request cheap since only the total count
    // is needed here, not individual pulse objects.
    //
    // On success: c.lastStat = SourceStat{Name: "otx", RawCount: count,
    // ActorCount: 0, FetchedAt: time.Now()}; returns nil, nil (zero actors,
    // no error — a clean no-op contribution to MergeActors).
    //
    // On failure (request error or non-200 status): c.lastStat =
    // SourceStat{Name: "otx", Error: err.Error(), FetchedAt: time.Now()};
    // returns nil, err — matches MISPClient.Fetch()'s error-propagation
    // pattern, which Scheduler.sync() already handles generically.
}

func (c *OTXSource) Stats() SourceStat { return c.lastStat }
```

`ActorCount` is always `0` for now — that's the honest state of sub-project 3, not a placeholder. `RawCount` is real (the account's actual subscribed-pulse count from OTX).

### Wiring (`orchestrator/cmd/server/main.go`)

Inserted after the existing Bundle block, before `gen := connector.NewGenerator(...)`:

```go
if cfg.OTXAPIKey != "" {
    tiSources = append(tiSources, connector.NewOTXSource(cfg.OTXAPIKey))
    log.Printf("[+] OTX connector configured (periodic sync)")
}
```

Reuses the existing `cfg.OTXAPIKey` (`OTX_API_KEY` env var) already read for the unrelated `iocProvider` on-demand-lookup wiring later in `main.go` — both consumers gate on the same config value independently, no new config surface.

### Why no `Scheduler`/`ConnectorStatus`/handler changes are needed

`Scheduler.sync()` (`internal/connector/scheduler.go`) already type-asserts every configured source against `StatsSource` generically:

```go
if ss, ok := src.(StatsSource); ok {
    bySource[src.Name()] = ss.Stats()
}
```

`OTXSource` implementing `StatsSource` is sufficient for `BySource["otx"]` to populate automatically on every sync — no scheduler code changes required. Similarly, `MergeActors`/`generator.Write` already treat a zero-actor source as a no-op (this is the same code path Bundle/MISP/OpenCTI already exercise when a sync returns nothing new).

`handlers.go`'s `connectorStatusResponse.OTXEnabled: h.iocProvider != nil` stays as-is — it already reports the correct enabled/disabled state under the same gate (`cfg.OTXAPIKey != ""`) that now also controls whether `OTXSource` joins `tiSources`. Adding a second `OTXEnabled` field to `connector.ConnectorStatus` itself (mirroring `MISPEnabled`/`OpenCTIEnabled`) would create two sources of truth for one boolean; not worth it for this sub-project. Its doc comment ("OTX has no sync/schedule of its own... so it doesn't belong in `connector.ConnectorStatus` itself") is stale after this change and will be updated to reflect that OTX now does sync, but the wrapper field itself stays.

### No frontend changes

OTX's Settings row already reads `s.otxEnabled` and renders "✓ Enabled / ✗ Not configured" — unchanged behavior, unchanged code.

## Testing

- `orchestrator/internal/connector/otx_test.go` (new), mirroring `misp_stats_test.go`/`opencti_stats_test.go`'s `httptest.Server` pattern:
  - `TestOTXSource_Stats_CountsSubscribedPulses`: server returns `{"count": 47, "results": [...]}`; asserts `Fetch()` returns zero actors and no error, and `Stats()` reports `RawCount: 47, ActorCount: 0`.
  - `TestOTXSource_Stats_RecordsErrorOnFailedFetch`: server returns non-200; asserts `Fetch()` returns an error and `Stats().Error` is set.
- Extend or add a `Scheduler`-level test alongside the existing `TestScheduler_Sync_PopulatesBySourcePerSource` (`scheduler_test.go`), using a `fakeSource` named `"otx"` returning zero actors with a populated `stats` field — confirms a zero-actor `StatsSource` doesn't disrupt `MergeActors`, `setOK`, or the other sources' results.
- No live-server smoke test needed — this sub-project has no frontend or HTTP-handler surface change; Go tests are the full verification surface.
