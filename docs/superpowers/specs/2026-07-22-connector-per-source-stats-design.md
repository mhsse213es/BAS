# Threat-Intel Connector Per-Source Stat Tracking — Design Spec

**Goal:** track MISP's and OpenCTI's raw fetch numbers separately instead of only a single combined total, so a future UI can show each connector's own real numbers (sub-project 2 of the "Caldera-like auto-config" initiative — see `MEMORY.md` project note). This is sub-project 1 of 4; it ships independently and produces no user-visible change on its own (backend-only, additive JSON field).

**Why now:** `internal/connector/scheduler.go`'s `sync()` method fetches from every configured `Source` (MISP, OpenCTI, the air-gapped bundle) into one shared `actors` slice, merges them, and only ever persists the combined total (`ConnectorStatus.TotalActors`). Each source's own raw fetch count is already computed internally and even logged (`log.Printf("[connector/misp] fetched %d events", len(events))`, `log.Printf("[connector/opencti] fetched %d threat actors", len(actorsRaw))`) — it's just discarded immediately after. There is currently no way to answer "how many did MISP contribute vs. OpenCTI" from the API.

---

## Architecture

### New type: `SourceStat`

In `orchestrator/internal/connector/types.go`, alongside `ConnectorStatus`:

```go
// SourceStat is one threat-intel source's numbers from its most recent fetch.
// RawCount and ActorCount differ because MISP/OpenCTI results are filtered to
// actors with 2+ mapped ATT&CK techniques before being merged — RawCount is
// what the source returned before that filter (MISP: events; OpenCTI: raw
// threat-actor nodes), ActorCount is what passed it. The bundle source applies
// no such filter, so its RawCount and ActorCount are always equal.
type SourceStat struct {
	Name       string    `json:"name"`      // "misp" | "opencti" | "bundle"
	RawCount   int       `json:"rawCount"`
	ActorCount int       `json:"actorCount"`
	FetchedAt  time.Time `json:"fetchedAt"`
	Error      string    `json:"error,omitempty"` // set instead of counts when this source's fetch failed
}
```

`ConnectorStatus` gains one field:

```go
BySource map[string]SourceStat `json:"bySource,omitempty"` // keyed by Source.Name()
```

### New optional interface: `StatsSource`

```go
// StatsSource is implemented by sources that can report their last fetch's raw
// numbers. Checked via type assertion in Scheduler.sync (the same pattern
// already used there for *BundleSource's Version()) — sources that don't
// implement it (e.g. test fakes) are simply skipped, not an error.
type StatsSource interface {
	Stats() SourceStat
}
```

Each production source stores its last fetch's numbers on itself and implements `Stats()`:

- **`MISPClient`** (`misp.go`): add a `lastStat SourceStat` field. At the end of `Fetch()`, after `events` and `out` are computed, set `c.lastStat = SourceStat{Name: "misp", RawCount: len(events), ActorCount: len(out), FetchedAt: time.Now()}` before returning. Add `func (c *MISPClient) Stats() SourceStat { return c.lastStat }`.
- **`OpenCTIClient`** (`opencti.go`): same pattern — `RawCount: len(actorsRaw)`, `ActorCount: len(actors)`.
- **`BundleSource`** (`bundle.go`): same pattern — `RawCount` and `ActorCount` both `len(bundle.Actors)` (no filter applied here).
- **On a fetch error**, each client still records a `SourceStat{Name: ..., Error: err.Error(), FetchedAt: time.Now()}` before returning the error, so a failed source is distinguishable from one that returned zero actors.

### Scheduler wiring (`scheduler.go`)

In the existing per-source loop inside `sync()`:

```go
for _, src := range s.sources {
    got, err := src.Fetch()
    if err != nil {
        log.Printf("[connector/%s] fetch error: %v", src.Name(), err)
        s.setError(src.Name() + ": " + err.Error())
        continue
    }
    ...
}
```

Add stat capture right after each `Fetch()` call (success or failure), accumulating into a `map[string]SourceStat` that's threaded through to `setOK`/`setError` the same way `bundleVersion` already is:

```go
bySource := map[string]SourceStat{}
...
for _, src := range s.sources {
    got, err := src.Fetch()
    if ss, ok := src.(StatsSource); ok {
        bySource[src.Name()] = ss.Stats()
    }
    if err != nil {
        log.Printf("[connector/%s] fetch error: %v", src.Name(), err)
        s.setError(src.Name()+": "+err.Error(), bySource)
        continue
    }
    ...
}
...
s.setOK(result.Created, result.Updated, len(actors), bundleVersion, bySource)
```

`setOK`/`setError` both gain a `bySource map[string]SourceStat` parameter and set `s.status.BySource = bySource` under the existing mutex lock (same pattern as every other field they already set).

**Snapshot semantics, not accumulation:** `BySource` is fully replaced each sync tick (matching how `TotalActors` is overwritten with `=`, not accumulated like `ScenariosCreated`/`ScenariosUpdated` with `+=`) — it always reflects the most recent sync, not a running total across ticks. A source with no entry in the map (because it isn't configured, matching the existing `MISPEnabled`/`OpenCTIEnabled`/`BundleEnabled` flag semantics) simply doesn't appear as a key.

### What this does NOT do (explicitly out of scope)

- No new API calls to MISP/OpenCTI for fields like Feeds, Server Version, or Tags — those aren't computed anywhere in this codebase today, and identifying which are feasible is sub-project 2's job once the UI design is locked in.
- No UI changes — this is purely a backend data-capture change. `GET /api/connector/status`'s response gains one new optional field; nothing currently parses or displays it.
- No OTX involvement — OTX has no periodic sync yet (that's sub-project 3) and isn't a `Source` in this scheduler at all yet (sub-project 4).

## Testing

- `MISPClient`/`OpenCTIClient`/`BundleSource`: unit test that `Stats()` returns the right `RawCount`/`ActorCount` after a `Fetch()` call, using each client's existing test fixtures/mocked HTTP responses (`misp_filter_test.go`, `bundle_test.go` already have the scaffolding for this).
- `Scheduler`: extend `scheduler_test.go`'s `fakeSource` with a `stats SourceStat` field and a `Stats()` method returning it. Go interfaces are structural — adding `Stats()` to `fakeSource` means *every* `fakeSource` value satisfies `StatsSource` from then on, including in the existing tests that don't set `stats` (they'll just get a zero-value `SourceStat` in `BySource`, which none of them assert on, so this is harmless). No need for a second fake type or a "does it implement `StatsSource`" test — the `ok` false-branch of the type assertion in `scheduler.go` is a standard, well-understood Go idiom that doesn't need dedicated coverage. New test: after a sync with two fake sources (one erroring, one succeeding), `Status().BySource` contains both entries with the right shape — the erroring one has `Error` set and zero counts, the succeeding one has real counts.
