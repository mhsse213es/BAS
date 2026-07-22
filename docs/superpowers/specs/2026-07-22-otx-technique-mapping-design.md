# OTX Pulse → ATT&CK Technique Mapping — Design Spec

**Goal:** make `OTXSource.Fetch()` (`orchestrator/internal/connector/otx.go`, shipped in sub-project 3) return real `ThreatActor`s instead of always zero, joining the scenario-generation pipeline as a genuine fourth source alongside MISP/OpenCTI/Bundle. Sub-project 4 of 4 — the last of the connector auto-config initiative. See `docs/superpowers/specs/2026-07-22-connector-per-source-stats-design.md` (1), `docs/superpowers/specs/2026-07-22-connector-rich-status-cards-design.md` (2), `docs/superpowers/specs/2026-07-22-otx-periodic-sync-design.md` (3) for prior context.

**Why now:** sub-project 3 deliberately deferred actor/technique extraction, flagging a real open question: does the bundled ATT&CK data have the Groups/intrusion-set layer needed to map OTX's adversary-name-based pulses to techniques? Investigation for this spec found it does — `internal/reporting/attackdata.GroupTechniqueIndex()` already inverts MITRE's authoritative STIX data into `map[string][]string` (ATT&CK group name → technique IDs), and is already used elsewhere (`internal/api/ti_handlers.go`'s `ransomwarePackTechs`, `internal/recommend/recommend.go`'s `actorCounts()`). This sub-project reuses that index rather than building anything new.

---

## Scope

**In scope:**
- `OTXSource.Fetch()` pages through `/pulses/subscribed`, extracts each pulse's `adversary` field, and exact-matches it against `attackdata.GroupTechniqueIndex()`'s keys.
- On a match, the resulting `ThreatActor.Techniques` = MITRE's own authoritative technique list for that group (from the index) — not anything parsed from the pulse's own tags.
- Pulses matching the same group merge into one actor (mirrors `MISPClient.Fetch()`'s `actorMap` pattern).
- A bounded fetch: most-recent 500 pulses per sync (10 pages × `limit=50`), not unbounded pagination.

**Explicitly out of scope:**
- Parsing individual pulse tags for embedded technique IDs (T1059-shaped strings) — rejected as a primary strategy; OTX pulse tagging is inconsistent and unverified, whereas the MITRE-authoritative Groups index is reliable and already proven in production use elsewhere in this codebase.
- Fuzzy/substring matching of adversary names (e.g. `ransomwarePackTechs`'s `strings.Contains` approach) — this sub-project uses exact match only (see Design). A future substring-matching upgrade, if the exact-match hit rate proves too low against a real account, is a separate later decision, not part of this sub-project.
- Any change to `Scheduler`, `ConnectorStatus`, the HTTP handler, or the frontend — sub-project 3 already wired `OTXSource` into the scheduler and `Stats()`/`BySource` machinery; this sub-project only changes what `Fetch()` returns.
- Sectors/regions on OTX-sourced actors — OTX pulses don't carry this data in a form worth extracting yet (mirrors OpenCTI's existing `sectors` field being present-but-unused, documented rather than half-implemented).

## Design

### Pagination (`OTXSource.Fetch()`, replacing sub-project 3's `limit=1` call)

```
GET /pulses/subscribed?limit=50&page=1
GET /pulses/subscribed?limit=50&page=2
...
```

Loops until either 10 pages have been fetched (500 pulses) or a page's `results` comes back empty/short (end of data), whichever comes first. This assumes OTX returns pulses ordered most-recently-modified-first by default and that each pulse object carries a singular `adversary` string field — **unverifiable without a live OTX account**, stated plainly here with the same honesty standard as the existing OpenCTI sector/region comment (`internal/connector/opencti.go`). If either assumption is wrong in practice, the sync degrades gracefully: either to fewer matched actors (if `adversary` is absent/empty on most pulses) or to an arbitrary rather than "most recent" 500-pulse sample — never to a crash or fabricated data. This should be verified against a real OTX account before sub-project 4 is considered fully proven.

### Actor extraction

```go
type otxPulse struct {
    Name      string `json:"name"`
    Adversary string `json:"adversary"`
    Modified  string `json:"modified"` // RFC3339
}
type otxPulsesResponse struct {
    Count   int        `json:"count"`
    Results []otxPulse `json:"results"`
}
```

For each pulse across all fetched pages:
1. Skip if `Adversary == ""`.
2. Normalize: `key := strings.ToUpper(strings.TrimSpace(pulse.Adversary))`.
3. Look up `key` against a normalized copy of `attackdata.GroupTechniqueIndex()`'s keys (the index itself is keyed by MITRE's original-case group names, e.g. `"Wizard Stinger"` — normalization happens on both sides for the comparison, but the actor is stored under the **original MITRE casing**, not the normalized form, so it matches the naming convention MISP/Bundle actors already use).
4. No match → skip this pulse (expected — most OTX adversary names won't hit a MITRE-named group).
5. Match → get-or-create a `ThreatActor` keyed by the matched MITRE group name: `Techniques` set once (from the index, converted to `[]TechniqueRef{ID: id}` — no `Name`/`Tactic`, matching what the index provides), `Source: "otx"`, `Confidence: "medium"` (same fallback MISP uses when it can't determine confidence), `LastSeen` updated to the latest pulse's parsed `Modified` seen for that actor.

`RawCount` = number of pulses actually fetched this sync (bounded by the pagination cap above) — **note this changes RawCount's meaning from sub-project 3**, where it was the account's total subscribed-pulse count (`parsed.Count` from a single `limit=1` call). The new meaning ("items examined for the actor-extraction filter") matches MISP's and OpenCTI's existing `RawCount` semantics exactly (their `RawCount` is always "however many raw items were examined," never an unbounded account-wide total), so this is a correction toward consistency, not a regression. `ActorCount` = number of distinct matched actors.

### Error handling

- First-page request failure (network error or non-200 status): `Fetch()` returns `nil, err` immediately — unchanged from sub-project 3's existing behavior for a first-request failure.
- A failure on page 2+ (after at least one page succeeded): pagination stops, and `Fetch()` returns whatever actors were successfully extracted from the pages gathered so far, **with** the error — `return actors, err`. This differs from returning nothing on a partial failure; deliberately, since a partial page's worth of real work shouldn't be discarded just because a later page failed. `Scheduler.sync()` already logs the error and continues to the next source on any non-nil error from `Fetch()` — but currently discards whatever actors a failing source's `Fetch()` call returned alongside the error (`if err != nil { ...; continue }` skips the `actors = append(...)` line entirely). **This is a pre-existing `Scheduler.sync()` behavior, not something this sub-project changes** — flagging it here because it means a partial-failure OTX sync's recovered actors won't actually reach `MergeActors` today. Fixing that is a `Scheduler.sync()` change affecting all sources uniformly, out of scope for this sub-project; OTX's partial-failure path is implemented correctly (returns useful data) even though the scheduler doesn't yet use it. Worth a future, separate sub-project if partial-failure data recovery ever matters in practice — not blocking here.

### Testing

`attackdata.GroupTechniqueIndex()` already has an established, stable test fixture: `"Wizard Spider"` (`attackdata_test.go`'s `TestGroupTechniqueIndex_ContainsKnownGroupAndTechnique`, also relied on by `internal/api/ti_suggest_pack_test.go`'s ransomware-pack test). This sub-project's tests reuse the same real group name rather than inventing a fake/injectable index:

- `orchestrator/internal/connector/otx_test.go` (extending sub-project 3's file):
  - `TestOTXSource_Fetch_MatchesKnownGroupToAuthoritativeTechniques`: `httptest.Server` returns one page with a pulse whose `adversary` is `"Wizard Spider"` (any case/whitespace variant, to also exercise normalization) — asserts the returned `ThreatActor` has `Name: "Wizard Spider"`, `Source: "otx"`, and `Techniques` non-empty and matching `attackdata.GroupTechniqueIndex()["Wizard Spider"]` exactly.
  - `TestOTXSource_Fetch_SkipsUnmatchedAdversary`: a pulse with `adversary: "Some Made Up Actor Name Zzyzx"` — asserts zero actors returned.
  - `TestOTXSource_Fetch_SkipsEmptyAdversary`: a pulse with `adversary: ""` — asserts zero actors returned, no panic.
  - `TestOTXSource_Fetch_PaginatesUpToCap`: mock server serving 11 pages of 50 synthetic pulses each (all with empty `adversary`, to keep the test focused on pagination count rather than matching) — asserts the mock server received exactly 10 page requests (not 11), and `Stats().RawCount == 500`.
  - `TestOTXSource_Fetch_StopsOnShortPage`: mock server's page 1 returns 30 results (fewer than `limit=50`) — asserts pagination stops after page 1 without a second request, and `RawCount == 30`.
  - `TestOTXSource_Fetch_PartialFailureReturnsActorsGatheredSoFar`: page 1 succeeds with a `"Wizard Spider"` pulse, page 2 returns HTTP 500 — asserts `Fetch()` returns a non-nil error **and** one actor (the page-1 result), and `Stats().Error` is set.
  - Existing sub-project 3 tests (`TestOTXSource_Stats_CountsSubscribedPulses`, `TestOTXSource_Stats_RecordsErrorOnFailedFetch`) will need updating: they currently assert against the `limit=1`/single-page/`Count`-field behavior being replaced here. The plan will show the exact updated versions.
- No `Scheduler`-level test changes needed — `Scheduler.sync()`'s generic handling of any `Source`/`StatsSource` already covers a source that now happens to return non-empty actors (sub-project 1's `TestScheduler_Sync_PopulatesBySourcePerSource` already tests a source with real actors, via `misp`).
- No frontend changes, no live-server smoke test — same reasoning as sub-project 3 (no HTTP-handler or `wwwroot` surface touched).
