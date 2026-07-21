# IOC Threat-Intel Enrichment — Design

**Status:** Approved (pending final user sign-off on this written doc)
**Sub-project:** C of 3, under the LevelBLUE OTX threat-intel initiative — final piece
**Depends on:** Sub-project A — `internal/ioc.Provider` interface + OTX client (DONE, `1000f7b`/`0fe0e43`/`1d5909b`/`f8f25a9`); Sub-project B — `run_iocs` extraction + storage (DONE, `4edc15a`/`87e2f1e`/`82b72ad`/`3b815b1`)

## Terminology

This is **enrichment**, not correlation. Correlation would be IOC↔Alert, IOC↔Finding, IOC↔Asset — cross-referencing BAS's own data. What this sub-project does is take an IOC already known from a run and ask an external threat-intel source "is this seen elsewhere in the world." Naming throughout reflects that: `enrichRunIOCs`, `ioc_enrichment`, `populateThreatIntel`. Nothing here is called "correlate."

## Architecture

```
run_iocs (sub-project B — the IOC repository)
    │  SubmitScenarioResult, right after extraction persists
    ▼
go h.enrichRunIOCs(ctx, runID)   ← background, non-blocking, never blocks the HTTP response
    │  for each distinct indicator in the run:
    │    cache row exists AND not expired → skip (no external call)
    │    else → ioc.Lookup(ctx, provider, type, value) → external call → cache write (success or failure, both start a fresh TTL clock)
    ▼
ioc_enrichment (new cache table — global, provider-aware, schema-versioned)
    │
    ▼  (BuildFromRun reads this — NEVER calls a provider live)
FullReport.ThreatIntel  →  HTML/PDF "Threat Intelligence" section
```

**Pipeline shape is extraction → repository → enrichment → provider(s)**, not extraction → OTX directly:
- `run_iocs` is the repository — provider-agnostic, already built in sub-project B.
- `ioc.Lookup(ctx, provider ioc.Provider, indicatorType, value string) (*ioc.Result, error)` (new, `internal/ioc/lookup.go`) is the enrichment pipeline's single provider-dispatch point — extracted from the existing `LookupIOC` HTTP handler (sub-project A), which currently duplicates this exact switch inline. Both the handler and the new background job call the same function afterward.
- The cache (`ioc_enrichment`) is keyed `(indicator_type, indicator_value, provider)` — provider-aware from day one, so `1.2.3.4` from OTX and `1.2.3.4` from a future VirusTotal/MISP/GreyNoise provider are distinct rows, never collide, and adding a new provider later is purely additive (new rows, no migration).
- **What this sub-project does NOT build:** true multi-provider fan-out (calling OTX *and* VirusTotal for the same indicator and merging/showing both). Sub-project A deliberately chose a single-active-provider config model (`OTX_API_KEY` env var, one `ioc.Provider` wired into `Handler`) — that decision stands here. `enrichRunIOCs` calls whichever one provider is configured, same as the existing lookup endpoint. The schema and dispatch function are shaped so fan-out is a later additive change, not a redesign — but building it now would be scope creep against an already-made architectural call.

## Which indicators get enriched

All of them — because `run_iocs` already only ever contains `ip`/`domain`/`url`/`hash`/`cve` (sub-project B's extractor doesn't match filenames, process names, registry keys, mutexes, or private/loopback IPs at all — `svchost.exe`/`cmd.exe`-style strings are filtered by the domain extension blocklist, `127.0.0.1`/`192.168.x.x` are filtered as private/reserved). The "only enrich threat-intel-relevant types" concern is already fully satisfied by sub-project B's scope; there's no additional filtering to add here.

## Cache: `ioc_enrichment`

```sql
CREATE TABLE IF NOT EXISTS ioc_enrichment (
    id                BIGSERIAL PRIMARY KEY,
    indicator_type    TEXT NOT NULL,
    indicator_value   TEXT NOT NULL,
    provider          TEXT NOT NULL,              -- "otx" (extensible)
    provider_version  TEXT NOT NULL DEFAULT '',    -- forward-compat; OTX exposes none today, left blank
    schema_version    SMALLINT NOT NULL DEFAULT 1, -- bump when the parsed-fields shape changes
    pulse_count       INT NOT NULL DEFAULT 0,
    pulse_names       JSONB NOT NULL DEFAULT '[]',
    malware_families  JSONB NOT NULL DEFAULT '[]',
    adversary_names   JSONB NOT NULL DEFAULT '[]',
    industries        JSONB NOT NULL DEFAULT '[]',
    tags              JSONB NOT NULL DEFAULT '[]', -- NEW: see "Extending sub-project A" below
    raw_response      JSONB,                       -- provider's raw response, for debugging/future re-parse
    lookup_duration_ms INT,
    last_success_at   TIMESTAMPTZ,
    last_failure_at   TIMESTAMPTZ,
    last_error        TEXT,
    ttl_expires_at    TIMESTAMPTZ NOT NULL,         -- both success AND failure paths set this — see below
    UNIQUE(indicator_type, indicator_value, provider)
);
CREATE INDEX IF NOT EXISTS idx_ioc_enrichment_ttl ON ioc_enrichment(ttl_expires_at);
```

Global (not per-run, not per-tenant): OTX's pulse count for `1.2.3.4` is the same fact no matter which run or tenant asked, so one lookup serves every future run sharing that indicator — this is what makes the 24h TTL actually pay off.

**Failures are cached too, with their own TTL.** If a lookup errors (network failure, OTX down, rate-limited), `enrichRunIOCs` still writes a row: `last_failure_at`, `last_error` set, `ttl_expires_at = now + 24h` (same TTL as success — kept uniform for this first pass; a shorter failure-retry window is a reasonable future refinement, not built now). Without this, a struggling or rate-limited provider would get hammered by every single run's enrichment pass instead of backing off. A failure does **not** clear a previous success's pulse/malware/adversary data — if indicator `X` was successfully enriched yesterday and today's re-check errors, yesterday's data stays visible in the cache (and therefore in reports) while `last_failure_at`/`last_error` record that today's refresh attempt failed. This is also exactly the operational visibility (why did enrichment fail, is the cache stale, is the provider throttling us) that was missing from the first draft.

`schema_version` exists so that if OTX's response shape changes, or a future provider is added with a richer field set (geo, ASN, campaigns, TLP), old cached rows are identifiable and can be selectively re-fetched rather than silently misread.

## Extending sub-project A: `Tags` on `ioc.Result`

`otx.go`'s response struct already unmarshals per-pulse `Tags []string` (`internal/ioc/otx.go:53`) but the field is discarded — never aggregated into the returned `Result`. Since "Tags" is explicit, real, already-available OTX data (not a fabricated field), this is a small additive fix to already-shipped code: aggregate unique tags across all pulses into a new `Result.Tags []string` field. Existing `otx_test.go` cases are unaffected; a new test covers tag aggregation/dedup. This does **not** touch `Confidence`, `PulseCount`, or any other existing field/behavior.

**What is explicitly NOT added:** First Seen / Last Seen / References. These were requested but sub-project A's OTX client doesn't currently parse them, and I haven't re-verified against OTX's live API docs whether `/indicators/{type}/{value}/general` even returns them in a directly usable shape — sub-project A's original grounding only confirmed `pulse_info.count`, `pulse_info.pulses[].name/tags`, and `pulse_info.related.alienvault.*`. Adding fields I haven't verified would risk fabricating a schema. If these matter, re-grounding OTX's response shape (a WebFetch pass) is a small, separate follow-up before implementation — flagging rather than guessing.

## Report section

**No "confidence" label.** OTX doesn't provide an authoritative confidence score, and presenting pulse-count buckets as "confidence" implies certainty that isn't there. The report shows the observed fact (pulse count) and a plain, honestly-labeled tier derived from it — not reusing `ioc.Result.Confidence`'s naming, just its existing 0 / 1–2 / 3+ thresholds (unchanged from sub-project A) under different, more honest report labels:

- **Malicious-Associated** — 3+ pulses
- **Suspicious** — 1–2 pulses
- **Unknown** — looked up, 0 pulses (OTX has no record of it — genuinely "unknown," not "clean," since absence of pulses isn't proof of safety)
- **Pending** — extracted but not yet enriched (no cache row yet — normal for a report generated shortly after a run, before the background pass catches up)

`FullReport` (in `internal/reporting/engine.go`) gains:

```go
// ThreatIntel is the OTX (or configured provider) enrichment of this run's
// extracted IOCs. Nil when the run has no IOCs. Populated by BuildFromRun
// only (single-run reports) -- see "Report scope" below.
ThreatIntel *ThreatIntelSection `json:"threatIntel,omitempty"`
```

```go
type ThreatIntelSection struct {
	Provider   string                  `json:"provider"` // "otx"
	Summary    ThreatIntelSummary      `json:"summary"`
	Indicators []ThreatIntelIndicator  `json:"indicators"` // sorted: Malicious-Associated, Suspicious, Unknown, Pending
}

type ThreatIntelSummary struct {
	ExtractedCount           int `json:"extractedCount"`
	PendingCount             int `json:"pendingCount"`
	UnknownCount             int `json:"unknownCount"`
	SuspiciousCount          int `json:"suspiciousCount"`
	MaliciousAssociatedCount int `json:"maliciousAssociatedCount"`
}

type ThreatIntelIndicator struct {
	Type            string   `json:"type"`  // ip | domain | url | hash | cve
	Value           string   `json:"value"`
	TechniqueIDs    []string `json:"techniqueIds"`
	SimulationIDs   []string `json:"simulationIds"`
	Tier            string   `json:"tier"` // pending | unknown | suspicious | malicious-associated
	PulseCount      int      `json:"pulseCount"`
	PulseNames      []string `json:"pulseNames,omitempty"`
	MalwareFamilies []string `json:"malwareFamilies,omitempty"`
	AdversaryNames  []string `json:"adversaryNames,omitempty"`
	Industries      []string `json:"industries,omitempty"`
	Tags            []string `json:"tags,omitempty"`
}
```

Populated by a new `populateThreatIntel(ctx, report, runID)` on `Engine`, called from `BuildFromRun` right after `populateKEVExposure` — following the exact convention every other optional section already uses (self-contained SQL via `e.db.Query`, mutate `report` in place, no-op/leave-nil when there's nothing to show). One query: `run_iocs LEFT JOIN ioc_enrichment ON (type, value, provider = $activeProvider)`, so indicators with no cache row yet still appear (tier = pending).

`Engine` needs to know which provider's cache rows to read — the cache is provider-keyed, so an unfiltered join risks ambiguity if a provider is ever switched and old rows linger. `Engine` gains a `WithThreatIntelProvider(name string) *Engine` builder method, following the exact same optional-dependency pattern as `WithScenarios`/`WithVerifications`/`WithRuleLibrary`. `cmd/server/main.go` calls `.WithThreatIntelProvider("otx")` alongside the engine's other `With*` calls when `cfg.OTXAPIKey != ""` (mirroring how `iocProvider` itself is only constructed when the key is set); `populateThreatIntel` no-ops (leaves `ThreatIntel` nil) when no provider name was configured.

**Report copy leads with the summary, not a flat table** — answering "did this execution produce artifacts known to threat intelligence," not just listing rows:

> **Threat Intelligence Summary** — Extracted IOCs: 17 · Pending: 8 · Unknown: 3 · Suspicious: 2 · Malicious-Associated: 4

...followed by the per-indicator table (type, value, originating technique(s), tier, pulse count, malware families, adversaries, tags), sorted worst-tier-first.

## Report scope

Single-run reports only (`BuildFromRun`) — `run_iocs` is keyed per `run_id`, so this is the natural fit. Campaign-wide aggregation (dedup across every run in a campaign) is real extra work deferred to a future pass; `Build` (agent-latest-run) and `BuildFromCampaign` are untouched.

## HTML/PDF template

`FullReport` reaches the report template via a JSON-marshal-to-map step (`internal/reporting/html.go`), not struct reflection (this codebase's templates are garble-safe by design — see memory: garble breaks `html/template` field-name reflection). Adding the Go struct field is sufficient for the data to reach the template; the markup itself — a new "Threat Intelligence" section with the summary line and the per-indicator table — is new work in the HTML template. PDF inherits it automatically (renders from the same HTML via the headless-Chromium sidecar). CSV forensic export (`forensic.go`) is out of scope — that's the raw execution transcript, a different report artifact.

## Trigger + degrade path

`h.enrichRunIOCs(ctx, runID)` (new, `internal/api`) is fired via `go h.enrichRunIOCs(context.Background(), raw.RunID)` in `SubmitScenarioResult`, right after the existing `db.UpsertRunIOCs` call (sub-project B). Reads the run's `run_iocs` rows, for each checks the cache (skip if `ttl_expires_at` in the future), else calls `ioc.Lookup` and upserts success/failure into `ioc_enrichment`. Sequential per run (no concurrency limiter) — acceptable for a background, non-blocking first pass; a run with hundreds of unique indicators just takes longer in the background, nothing user-facing waits on it. No-op entirely when `h.iocProvider == nil` (OTX not configured) — same degrade path sub-project A already established for the lookup endpoint.

## Testing

- `internal/ioc/lookup_test.go` (new) — dispatch coverage for `ioc.Lookup` across all 5 types + unknown-type error.
- `internal/ioc/otx_test.go` (extended) — tag aggregation/dedup across multiple pulses; existing tests untouched.
- `internal/db/ioc_enrichment_test.go` (new, Docker-Postgres-backed, same `sharedDB` pattern as `ioc_test.go`) — upsert-success round-trip, upsert-failure preserves prior success data, TTL-expired row is treated as stale, provider-keyed uniqueness (same indicator, two different `provider` values, two rows).
- `internal/api` — `enrichRunIOCs` unit/integration test using a stub `ioc.Provider` (mirroring the existing `detectVerifyConnector` test-override pattern already in `Handler`) to avoid real OTX calls; verifies cache-hit skip, failure-doesn't-clear-success, and the `h.iocProvider == nil` no-op path.
- `internal/reporting` — `populateThreatIntel` test: mixed pending/unknown/suspicious/malicious-associated indicators produce the correct summary counts and sort order; a run with zero `run_iocs` rows leaves `ThreatIntel` nil.
- Live end-to-end verification (matching sub-project B's methodology): throwaway Postgres + `go run ./cmd/server`, submit a synthetic result containing a known-shape indicator, confirm `enrichRunIOCs` populates `ioc_enrichment`, then confirm `GET /api/scenarios/runs/{runId}/report.json` includes the populated `threatIntel` section. Real OTX API key not required for this — the stub-provider tests are the primary evidence; live-against-real-OTX is optional and skipped if no key is available, same caveat as sub-project A.

## Out of scope

- True multi-provider fan-out (calling 2+ providers per indicator).
- Campaign-wide report aggregation.
- CSV forensic export enrichment.
- A manual "re-check now" refresh endpoint (automatic background enrichment only).
- First Seen / Last Seen / References fields (not currently parsed by sub-project A's client; would need re-grounding OTX's schema first).
