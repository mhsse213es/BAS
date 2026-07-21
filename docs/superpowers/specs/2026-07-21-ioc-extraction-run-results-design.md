# IOC Extraction From Run Results — Design

**Status:** Approved (pending final user sign-off on this written doc)
**Sub-project:** B of 3, under the LevelBLUE OTX threat-intel initiative
**Depends on:** Sub-project A — `internal/ioc` provider interface + OTX client (DONE, commits `1000f7b`/`0fe0e43`/`1d5909b`/`f8f25a9`)
**Feeds into:** Sub-project C (future) — correlate extracted indicators against OTX, cache results, surface in reports

## Problem

BAS run results already contain command output (stdout/stderr from ART/Caldera/custom steps, human-readable `Details` from local posture checks) that frequently mentions IOCs — C2 callback IPs, download URLs, dropped-file hashes, referenced CVEs — but nothing extracts them. This sub-project builds the extraction and storage layer only. It does **not** call OTX or any other provider; that's sub-project C.

## Architecture

Extraction happens synchronously inside `SubmitScenarioResult` (`orchestrator/internal/api/handlers.go:1668`), the instant a run's results land, using data the handler already has in scope — no new agent-side collection, no new ingestion path.

```
Simulation
    │
    ▼
IOC Extraction  ← sub-project B (this spec)
    │
    ▼
IOC Store (run_iocs table)
    │
    ▼
GET /api/scenarios/runs/{runId}/iocs
    │
 ┌──┼────────┐
 ▼  ▼        ▼
OTX MISP  VirusTotal   ← sub-project C (future) — enrichment/correlation, unmodified by this work
```

Two new files in the existing `internal/ioc` package (no new package — extraction is a natural extension of "things we know about indicators," and reusing the package keeps the `ip`/`domain`/`url`/`hash`/`cve` type strings identical to what `Provider.LookupIP` etc. already expect, so sub-project C can feed rows straight in):

- **`internal/ioc/extract.go`** — pure, stateless `ExtractIndicators(text string) []Indicator`. No knowledge of runs, steps, or techniques — just "here's a blob of text, here's what looks like an indicator in it, with position and confidence." Fully unit-testable in isolation.
- **`internal/ioc/aggregate.go`** — `BuildRunIndicators(runID, scenarioID string, execResults []scenario.ExecResult, checks []scenario.SimCheckResult, stepMap map[string]scenario.Step) []RunIndicator`. Walks every step's raw text, calls `ExtractIndicators` per source, resolves technique/simulation identity, and dedups into one row per distinct indicator for the run.

And two additions outside it:

- **`internal/db/ioc.go`** — `EnsureIOCSchema`, `UpsertRunIOCs`, `GetRunIOCs` (with type/search filtering).
- **`internal/api/handlers.go`** — a new call in `SubmitScenarioResult` right alongside the existing `h.upsertFindingsForRun` / `h.persistVariantResults` derived-data calls, plus a new `GetRunIOCs` handler and route.

## Why extraction reads `ExecResult`/`SimCheckResult`, not the already-built `SimulationResult`

`models.SimulationResult.RawOutput` (what sub-project A's earlier design assumed it would scan) is `stdout+"\n"+stderr`, already merged and truncated to 3000 chars by `scenario.Interpret` (`internal/scenario/interpreter.go:32,69`). Extracting from it would lose the stdout/stderr distinction and lose anything past the truncation point. `SubmitScenarioResult` still has the original `raw.Results []scenario.ExecResult` (untruncated `Stdout`/`Stderr` fields) and `raw.Checks []scenario.SimCheckResult` in scope before that merge happens, so extraction reads from there instead — giving true per-source provenance and the full untruncated text.

## Provenance and traceability (addressing the gaps in the first draft)

**Simulation vs. technique identity.** One ATT&CK technique (e.g. T1059) can execute as several distinct simulations within a run — `cmd.exe`, `pwsh.exe -EncodedCommand`, a download-cradle variant — each a separate step with its own `TaskID`. Collapsing extraction down to `technique_ids` alone would hide which specific execution produced an indicator. Every `RunIndicator` therefore carries **both**:
- `TechniqueIDs []string` — every ATT&CK technique that produced this indicator in the run.
- `SimulationIDs []string` — every step (`scenario.TaskID(techniqueID, name)`, e.g. from `builder.go:22`) that produced it. For `ExecResult`-based steps this is `execResult.TaskID`; for local-check steps it's `SimCheckResult.ID`.

Both are arrays because dedup is per-run (one row per distinct indicator, decided during brainstorming), and the same indicator can legitimately surface from multiple steps or even multiple techniques.

**Source.** Each `Indicator` occurrence is tagged with where it came from: `stdout`, `stderr`, or `details` (the third case only for local-check steps, which have no stdout/stderr). When the same indicator appears more than once across sources/steps within a run, the row keeps the **first occurrence's** source+offset as its representative provenance — full traceability lives in `TechniqueIDs`/`SimulationIDs`, but only one canonical "here's where we first saw it" location is stored. Storing every occurrence's offset would need a child table; that's real over-engineering for a first pass and can be added later without breaking this schema.

**Scan order (deterministic "first occurrence").** `BuildRunIndicators` walks `execResults` in slice order, and for each one scans `Stdout` then `Stderr`; then walks `checks` in slice order scanning `Details`. "First occurrence" for `Source`/`OffsetStart`/`OffsetEnd` means first in this fixed walk order — not first by wall-clock time (steps within one submission don't carry reliable sub-second ordering).

**Offsets.** `OffsetStart`/`OffsetEnd` are byte offsets into the specific source text (that step's `Stdout`, `Stderr`, or `Details`) where the match occurred — computed directly from Go's `regexp.FindAllStringIndex`, no extra work. Lets a future UI highlight exactly where in the evidence an indicator was found.

**Hash algorithm.** Hashes are not collapsed into a generic `hash` type. Length disambiguates: 32 hex chars → `md5`, 40 → `sha1`, 64 → `sha256`. Stored in a dedicated `Algorithm`/`hash_algorithm` field (empty for non-hash indicator types). `Type` stays `hash` for all three — that's still the right OTX/VirusTotal/MISP lookup-type bucket — but the algorithm is preserved since different future providers expose different per-algorithm capabilities.

**Normalization.** Applied before dedup and storage so the same real-world indicator doesn't fragment into multiple rows over casing/formatting differences:
- Domain: lowercase.
- URL: lowercase scheme+host, strip fragment (`#...`), collapse a bare root path (`http://host/` → `http://host`); non-root paths and query strings are left untouched (stripping those could change the indicator's meaning).
- Hash: lowercase hex.
- CVE: uppercase (`CVE-2024-1234`).
- IPv4: no case concern, whitespace-trimmed.

**Confidence.** Static per-type score reflecting how precise each regex is, so a future UI can filter out noisy types: `hash`=100, `url`=100, `cve`=100, `ip`=95, `domain`=80. This is a fixed table for now (YAGNI on anything adaptive); ML-based refinement is a future concern, not blocked by this schema.

## Extraction rules per type

- **IPv4** — dotted-quad, each octet validated 0–255 (this alone rejects version-looking strings like `10.0.19045.1`, since `19045` isn't a valid octet). Private/reserved ranges (RFC1918, loopback `127.0.0.0/8`, link-local `169.254.0.0/16`, multicast `224.0.0.0/4`) are filtered out entirely — OTX has no threat data on them and they'd just be wasted lookups for sub-project C.
- **Domain** — `label.label.tld` shape, filtered against a blocklist of common non-TLD file extensions (`.exe .dll .sys .ps1 .psm1 .py .sh .bat .cmd .msi .zip .rar .log .txt .json .xml .yaml .yml .config .ini .dat .tmp .bak .jar .class`) that would otherwise false-positive on filenames like `svchost.exe` or `report.json` inside command output. **Known tradeoff, accepted deliberately:** this favors precision over recall — a small number of real ccTLDs collide with common script extensions (`.sh` is both Saint Helena's ccTLD and the most common shell-script extension in this system's actual command output; `.io`/`.dev`/`.app` are not on the blocklist and extract fine). Documented in the test suite, not silently swallowed.
- **URL** — `http(s)://...` matched as one indicator, not decomposed into a separate domain hit (avoids double-counting and matches OTX's own distinct `url` vs `domain` lookup types).
- **Hash** — 32/40/64 contiguous hex characters, word-boundary delimited.
- **CVE** — `CVE-\d{4}-\d{4,7}`, case-insensitive.

## Storage

```sql
CREATE TABLE IF NOT EXISTS run_iocs (
    id BIGSERIAL PRIMARY KEY,
    run_id TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    indicator_type TEXT NOT NULL,        -- ip | domain | url | hash | cve
    indicator_value TEXT NOT NULL,       -- normalized
    hash_algorithm TEXT,                 -- md5 | sha1 | sha256 (hash type only, else NULL)
    confidence SMALLINT NOT NULL,        -- 0-100
    indicator_source TEXT NOT NULL,      -- stdout | stderr | details (first occurrence)
    offset_start INT NOT NULL,
    offset_end INT NOT NULL,
    technique_ids JSONB NOT NULL DEFAULT '[]',
    simulation_ids JSONB NOT NULL DEFAULT '[]',
    extracted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(run_id, indicator_type, indicator_value)
);
CREATE INDEX IF NOT EXISTS idx_run_iocs_run_id ON run_iocs(run_id);
CREATE INDEX IF NOT EXISTS idx_run_iocs_value ON run_iocs(indicator_type, indicator_value);
```

`idx_run_iocs_value` exists specifically so sub-project C can later ask "has this indicator shown up in any other run" cheaply — a natural next step this schema doesn't block.

**Write path:** delete-then-bulk-insert per run inside a transaction, mirroring the "agent always submits a complete snapshot, REPLACE never append" idempotency pattern `SubmitScenarioResult` already documents for `scenario_runs` itself. A retried submission converges to the same row set instead of duplicating or double-merging arrays — this is also why there's no SQL-side array-merge logic anywhere in this design.

`EnsureIOCSchema(ctx, pool)` follows the exact pattern of `EnsureExerciseSchema`/`EnsureContentSchema`, called from `cmd/server/main.go` alongside them.

## Go types

```go
// internal/ioc/extract.go — pure extractor output, no run/step context.
type Indicator struct {
    Type        string // ip | domain | url | hash | cve
    Value       string // normalized
    Algorithm   string // md5 | sha1 | sha256 (hash only, else "")
    Confidence  int    // 0-100
    OffsetStart int
    OffsetEnd   int
}

func ExtractIndicators(text string) []Indicator
```

```go
// internal/ioc/aggregate.go — per-run aggregation; also the DB row / API response shape.
type RunIndicator struct {
    Type          string    `json:"type"`
    Value         string    `json:"value"`
    Algorithm     string    `json:"hashAlgorithm,omitempty"`
    Confidence    int       `json:"confidence"`
    Source        string    `json:"source"`      // stdout | stderr | details (first occurrence)
    OffsetStart   int       `json:"offsetStart"`
    OffsetEnd     int       `json:"offsetEnd"`
    TechniqueIDs  []string  `json:"techniqueIds"`
    SimulationIDs []string  `json:"simulationIds"`
    ExtractedAt   time.Time `json:"extractedAt,omitempty"` // set on read; zero on fresh extraction
}

func BuildRunIndicators(
    runID, scenarioID string,
    execResults []scenario.ExecResult,
    checks []scenario.SimCheckResult,
    stepMap map[string]scenario.Step,
) []RunIndicator
```

`RunIndicator` is reused as both the in-memory aggregation result and the DB/API shape (same pattern `models.SimulationResult` already follows elsewhere in this codebase) — no duplicate near-identical struct.

## API

`GET /api/scenarios/runs/{runId}/iocs` — added to the existing JWT-only "Viewer+Analyst+Admin" route group in `routes.go` (same group as `/report`, `/export`, `/events` — no new permission; extracted IOCs are a derived view of data the caller can already see in the run's raw output).

Query params:
- `?type=url` — filter to one indicator type (`ip`/`domain`/`url`/`hash`/`cve`).
- `?search=1.2.3.4` — substring match against `indicator_value`.

Both optional and combinable. Filtering matters once a run produces hundreds of indicators — plain unfiltered dump doesn't scale to real ART/Caldera runs with many steps.

## Handler wiring

```go
// In SubmitScenarioResult, right after simResults is finalized (same place
// h.upsertFindingsForRun / h.persistVariantResults already run):
indicators := ioc.BuildRunIndicators(raw.RunID, raw.ScenarioID, raw.Results, raw.Checks, stepMap)
if err := h.db.UpsertRunIOCs(r.Context(), raw.RunID, raw.ScenarioID, indicators); err != nil {
    log.Printf("[!] ioc extraction: failed to persist for run %s: %v", raw.RunID, err)
    // non-fatal — extraction failure must not fail result ingestion
}
```

Runs on partial runs too (completed steps' output is still real evidence, unlike findings which intentionally skip partial runs to avoid healing on incomplete data). Failure is logged and swallowed, never blocks the result-ingestion response — this is enrichment, not core scoring.

## Testing

`internal/ioc/extract_test.go`:
- One test per indicator type against clean positive matches.
- Private/reserved IPv4 filtering (each excluded range).
- Domain file-extension blocklist (the main false-positive risk) — including the documented `.sh` tradeoff as an explicit, named test case (not a silent gap).
- Normalization: mixed-case domain, URL with fragment and root path, mixed-case hash, lowercase CVE.
- Hash algorithm disambiguation by length (32/40/64).
- Two realistic mixed-content fixtures: an ART network-recon step's stdout, a Caldera C2-callback step's stdout — proving extraction against real-shaped output, not just synthetic one-liners.

`internal/ioc/aggregate_test.go`:
- Same indicator from two different steps of the same technique → one row, two entries in `SimulationIDs`, one entry in `TechniqueIDs`, first-seen source/offset preserved.
- Same indicator from two different techniques → one row, two entries in `TechniqueIDs`.
- Indicator appearing in both `Stdout` and `Stderr` of the same step → one row, `Source` reflects whichever was scanned first (stdout).
- Local-check step (`SimCheckResult`) → `Source` = `details`, `SimulationIDs` uses `SimCheckResult.ID`.

`internal/db/ioc_test.go` (Docker-Postgres-backed, matching this codebase's existing DB test pattern):
- `UpsertRunIOCs` then `GetRunIOCs` round-trip.
- Re-submission (same `run_id`) replaces rather than duplicates or appends.
- `?type=` and `?search=` filtering.

Live verification: run the existing throwaway-Postgres + `go run ./cmd/server` setup, submit a synthetic `RawRunResult` via `POST /api/scenarios/result` containing a known IP/domain/URL/hash/CVE in `Stdout`, confirm `GET /api/scenarios/runs/{runId}/iocs` returns the expected rows with correct provenance.

## Out of scope (deferred to sub-project C)

- Any call to `ioc.Provider`/OTX for the extracted indicators.
- Cross-run correlation ("has this indicator appeared before").
- Surfacing indicators in the HTML/PDF report.
- Per-occurrence (not just first-occurrence) provenance history.
