# TCF Phase 9 — Threat-Triggered Generation Observability Design

**Status:** Approved for planning
**Date:** 2026-10-13
**Supersedes:** the Phase 9 entry in `docs/threat-content-factory/roadmap-phases-4-11.md:15`, whose 2026-10-13 re-verification this spec confirms and extends with exact code citations.

## 1. Current state (evidence-backed)

### 1.1 The trigger chain already exists; there is no missing trigger-chain gap

`Scheduler.sync()` (`orchestrator/internal/connector/scheduler.go:303-505`) runs on every `pollHours` tick and on every `TriggerSync()` call (itself called from `scheduler.go:133`, `223`, and `POST /api/connector/sync`), and calls `s.generator.Write(resolved)` unconditionally at `scheduler.go:478` — there is no change-detection gate before it. `Generator.Write` (`orchestrator/internal/connector/generator.go:150-245`) is called from exactly this one site; nothing else calls it. Generation is already idempotent: `RegisterGenerated`'s dedup and the three distinguishable registry-collision errors (`ErrSourceCollision`/`ErrOriginCollision`/`ErrThreatCollision`) already exist and are already handled with distinct log messages (`generator.go:204-213`).

### 1.2 Per-actor outcomes are already distinguishable in code, but only as aggregate, in-memory, per-cycle counters

Walking `Generator.Write`'s loop body (`generator.go:163-240`) actor by actor, every exit path increments exactly one of four counters on `GenerateResult` (`generator.go:130-141`):

- `Skipped` — unresolved identity (`actor.ThreatID == ""`, line 164, counter at line 166), below `minTechniques` (line 180, counter at line 181), or the registry's "already registered, nothing new" case (the terminal `else` at line 238).
- `Failed` — active-techniques fetch error (line 173, counter at line 175), `RegisterGenerated` error for any reason, including all three collision types and a generic registrar error (switch at lines 204-213, counter at line 214), and a file-write error (line 219, counter at line 221).
- `Created` — `RegisterGenerated` returned `created == true` (counter at line 228).
- `Changed` — the working-copy file's bytes differed from what's on disk and were rewritten (counter at line 224); this is **not mutually exclusive** with `Created` — a single actor's iteration can increment both `Changed` and `Created` in the same pass, since the file-rewrite check (line 218) and the `created` branch (line 226) are independent checks against independent state (disk bytes vs. registry state).

These counters live only on `Scheduler.status` (`ConnectorStatus`, `orchestrator/internal/connector/types.go:82-103`): in-memory, cumulative (`+=`, never reset or timestamped per cycle), lost on restart. They are exposed read-only via `GET /api/connector/status` (`orchestrator/internal/api/handlers.go:5062-5078`). The only place the full per-actor breakdown (which actor, which outcome, why) ever appears is a `log.Printf` line — never persisted, never queryable, gone the moment the log rotates or the process restarts.

### 1.3 One table already persists part of the success path — and it is evidence provenance, not an attempt log

`content_generations` (`orchestrator/internal/db/evidence_schema.go:114-126`) is written only when `created == true` (`generator.go:226-235`, the `evidence.RecordGeneration` call at line 233), keyed `(threat_id, generation_number)`, and holds `technique_set_hash`/`evidence_snapshot_hash`/`evidence_snapshot jsonb` — a record of *why* a successful generation included the techniques it did, not a record that an attempt happened. It has no row for `Skipped`, `Failed`, or `Changed`-without-`Created` outcomes. The roadmap note's claim — failures and skips vanish with no durable record — holds exactly.

### 1.4 The idempotency fingerprint already exists

`generationKey(actor)` (`generator.go:485-494`) is a sha256 over `{generator, generator_version, mapping_version, resolved inputs, deduped technique ids, min_techniques}`, computed once per actor (`generator.go:196`) immediately before `RegisterGenerated` is called. It is available for every outcome except the three early-exit paths (unresolved identity, active-techniques error, below-minimum) that return before line 196 — the same nullability boundary as `content_id` (computed at `generator.go:185`, same early-exit boundary).

### 1.5 No scheduler-cycle identifier exists anywhere

`sync()` has a local `start := time.Now()` (`scheduler.go:310`) and nothing else identifying a cycle. There is no UUID, sequence number, or other handle a caller could use to group "every attempt from this poll" together.

### 1.6 A general attempt-log pattern exists elsewhere in the codebase, and is deliberately not reused here

`execution_attempts` (`orchestrator/internal/db/postgres.go:1786`) logs ART/Caldera/exercise dispatch attempts, with a `source` CHECK constraint scoped to `('art','caldera','exercise')`. This was considered and rejected (see §2.1): generation attempts are a different kind of event (a content-factory decision per actor per cycle, not a dispatch/execution of a security test), and widening an execution-oriented table's status semantics to also mean "skipped because below minimum technique count" or "registry collision" would create long-term ambiguity for a one-migration saving. `execution_attempts` is not touched by this spec.

### 1.7 Out of scope, confirmed correct, do not touch

- Changing `RegisterGenerated`'s collision semantics, the registry's dedup behavior, or `content_generations`'s schema — Phase 9 is purely additive observability.
- Gating the every-poll unconditional re-run of `Generator.Write` on "did intel actually change since last sync" — confirmed a real, open question (§1.1, §5) but explicitly deferred: the DB cost today (up to 2 round-trips per actor per poll — one `ActiveTechniques` call, one `RegisterGenerated` dedup check) is not alarming at current actor counts, and conflating a performance change with an observability phase risks masking which change caused which effect.
- `execution_attempts` and anything in the ART/Caldera/exercise dispatch path (§1.6).

## 2. Design

### 2.1 A dedicated `content_generation_attempts` table

Decision, made explicitly against reusing `execution_attempts` (§1.6): generation attempts get their own table.

```sql
CREATE TABLE IF NOT EXISTS content_generation_attempts (
    id                 text        PRIMARY KEY DEFAULT ('cga-' || gen_random_uuid()::text),
    cycle_id           text        NOT NULL,
    threat_id          text,
    content_id         text,
    content_version_id text,
    outcome            text        NOT NULL CHECK (outcome IN ('created','changed','skipped','failed')),
    reason_code        text        NOT NULL,
    detail             text,
    generator_version  text        NOT NULL,
    fingerprint        text,
    started_at         timestamptz NOT NULL,
    completed_at       timestamptz NOT NULL DEFAULT NOW()
)
```

Column notes, each tied to a specific finding above:

- **`threat_id`, `content_id`, `fingerprint` are nullable** (§1.2, §1.4): the unresolved-identity, active-techniques-error, and below-minimum paths exit before any of these exist. A `NOT NULL` constraint here would be a lie the code can't keep.
- **`content_version_id` is nullable with no `REFERENCES` constraint**, deliberately matching `content_generations.content_version_id`'s own existing convention (§1.3) — "don't make failure records depend on content versions that may never have been created" is already this codebase's pattern, not a new one.
- **No FK from `content_generation_attempts` to `content_generations`.** They're linked application-side when both exist (a `created` attempt with a `content_version_id` can be joined to the `content_generations` row for the same `threat_id` + the generation number recorded at the same time), never by duplicating `technique_set_hash`/`evidence_snapshot_hash` into the new table.
- **`reason_code` is `NOT NULL`, free-text, not an enum** — the set in §2.3 is the initial list, but a `CHECK` enum would need a migration every time a new failure mode is added to `Generator.Write`; the `outcome` enum is the one that matters for dashboards and stays small and closed.
- **`generator_version`** is `generatorVersion` (currently `"4"`, `generator.go:47`) at the time of the attempt — not the current build's constant — so a historical row stays accurate after the constant bumps.
- **`cycle_id`**: new. Minted once per `sync()` call (a UUID is simplest — `sync()` has no existing identifier to repurpose per §1.5) and passed down to every attempt row written during that cycle. This is the only genuinely new piece of state Phase 9 introduces into the scheduler.

No index beyond the primary key is specified here — the implementation plan adds whatever `(cycle_id)` / `(threat_id, started_at DESC)` indexes its actual read-path queries need, once those queries are written.

### 2.2 Outcome precedence: `created` > `changed` > `skipped` > `failed`

Resolves the non-exclusivity in §1.2: a single actor's `Generator.Write` iteration can hit both the "file bytes rewritten" and "registry created a new version" branches. One attempt row per actor per cycle, with `outcome = 'created'` whenever `created == true` regardless of whether the file was also rewritten. This is a simplification of the current code's two-independent-counters reality, chosen because "a new version was created" is the more meaningful fact for observability than "the working copy's bytes also happened to change" — and because the alternative (non-exclusive boolean columns) would make every downstream query (including Phase 11's duplicate-generation metric) handle multi-valued outcomes for no analytical benefit. The precedence is documented in code as a named constant list, not inferred from `if`/`else` ordering.

### 2.3 Reason codes

One row per actor per cycle, `reason_code` set to exactly one of:

| `outcome` | `reason_code` | Current code location |
|---|---|---|
| `skipped` | `unresolved_identity` | `generator.go:164-166` |
| `failed` | `active_techniques_error` | `generator.go:172-175` |
| `skipped` | `below_min_techniques` | `generator.go:180-181` |
| `failed` | `source_collision` | `generator.go:205-206` (`ErrSourceCollision`) |
| `failed` | `origin_collision` | `generator.go:207-208` (`ErrOriginCollision`) |
| `failed` | `threat_collision` | `generator.go:209-210` (`ErrThreatCollision`) |
| `failed` | `registrar_error` | `generator.go:211-212` (any other `RegisterGenerated` error) |
| `failed` | `write_error` | `generator.go:219-221` |
| `created` | `ok` | `generator.go:226-228`, `created == true` |
| `skipped` | `already_registered` | `generator.go:237-238`, the terminal `else` |

A `created` attempt whose follow-up `NextGenerationNumber`/`RecordGeneration` call fails (`generator.go:230-235`, today only logged, the counters are unaffected) gets a second, distinct reason code — `generation_number_error` — recorded on the **same** attempt row (not a second row): the content version was genuinely created, so `outcome` stays `created`, but `detail` carries the evidence-recording failure so it's visible without being misclassified as a generation failure.

### 2.4 Integration point: wrap the single call site, not the loop internals

`Generator.Write`'s signature changes to accept a `cycleID string` and a writer for attempt rows (an interface, so `generator_test.go`'s existing tests can pass a no-op or in-memory fake rather than requiring Postgres for every existing test). The loop body's existing `continue`/counter-increment points (§1.2's line references) each gain one additional call: write the attempt row with the outcome/reason already being decided at that exact point, then `continue` as today. No new branching logic, no restructuring of the existing control flow — the attempt log is a side effect recorded at each existing exit point, not a parallel decision tree that could drift from the real one.

`scheduler.go:478`'s single call site mints `cycleID` (`uuid.New().String()` or equivalent) immediately before calling `Write`, and that's the only change needed in `scheduler.go` itself.

### 2.5 Retention and diagnostic bounding

- `detail` is bounded to a fixed max length (e.g. 2 KB) at write time — truncate, don't error, if a wrapped error's message is longer. No raw evidence snapshots, no raw intel source payloads, no secrets: `detail` holds error text and identifiers only, never the `body` YAML or `evidenceSnapshot` structures already persisted in full elsewhere (`content_generations.evidence_snapshot`) under that table's own, separate access controls.
- No retention/deletion policy is specified by this phase — rows accumulate. If row growth becomes a real concern, that's a follow-up, not a Phase 9 blocker: the table's purpose is restart-durable visibility, not a bounded audit log with a mandated TTL.

### 2.6 Read path

A `GET /api/connector/generation-attempts` endpoint (new handler, same package as `GetConnectorStatus`), supporting at minimum:
- `?cycle_id=` — every attempt from one cycle (for "what happened on the last poll").
- `?threat_id=` — every attempt for one actor across cycles (for "why does this content keep regenerating").
- A bounded default page size with `?limit=`/`?since=` for the general case, since this table has no retention cap (§2.5).

This is the durable data source Phase 11's duplicate-generation-rate metric needs (a `COUNT(*) WHERE outcome='skipped' AND reason_code='already_registered'` over a time window becomes possible for the first time); Phase 9 only needs to expose the read path, not build that metric — Phase 11 consumes it separately, per the user's own framing that persistence work for Phase 11 belongs in Phase 9, not duplicated into Phase 11.

## 3. Acceptance criteria

- A `sync()` cycle that produces one actor of each outcome (`created`, `skipped` via below-minimum, `skipped` via already-registered, `failed` via a forced collision) writes exactly four `content_generation_attempts` rows, all sharing one `cycle_id`, each with the `reason_code` from §2.3.
- An actor whose iteration both rewrites the working-copy file and creates a new registry version produces exactly one row with `outcome = 'created'` (§2.2), not two rows and not `'changed'`.
- `threat_id`/`content_id`/`fingerprint` are `NULL` on a row from the unresolved-identity path, and non-`NULL` on every row that reaches `generationKey` (§2.1).
- A forced `RegisterGenerated` error for each of the three collision types produces the matching, distinct `reason_code` (§2.3) — not a shared generic `registrar_error`.
- A `created` attempt whose `RecordGeneration` evidence write fails still has `outcome = 'created'`, with `generation_number_error` recorded in `detail` on that same row (§2.3) — asserted by forcing that specific failure in a test, not inferred.
- `GET /api/connector/generation-attempts?cycle_id=X` returns only that cycle's rows; `?threat_id=Y` returns only that actor's rows across cycles.
- Existing `generator_test.go` tests continue to pass unmodified in shape (same assertions on `GenerateResult`'s counters) after `Write`'s signature change — the attempt-writer dependency is injectable and a no-op fake satisfies every existing test without requiring Postgres.
- `detail` on a row built from a deliberately oversized error message is truncated to the bound in §2.5, not rejected and not silently empty.

## 4. Migration / backward compatibility

New table, new column additions to nothing existing — no migration of existing data. `Generator.Write`'s signature change is a breaking Go API change within this module only (its sole caller is `scheduler.go:478`, updated in the same change). No `.env`, config, or deployed-artifact compatibility concerns — this is pure application code plus one new table.

## 5. Out of scope

- Gating the unconditional every-poll `Generator.Write` call on genuine intel change (§1.7) — open question, explicitly deferred, not a Phase 9 blocker.
- Any change to `execution_attempts`, `content_generations`, or `RegisterGenerated`'s collision/dedup semantics (§1.6, §1.7).
- Building Phase 11's actual duplicate-generation-rate calculation — Phase 9 only makes the data available (§2.6).
- A retention/TTL policy for `content_generation_attempts` (§2.5).
- Any frontend/dashboard surface for the new read path — the API endpoint is the full scope; a future phase decides whether/how to visualize it.

## 6. Review Focus (for the implementation plan)

- A test that actually forces both `Changed` and `Created` to be true for the same actor in the same `Write` call, asserting the §2.2 precedence produces one row with `outcome='created'` — the acceptance criterion names this, but it's the one behavior most likely to be implemented by accident (e.g. two separate write calls) rather than deliberately.
- A test for the `generation_number_error` `detail`-on-the-same-row behavior (§2.3) — easy to misimplement as a second `failed` row instead of annotating the existing `created` row.
- A test with a forced over-length error message confirming `detail` truncates rather than erroring the whole attempt-write (§2.5) — an attempt-logging failure must never be allowed to fail the generation attempt it's trying to record.
- A test confirming existing `generator_test.go` assertions on `GenerateResult` counters are unaffected by the signature change (the in-memory no-op attempt-writer fake must be a drop-in, not require every existing test to be rewritten).
- A test on the read-path pagination default (`?limit=`/`?since=`) actually bounding an unbounded table, since §2.5 explicitly leaves retention unbounded at the storage layer.
