# TCF Threat-to-Validated-Coverage SLA Event Ledger — Design

**Status:** Design (approved in brainstorming 2026-10-31; not yet planned or implemented)
**Author:** Tausif + Claude
**Module:** `github.com/audspect/bas` (`orchestrator/`)
**Supersedes nothing.** Additive to the Phase 2C TCV implementation.

---

## 1. Intent & why

The Threat Content Factory (TCF) already ships a **Phase 2C TCV** metric: per-threat
time from a start clock to *first executable content*, plus one factory-wide
median/P95 aggregate (threat→emulation only). That metric answers "how fast did
content become runnable." It is kept exactly as-is.

It does **not** answer the question TCF engineering, content-ops, and product
leadership actually need for an internal SLA: **"are we turning relevant threats
into factory-*validated* coverage fast enough, and where is time being lost?"**
That needs (a) coverage defined as *successful factory validation*, not mere
executability; (b) the pipeline broken into measurable stages — observation →
eligibility → generation → validation — with queue delay, retries, and failures
visible; and (c) segmentation and bottleneck attribution.

This design adds an **append-only event ledger** as the one trustworthy event
foundation. The existing Phase 2C metric and a new internal-SLA metric become
two independent **projections** of this foundation. A future customer-facing
report can consume the same ledger without redefining it.

**Audience & decision, first implementation:** internal factory SLA only.
Audience: TCF engineering, threat-content operations, product leadership.
Decision it changes: are we fast enough, and which stage is the bottleneck.
Customer-facing claims are explicitly deferred until operational history exists
to defend them.

## 2. Goals / non-goals / anti-goals

**Goals**
- A single append-only `tcf_pipeline_events` ledger recording the real pipeline
  events with event-time, provenance, and idempotency.
- An internal-SLA projection computing per-stage and end-to-end durations, P50 &
  P95, segmented by threat source, content type, and validation outcome, with
  bottleneck attribution.
- Coverage counted **only** on successful factory validation of a specific
  content version.
- Phase 2C left byte-for-byte intact (tables, writers, `GET /…/tcv`, aggregate).

**Non-goals (this phase)**
- Customer-facing reporting UI or claim language.
- Changing what content the factory generates (that is Option A / evidence-driven
  generation, a separate initiative).
- Retroactive repair of events that were never recorded.
- A lab adapter / new validation mechanism — validation already exists (Phase 6).

**Anti-goals (would make this a failure even if it "works")**
- Overwriting or mutating ledger rows (corrections must be new events).
- Copying mutable lifecycle facts into the ledger such that it can drift from
  `content_version_events` / `content_validations` (the ledger references the
  authoritative row; it does not become a second source of truth for the fact).
- Fabricating an "accepted" timestamp by back-dating it from generation.
- Counting executable-but-unvalidated content as validated coverage.
- Mixing customer detection-validation runs into factory-validation measurement.

## 3. Constraints (verified against merged code, 2026-10-31)

- **Source of truth is `origin/main`.** The TCV core files are byte-identical
  between `origin/main` and the stale `tcf-phase2` worktree *except*
  `analytics/factory.go` (consumer only). Implement from current `main`, in a
  **new worktree/branch** (not `tcf-phase2`).
- Pure-domain style of the TCF packages: small focused files, table-driven,
  stdlib + pgx; schema in `internal/db/*_schema.go` with an idempotent
  `Ensure…Schema` run from `cmd/server/main.go` in dependency order.
- Postgres on-prem; app runs under the restricted `bas_app` role (see
  `internal/db/app_role.go`) — new tables need explicit grants, and the SLA
  projection must be readable by the app role.
- No new external dependencies.

## 4. Correlation anchors that already exist (do not rebuild)

| Anchor | Table / columns | Note |
|---|---|---|
| Threat observation | observations/claims via `connector/scheduler.go:964` resolve path; `observed_at`, trust state | clock-start writer already uses this |
| Generation attempt | `content_generation_attempts` (`cga-…`): `cycle_id, threat_id, content_id, content_version_id, outcome∈{created,changed,skipped,failed}, reason_code, generator_version, started_at, completed_at` | per-threat **and per-version** |
| Lifecycle transitions | `content_version_events`: `content_version_id, to_lifecycle, to_trust, actor, at` | **append-only, real event-time** |
| Validation outcome | `content_validations`: `content_version_id (NOT NULL FK), level∈{STATIC,EXECUTION}, outcome, run_id, validator, created_at` | **already bound to version + run** |
| Validation run | `scenario_runs`: `execution_kind∈{…,factory_validation}, content_version_id` | factory run = `execution_kind='factory_validation'` |
| Threat↔content | `content_version_threats`: `(content_version_id, threat_id, relationship_kind∈{emulates,generated_for})` | the coverage link |

**Consequence:** "validation tied to a specific content version, not a scenario id"
is already enforced at `content_validations` (version-keyed + `run_id`). The ledger
preserves this by always carrying `content_version_id` on validation events.

## 5. Event taxonomy & exact trigger points

One row per event in `tcf_pipeline_events`. Event-time comes from the authoritative
source row named in the last column.

| event_type | Trigger point (call site) | Write-once key | event_time |
|---|---|---|---|
| `threat_observed` | scheduler records a **trusted** claim for a threat (`scheduler.go` resolve path, same guard as the existing `RecordThreatClockStart`, `trustState==Trusted`) | per `threat_id` | observation `observed_at` |
| `threat_eligible` | **[new write]** inside `Generator.Write` the first time a threat **clears `minTechniques`** (`generator.go:198`, the non-skip branch) — the admission decision | per `threat_id` | admission time (cycle time) |
| `generation_attempted` | each `content_generation_attempts` insert (`recordAttempt`) | per `cga.id` | `cga.started_at` |
| `generation_failed` | cga insert with `outcome='failed'` | per `cga.id` | `cga.completed_at` |
| `content_created` | cga insert with `outcome IN ('created','changed')` (version now exists) | per `cga.id` | `content_versions.created_at` |
| `validation_dispatched` | `→VALIDATING` transition (lab claim, `validationlab/orchestrator.go:98`) | per (`content_version_id`, dispatch `at`) | `content_version_events.at` |
| `validation_resulted` | `content_validations` EXECUTION row written (`orchestrator.go:178`) | per `content_validations` row (`content_version_id`,`run_id`) | `content_validations.created_at` |
| `validated_coverage` | `→VALIDATED` transition (lab PASS, `orchestrator.go:232`) | per `content_version_id` (first VALIDATED) | `content_version_events.at` |
| `published_executable` | `→PUBLISHED` / `→PUBLISHED_LOCAL` transition | per (`content_version_id`, lifecycle) | `content_version_events.at` |
| `superseded` / `retired` / `rejected` | respective transitions | per (`content_version_id`, lifecycle) | `content_version_events.at` |

**Emulates-hole fix is structural here:** `published_executable` and
`validated_coverage` are *distinct* event types. A hand-authored LOCAL scenario
taking the legal `DRAFT→PUBLISHED_LOCAL` shortcut emits `published_executable`
but never `validated_coverage` (no EXECUTION PASS exists for its version). The
SLA coverage projection keys on `validated_coverage` only. Publishing remains
allowed; the two concepts are simply separated.

**Acceptance decision (locked):** `threat_eligible` is a real, persisted admission
event, not the first generation attempt. Rationale: if acceptance were "first
generation attempt," `eligible→generation` would be identically zero and the
scheduling/queue delay (a threat waiting across syncs until it accrues
`minTechniques`) would be permanently unmeasurable. The event fires at a decision
the scheduler already makes; it is the only genuinely new write in the pipeline.

## 6. Schema & idempotency

```sql
CREATE TABLE IF NOT EXISTS tcf_pipeline_events (
    event_id            text        PRIMARY KEY DEFAULT ('tpe-' || gen_random_uuid()::text),
    event_type          text        NOT NULL CHECK (event_type IN (
                            'threat_observed','threat_eligible',
                            'generation_attempted','generation_failed','content_created',
                            'validation_dispatched','validation_resulted','validated_coverage',
                            'published_executable','superseded','retired','rejected')),
    threat_id           text,                       -- FK threats(id) where known
    content_id          text,
    content_version_id  text,                       -- FK content_versions(id) where known
    generation_attempt_id text,                     -- FK content_generation_attempts(id)
    validation_run_id   text,                       -- scenario_runs(id), factory_validation
    event_time          timestamptz NOT NULL,       -- the real moment (from source row)
    recorded_time       timestamptz NOT NULL DEFAULT now(),
    source_table        text        NOT NULL,       -- provenance: which authoritative table
    source_pk           text        NOT NULL,       -- provenance: that row's key
    payload             jsonb       NOT NULL DEFAULT '{}',   -- outcome, reason_code, source type, content type, etc.
    idempotency_key     text        NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_tpe_threat       ON tcf_pipeline_events (threat_id, event_time);
CREATE INDEX IF NOT EXISTS idx_tpe_version      ON tcf_pipeline_events (content_version_id, event_time);
CREATE INDEX IF NOT EXISTS idx_tpe_type_time    ON tcf_pipeline_events (event_type, event_time);
```

- **FKs** are advisory where the referenced row is in another TCF table; use
  `REFERENCES` where it does not create a load-order problem with `Ensure…Schema`
  ordering (threats + content_versions + content_generation_attempts all exist
  before this table's `Ensure` runs — place `EnsureTCFPipelineEventsSchema` after
  them and before `EnsureAppRole`).
- **Idempotency:** `idempotency_key` is deterministic per event, e.g.
  `event_type || ':' || coalesce(content_version_id, threat_id) || ':' || source_pk`.
  Every writer does `INSERT … ON CONFLICT (idempotency_key) DO NOTHING`. Because
  each event is derived from exactly one authoritative source row, replay of a
  sync cycle or a transition never double-records.
- **Append-only enforcement:** grant the app role `INSERT`/`SELECT` only; **no
  `UPDATE`/`DELETE`** (mirror the pattern `app_role.go` already uses for
  `content_version_events`). Corrections are new rows.
- `payload` carries the facts the projection segments on (threat source, content
  type/`relationship_kind`, generation `reason_code`, validation `outcome`) copied
  from the source row **for read convenience only**; the authoritative value
  always remains in the source table (`source_table`/`source_pk` point to it).

## 7. Event-time vs recorded-time

- `event_time` = the authoritative source row's own timestamp (`observed_at`,
  `cga.started_at`/`completed_at`, `content_version_events.at`,
  `content_validations.created_at`). All durations are computed from `event_time`.
- `recorded_time` = `now()` at ledger insert. For forward (live) events
  `recorded_time ≈ event_time`; a large `recorded_time − event_time` gap is itself
  an operational health signal (late processing) and is reportable, never folded
  into stage durations.

## 8. Retry / failure / inconclusive / superseded semantics

- **Generation retry:** several `generation_attempted` under one `threat_eligible`.
  Generation-stage duration = `threat_eligible` → first `content_created`.
  Attempt count and `generation_failed` rows quantify churn.
- **Validation retry:** repeated `validation_dispatched` → `validation_resulted`
  (FAIL) → DRAFT → `validation_dispatched` cycles (the lab routes a FAIL back to
  DRAFT, `orchestrator.go:234`). The SLA stop is the **first** `validated_coverage`.
- **Failure / inconclusive:** `generation_failed`, and `validation_resulted` with
  `outcome ∈ {FAIL, NO_DATA, ERROR}`, are recorded but are **never coverage**.
  Only `validated_coverage` (a VALIDATED transition, i.e. an EXECUTION PASS) counts.
- **Superseded:** a newer version's events never retract an older version's. The
  threat-level SLA attributes coverage to the **first** content version that
  reached `validated_coverage` for that threat (per `relationship_kind`). A
  `superseded` event is informational for per-version analysis.

## 9. Projections

Two read-only projections over the ledger; neither writes.

**(a) Phase 2C compatibility — unchanged.** `threat_clock_starts` /
`threat_coverage_firsts`, `tcv.Store.Metrics`, `tcv.AggregateMetrics`, and
`GET /api/intel/threats/{id}/tcv` keep their current time-to-*executable*
semantics. Not rebuilt on the ledger; left exactly as merged.

**(b) Internal SLA projection — new.** Derived purely by query from
`tcf_pipeline_events`:

- **Per-leg stage durations** (event_time deltas, one `(threat, relationship_kind)`
  leg; grain per §15):
  - queue: `threat_observed` → `threat_eligible`
  - generation: `threat_eligible` → first `content_created`
  - validation: first `content_created` → first `validated_coverage`
  - end-to-end: `threat_observed` → first `validated_coverage`
  A stage with no terminating event is **open** (reported as open, not zero).
- **P50 / P95, segmented:**
  ```sql
  SELECT segment_source, segment_content_type, segment_validation_outcome,
         count(*) AS n,
         percentile_cont(0.5)  WITHIN GROUP (ORDER BY stage_seconds) AS p50,
         percentile_cont(0.95) WITHIN GROUP (ORDER BY stage_seconds) AS p95
  FROM <stage_durations_view>
  WHERE stage = $1
  GROUP BY 1,2,3;
  ```
  Each stage runs over its **own independent population** (legs with both of that
  stage's bounding events) and every result carries its stage `n`. Percentiles are
  computed on the **validated** cohort only; segments are threat source and content
  type (`relationship_kind`). Validation outcome is the terminal
  **{validated, failed, open}** cohort label — `failed` and `open` legs are
  reported as counts/rates (plus the open cohort's oldest-open age), never folded
  into the duration percentiles. `n=0` for a segment is reported explicitly.
  (See §15.)
- **Bottleneck attribution:** for a segment, the stage with the largest P95,
  surfaced alongside generation retry count and validation FAIL rate for that
  segment, so the number has a named cause.
- **Factory-run isolation:** validation events are sourced only from
  `content_validations` EXECUTION rows / `scenario_runs` where
  `execution_kind='factory_validation'`; customer detection-validation runs never
  enter the ledger's validation events.

## 10. Backfill & compatibility

- **Additive:** Phase 2C untouched; the ledger and SLA projection are new objects.
- **Forward events are authoritative.** A one-time backfill MAY emit historical
  events from rows that already exist — `content_version_events`,
  `content_validations`, `content_generation_attempts`, and trusted observations —
  with `event_time` from the source and `recorded_time=now()`.
- **Permanently unavailable, do not fabricate:**
  - `threat_eligible` for any threat admitted before this ships (never recorded).
  - any event predating the source table that would carry it.
  - precise coverage times for content that became executable before Phase 2C
    (the 2C writer used wall-clock, and only forward).
- The SLA projection **flags any reporting window with incomplete backfill**
  (e.g. threats whose `threat_observed` exists but `threat_eligible` cannot) and
  excludes them from P50/P95 rather than reporting a falsely precise number.

## 11. Acceptance tests (fixture-driven, pure where possible)

Ledger writers and the projection are DB-backed (pgx + testcontainers, the
existing `internal/db` / `internal/tcv` test style). Pure helpers (idempotency-key
derivation, stage-duration computation from an in-memory event list) are unit tests.

1. `threat_eligible` is written once; a second cycle clearing the threshold again
   does not move or duplicate it (idempotency).
2. A threat that never clears `minTechniques` has `threat_observed` but no
   `threat_eligible`; its queue stage is **open**, not zero.
3. `generation_attempted` + `generation_failed` recorded for a failed attempt; a
   later successful attempt records `content_created`; generation duration measured
   from `threat_eligible` to the first `content_created`.
4. Two `validation_resulted(FAIL)` then one PASS → exactly one `validated_coverage`,
   at the PASS transition's `event_time`; validation duration uses the first PASS.
5. A hand-authored LOCAL scenario `DRAFT→PUBLISHED_LOCAL` emits
   `published_executable` and **no** `validated_coverage`; it does not count as SLA
   coverage (emulates-hole fix).
6. Validation of version A does not produce a `validated_coverage` for version B
   sharing the same threat (version-keyed binding).
7. A customer detection-validation run (`execution_kind='content'` etc.) produces
   **no** ledger validation event.
8. Replaying the same sync cycle / transition produces no duplicate ledger rows.
9. SLA projection P50/P95 segmented by source/content-type/outcome returns correct
   percentiles on a seeded distribution; empty segment reports `n=0`, not an error.
10. Bottleneck attribution names the stage with the largest P95 on a seeded skew.
11. A window with a threat missing `threat_eligible` is flagged and excluded from
    P50/P95, not silently included as zero.
12. App role can `INSERT`/`SELECT` ledger rows but `UPDATE`/`DELETE` are refused.
13. Phase 2C `GET /…/tcv` and `AggregateMetrics` return byte-identical results
    with the ledger present (no regression).
14. Stage populations are independent: a leg with `threat_observed` + `threat_eligible`
    but no `content_created` contributes to the queue-stage percentile and is
    absent from the generation/validation samples — it does not reduce the queue `n`.
15. Duration percentiles use the validated cohort only: a failed leg and an open
    leg are excluded from P50/P95 but counted in the failed/open rates; the open
    cohort reports count and oldest-open age.
16. A leg whose version is demoted/retired after `validated_coverage` keeps its
    end-to-end measurement (monotone; no revoke event is emitted or required).

## 12. File layout (proposed; builder may adjust to match package conventions)

- `internal/db/tcf_pipeline_events_schema.go` — `EnsureTCFPipelineEventsSchema`
  (+ grants in `app_role.go`).
- `internal/tcv/ledger.go` — event types, idempotency-key derivation, append-only
  writer (`RecordPipelineEvent`), pure stage-duration helpers.
- Writers wired at trigger points: the trusted-claim path and new eligibility
  write in `connector/` (scheduler/generator); generation events alongside
  `content_generation_attempts`; lifecycle/validation events alongside the
  `contentregistry`/`validationlab` transition + `content_validations` writes.
- `internal/tcv/sla.go` — the SLA projection queries (stage durations, P50/P95,
  bottleneck), returning typed read-models.
- New read endpoint(s) under `internal/api` (e.g. `GET /api/intel/factory/sla`),
  RBAC-gated and added to the route matrix (watch the known RBAC-drift trap).
- Matching `_test.go` files per the acceptance tests above.

## 13. Left to the builder

- Exact idempotency-key format and `payload` field names (settle during planning;
  spec fixes the semantics, not the string).
- Whether the SLA projection is a Go-computed read-model, a SQL view, or a
  materialized view (default: Go-computed over indexed base table, matching
  `tcv.AggregateMetrics`' single-aggregate approach; revisit only if too slow).
- Precise admission call-site inside `Generator.Write` for the `threat_eligible`
  write (confirmed region: the non-skip branch after the `minTechniques` check,
  `generator.go:198`).
- Endpoint naming and the SLA read-model JSON shape.

## 14. Resolutions from builder-check (builder's calls, 2026-10-31)

A fresh-eyes review raised these; settled here. (Owner-decision items from the
same review are in §15.)

- **`threat_observed` semantics — mirror Phase 2C exactly.** Fires on the first
  observation that is *trusted at observation time* (`trustState==Trusted`), with
  `event_time = observed_at`, write-once per `threat_id` — identical to the
  existing `RecordThreatClockStart` trigger (`scheduler.go:964`), keeping the SLA
  start clock consistent with the 2C threat clock. Append-only: a later or
  earlier-arriving trusted observation never moves it (same as 2C acceptance
  test 28). There is no start-clock correction event; this is accepted.
- **`threat_eligible` lapse / config change.** Write-once on the *first* cycle a
  threat clears `minTechniques`. A later drop below threshold, or a change to the
  `minTechniques` constant, is **not** retroactive and never moves or duplicates
  the event.
- **Writer failure semantics — telemetry never breaks the pipeline.** Ledger
  inserts are **log-and-continue**, NOT in the source write's transaction: a
  ledger insert failure must never roll back a real lifecycle transition,
  generation attempt, or validation result. Because every event is an idempotent
  (`ON CONFLICT (idempotency_key) DO NOTHING`) derivation of exactly one
  authoritative row, a periodic **reconciler** re-emits any missed events from the
  source tables — §6 replay-safety and §10 backfill are the same mechanism run on
  a schedule. Silent gaps are therefore self-healing, not permanent.
- **Validation-event sourcing & factory-run proof.** Validation events are derived
  from `content_validations` rows at `level='EXECUTION'` whose `run_id` joins a
  `scenario_runs` row with `execution_kind='factory_validation'` — an explicit
  join at derive time, and the point where acceptance test 7's customer-run
  isolation is enforced. `validation_dispatched` → `validation_resulted` →
  `validated_coverage` are paired by `content_version_id` + `run_id`; a dispatch
  recorded before its run row exists simply carries a null `validation_run_id`
  until the result supplies it.

## 15. Owner decisions from builder-check (locked 2026-10-31)

- **Grain & cohort model.** TCV is measured **per `(threat, relationship_kind)`
  leg** (matching 2C's emulates/generated_for split); the "source" segment is the
  source of that leg's `threat_observed`. Each **stage is computed over its own
  independent population** — every leg that has both of that stage's bounding
  events — not restricted to fully-instrumented legs. **End-to-end**
  (observed→validated) is computed only over legs that reached
  `validated_coverage`. Every reported percentile is shown with its stage `n`,
  because stage populations differ by construction.
- **Validation-outcome segmentation = terminal cohort label, not a duration
  split.** Each leg carries a terminal bucket **{validated, failed, open}**.
  Duration percentiles (P50/P95) are computed on the **validated** cohort only;
  **failed** and **open** are reported as counts/rates alongside, never folded
  into duration percentiles.
- **Coverage is monotone for velocity.** First `validated_coverage` is a permanent
  achievement; later demotion / retire / supersede / revalidation does **not**
  un-measure it, and there is **no revoke event**. "Current coverage state" (is a
  threat covered *right now*) is explicitly a separate, out-of-scope projection
  over `content_version_events`, not a change to this metric.
- **No fixed SLA target in v1; open cohort reported to defang censoring bias.**
  v1 reports P50/P95 + bottleneck with **no target threshold** (targets and
  breach-rates are a later addition once a baseline exists). To stop a
  good-looking P95 from hiding unfinished slow legs, the projection always reports
  the **open cohort's count and oldest-open age** next to the percentiles.
