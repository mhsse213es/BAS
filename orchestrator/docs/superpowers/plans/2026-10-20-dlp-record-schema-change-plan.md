# DLP record schema change — review plan (no code yet)

Status: **proposed, for review.** No record-path code changes until this plan
is approved. Parent contract:
`docs/superpowers/specs/2026-10-20-dlp-metrics-definitions-draft.md` §5–6.

## 0. Blockers (must be resolved before implementation)

**B1. Destination-side block evidence contract — APPROVED, with conditions.**

Classification of each scored decision (approved 2026-10-20):

- **Confirmed blocked:** a DLP or SIEM event explicitly reports `action = block`,
  and its sink token or correlation ID matches the relevant test step.
- **Inconclusive:** the sink receipt is absent; a local marker exists without a
  matching authoritative event; the correlation fails; or the event does not
  establish a block.
- **Not blocked:** a correlated event explicitly establishes that the action was
  allowed or otherwise not blocked. Never inferred from missing evidence.
- **Conflicting evidence:** if correlated sources disagree, the conflict is
  preserved and the result is Inconclusive until resolved.

Each evidence record retains: source, event ID, correlation identifier, event
timestamp, reported action, and verification status.

**Adapter conformance — UNVERIFIED.** This approves the contract, not the claim
that `internal/vendors/*` implements it correctly. None of the adapters has been
verified against a live tenant. Conformance is labelled unverified until tested,
and no metric may rely on a block from an adapter until then.

**B2. `test_event_timestamp` semantics — DECIDED (Option A, approved 2026-10-20). Contract below; not yet implemented. Field stays unpopulated until the payload marker exists.**

**Decision:** the controlled test-event start is the timestamp the test payload
records itself immediately before it attempts the transfer. Dispatch time
(Option B) is not used as an event start.

**Contract (Option A):**
- **Marker:** a stdout line `DLP_EVENT_START: <task_id> <rfc3339nano_utc>`,
  written by the payload immediately before the transfer attempt. `<task_id>` is
  the step's `TaskID` as given to the payload, so the marker correlates to one
  step. It parallels the existing `DLP_OBSERVATION:` marker, which is a
  stdout-line regex in `internal/reporting/dlp.go`.
- **Clock source:** the test host's wall clock, UTC. The payload reads the clock
  on the same host where the transfer is attempted.
- **Parsing:** a separate regex and parser, not shared with `DLP_OBSERVATION`.
  Exactly one matching marker for the step's `task_id` gives a value. Zero
  markers, two or more markers, or an unparseable timestamp gives NULL, with the
  reason recorded (`no_marker`, `ambiguous`, `unparseable`).
- **Both execution paths:** the marker is stdout, so it is captured the same way
  on the pooled path and the per-process path. Both are covered.
- **Source column:** a new `test_event_source` field records how the value was
  obtained (`payload-marker`, or NULL). It is added alongside
  `test_event_timestamp`, so a dispatch time can never be mixed into an
  event-time column.
- **Latency gate:** latency still requires a measured clock-skew bound between
  the test host and the detection source (§3.4 of the metrics spec). Until it is
  measured, latency is undefined, even when the marker exists.
- **Prerequisite found (blocks the payload change):** the payload cannot learn
  its own `task_id`. The agent exports no task identifier to step processes.
  The only `BAS_*` variables set in `agent/*.go` are config-file values, and
  `BAS_RUN_ID` is read by 21 scenarios but set by no agent code, so those
  scenarios always fall back to a random ID. The marker's correlation key
  therefore needs a new agent-side step variable (for example `BAS_TASK_ID`),
  set in both `executor.go` (per-process) and the pooled host path
  (`pool_windows.go`). The pooled host is a persistent PowerShell process, so
  per-step env propagation there is unverified. Until the variable is delivered
  on both paths, no marker can be correlated, and no payload change should land.
- **Implementation scope (not started):** scenario payloads that perform
  transfers gain the marker line, the parser and the column are added, and every
  edited scenario is re-signed (`.sig`) and verified. Historical rows stay NULL.

**Options considered:**

Verified at the agent boundary (`agent/executor.go`, `agent/pool_windows.go`):

| Timestamp | Set where | Meaning | Usable as test-event start? |
|---|---|---|---|
| `before` (executor.go:188) | per-process path, before token/env setup and `cmd.Start()` (line 277) | pre-launch dispatch time for the step | No. Includes setup, and is not the moment the test action happens. |
| `StartedAt` (executor.go:443) | copies `before` into the per-process result | same as above | No, same reason. |
| `ExecutedAt` (executor.go:292, 448; pool_windows.go:238) | when the result is built, after the process or host responds | completion time | No. |
| pooled path `StartedAt` | **not set**. The pooled `ExecResult` (pool_windows.go:230-240) omits it, so the field is zero | none | No. Pooled PowerShell discovery steps have no start time at all. |

Consequence: no existing agent timestamp marks when the controlled test action
happens. For DLP steps that action is a transfer performed inside the command, so
the agent cannot observe it from outside the process.

**Definition options for B2 (for approval, none chosen):**

- **Option A (chosen): test-payload timestamp.** The test payload records its
  own clock reading at the moment it attempts the transfer, in the same way it
  already writes `DLP_OBSERVATION:` markers, and that reading becomes the start.
  Requires scenario and payload changes (and re-signing), a defined clock source,
  and a documented skew bound against the detection source. This is the only option
  that marks the event itself.
- **Option B: agent dispatch time.** `before`, recorded for every step including
  pooled ones. Cheap, but it is a dispatch time. It must be named that way, and it
  cannot back an "event start" claim. Its use would also need the pooled path
  changed to record a time.

**Acceptance criteria before `test_event_timestamp` is populated:**
1. The start event, stop event, clock source and comparability requirement are
   written in the metrics spec (§3.4).
2. The start timestamp is recorded by the step that performs the action, or is
   clearly labelled as dispatch time (Option B), never silently substituted.
3. Pooled and per-process steps both record it, or the affected steps are
   excluded from latency and the exclusion is counted.
4. Each stored value carries its source, so a dispatch time and an event time are
   never mixed in one report.
5. Historical rows stay NULL. No backfill from `ExecutedAt`, `StartedAt` or `before`.

Implementation does not start while B1 and B2 are open.

## 1. Why

`dlp_evidence_records` (migration in `internal/db/postgres.go`) stores one
`dlpreport.Record` JSON per (run, step, expectation). It carries the
enforcement outcome and the verbatim comparison, but not the three fields the
approved metric definitions need. Without them, precision, recall and FN rate
cannot be computed from stored data, and latency cannot be computed at all.

## 2. Fields

| Field | Type | Allowed values | Nullable | Meaning |
|---|---|---|---|---|
| `decision_class` | text | `TP` `TN` `FP` `FN` `Unsupported` `Untested` `Inconclusive` | Yes | Classification of one scored decision, per the approved exclusion rules |
| `evidence_source` | text | `sink-receipt` `local-marker` `none` | Yes | How the actual outcome was established |
| `test_event_timestamp` | timestamptz | — | Yes | Start of the controlled test event (payload marker, §0 B2), for latency |
| `test_event_source` | text | `payload-marker` | Yes | How `test_event_timestamp` was obtained; NULL when no value. Dispatch times never appear here. |

Nullability is deliberate. `NULL` means *unknown*, never a default value.

## 3. Derivation rules (proposed)

These rules only run for rows written after the migration. They use the
expected outcome from the scenario expectation and the observed outcome from
the evidence the verifier already uses.

**decision_class**

| Expected | Observed (evidence) | decision_class |
|---|---|---|
| Block | Correlated authoritative event, `action = block` (confirmed blocked) | TP |
| Block | Correlated event establishes not blocked | FN |
| Block | Sink receipt absent, local marker only, correlation fails, or no establishing event | Inconclusive |
| Block | Correlated sources conflict | Inconclusive (conflict preserved) |
| Allow | Correlated event establishes not blocked, or sink receipt present for an allowed transfer | TN |
| Allow | Correlated event reports `action = block` | FP |
| Allow | Local marker only, or no establishing event | Inconclusive |
| Any | Unknown / no observation | Untested |
| Any | Channel unsupported in environment | Unsupported |

Consequences to review explicitly:

- **A block counts as TP or FP only from a correlated authoritative event.**
  Today's sink receipts confirm transfers that succeeded, not blocks, so they
  support TN and FN, not TP or FP. Until a DLP or SIEM adapter is verified
  against a live tenant, no adapter-sourced block may be counted.
- **Rows written before any adapter exists cannot yield TP or FP.** Precision
  and recall stay uncomputable for DLP records until then. This is a limit of
  the evidence, not a bug in the rules.

**evidence_source** is taken directly from the existing `collection_method`
(`sink-receipt` or `local-marker`), or `none` when no observation was made.

**test_event_timestamp** is open. `SimulationResult.ExecutedAt` is recorded
per step, but nothing establishes that it is the start of the controlled test
event rather than the time the agent reported execution. This must be verified
against the agent code before it is used. Until then it is not populated.

## 4. Provenance

- Values are derived at write time in `verifysync` from the verdict, the
  evidence and the scenario expectation. They are not derived at report time.
- Each derived value stores the rule identifier that produced it, so a later
  rule change does not silently relabel old rows. (Stored as a `rule_version`
  text column, nullable.)

## 5. Compatibility

- Adding nullable columns is additive. `DLPRecordsForRun` and the endpoint
  `GET /api/scenarios/runs/{runId}/dlp-records` continue to return the
  existing fields; the new fields are added to the response only after review.
- The `dlpreport.Record` JSON shape is unchanged. The new fields live in the
  table columns, not inside the record JSON, so existing readers are unaffected.
- The primary key `(run_id, task_id, expectation_id)` is unchanged.

## 6. Migration and backfill

- Migration: `ALTER TABLE dlp_evidence_records ADD COLUMN IF NOT EXISTS ...`
  for each column, all nullable, no default. Idempotent, consistent with the
  existing migration style in `EnsureSchema`.
- **Backfill: none.** Historical rows keep `NULL` for all new fields. They are
  not assigned decision classes, evidence sources or timestamps they never had.
  Reports treat them as *unknown*, and their count is reported.
- Rows written before this migration will therefore be excluded from any metric
  as Untested-unknown, and that exclusion is counted and shown.

## 7. Test plan (for implementation, after approval)

- Derivation table: every row above has a unit test.
- Block contract (B1), one test per class:
  - correlated authoritative event, action = block, token matches → TP
  - correlated event establishes not blocked → FN (expected Block) / TN (expected Allow)
  - correlated event, action = block, expected Allow → FP
  - sink receipt absent → Inconclusive
  - local marker only, no matching authoritative event → Inconclusive
  - correlation identifier fails to match → Inconclusive
  - correlated sources disagree → Inconclusive, both sources preserved
  - no evidence of a block from missing data alone → never TP
- Evidence record retains source, event ID, correlation identifier, event
  timestamp, reported action and verification status; each has a presence test.
- Adapter conformance: every adapter-sourced test is labelled
  `conformance=unverified` in its output until a live-tenant test exists.
- Seam test through `Tick`: a sink-confirmed Allow produces TN; a local-marker
  block produces Inconclusive, not TP; a missing receipt produces Inconclusive.
- Migration test: a row written by the current code has `NULL` for every new
  field after the migration, and its existing fields are unchanged.
- Endpoint test: existing response fields unchanged.

## 8. Status of open questions

1. **B2 — OPEN.** `ExecutedAt` is the completion time and `StartedAt` the
   pre-launch time (verified in `agent/executor.go`). Neither is a trustworthy
   controlled test-event start. `test_event_timestamp` stays unset, latency stays
   undefined, and implementation does not begin until a test-event start is
   defined and verified at the agent boundary.
2. **`rule_version` — proposed for this change**, so historical derivations stay
   honest. Pending approval with the rest of the plan.
3. **B1 — RESOLVED.** The contract in §0 is approved, with the four-class
   distinction and the adapter-conformance label. Precision and recall remain
   uncomputable until an adapter is verified against a live tenant.

**Gate:** implementation and any push remain blocked until B2 is resolved and
this plan is reviewed again.

## 9. Implementation status (2026-10-20)

- Done: `DLP_EVENT_START` parser (`reporting/dlp_event_start.go`); columns
  `test_event_timestamp`, `test_event_source`, `decision_class`,
  `evidence_source`, `rule_version`; B1 derivation (`verifysync/dlprecord_decision.go`);
  per-process and pooled `BAS_TASK_ID`; markers in 12 DLP scenarios (re-signed,
  verify-all 126/126). Migration additive, no backfill.
- **Not done: end-to-end run.** The USB marker fires only with removable media.
  Needs a lab host with a removable drive; a single step run confirms the marker
  reaches `dlp_evidence_records`.
- **Clock-skew measurement: not established.** One host reading, `w32tm /query
  /status`: source `time.windows.com`, stratum 5, root dispersion 7.89 s. This is
  the host's own error estimate against its time source, not skew against the
  detection source. It says a bound from this host would be seconds wide, so
  latency stays undefined. Next step: measure against the detection source's
  clock and state the bound.
- **Not all DLP steps emit the marker.** Multichannel's archive step and the
  validation archive step are local ZIP writes, not outbound attempts, so they get
  none by design.
- **Pre-existing failure:** `dlpfixture` drift test reports unregistered fixture
  values in the AI-prompt and DB-export steps. The payload values are unchanged by
  this work (YAML diff is additive), so the failure predates it.
