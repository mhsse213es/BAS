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

**B2. `test_event_timestamp` semantics — VERIFIED, field stays unpopulated.**
Checked in `agent/executor.go`:
- `StartedAt` is captured before the command launches (line 188). It is the
  closest candidate for the start of the controlled test event, but it is the
  agent's pre-launch time, not an independently verified test-event start.
- `ExecutedAt` is set when the result is built, after the process exits
  (lines 292 and 448). It marks completion. It must not be used as the
  test-event start.
- Neither field is a verified controlled-event timestamp. `test_event_timestamp`
  remains unset. Latency stays undefined until a test-event start is defined and
  verified at the agent boundary.

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
| `test_event_timestamp` | timestamptz | — | Yes | Start of the controlled test event, for latency |

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
