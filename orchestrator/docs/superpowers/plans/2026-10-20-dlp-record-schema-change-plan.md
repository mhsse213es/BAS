# DLP record schema change — review plan (no code yet)

Status: **proposed, for review.** No record-path code changes until this plan
is approved. Parent contract:
`docs/superpowers/specs/2026-10-20-dlp-metrics-definitions-draft.md` §5–6.

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
| Block | Blocked, **sink-receipt absent** | Inconclusive (not a confirmed block) |
| Block | Succeeded, sink-receipt present | FN |
| Allow | Succeeded, sink-receipt present | TN |
| Allow | Succeeded, local-marker only | Inconclusive |
| Any | Unknown / no observation | Untested |
| Any | Channel unsupported in environment | Unsupported |

Consequences to review explicitly:

- **Under these rules, today's DLP data yields only TN and FN, and only from
  sink-confirmed successes.** A block never produces TP or FP, because a block
  is evidenced only by an absent sink receipt or a local marker, and both are
  Inconclusive. Precision and recall therefore cannot be computed from DLP
  records until a destination-side block signal exists. This is a limit of the
  evidence, not a bug in the rules.
- FP (control acted where it should have allowed) would need a confirmed
  block of an allowed action, which also needs destination-side evidence.

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
- Seam test through `Tick`: a sink-confirmed Allow produces TN; a local-marker
  block produces Inconclusive, not TP; a missing receipt produces Inconclusive.
- Migration test: a row written by the current code has `NULL` for every new
  field after the migration, and its existing fields are unchanged.
- Endpoint test: existing response fields unchanged.

## 8. Open questions for review

1. Is `SimulationResult.ExecutedAt` the controlled test-event start? Needs
   agent-side verification before `test_event_timestamp` is populated.
2. Should `rule_version` be added in this change or a follow-up? Proposed: in
   this change, since it is needed to keep historical derivations honest.
3. Confirm the consequence in §3: DLP precision and recall are not computable
   until a destination-side block signal exists. Approve that as the expected
   state, or direct where the block signal should come from.
