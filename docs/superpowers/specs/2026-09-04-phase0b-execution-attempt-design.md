# Phase 0B: Unified ExecutionAttempt Contract — Design

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:writing-plans to create the implementation plan for this spec.

## Goal

Give the platform one authoritative, queryable record of "did an executable unit run, and what happened" — spanning both execution engines that exist today — as the foundation Phase 0C (prerequisite evaluation), objective-level scoring, and eventually DAG/parallel execution (Phase 2-3, H2 2026) will consume. Nothing here changes scoring, dispatch, or agent protocol; this is purely an additive observability/audit layer.

## Context: two execution engines, confirmed during Phase 0A

This codebase runs technique/step execution through two structurally different subsystems, discovered the hard way during Phase 0A when instrumentation was first (incorrectly) attached to the wrong one:

1. **ART/Caldera `scenario_runs`** (`orchestrator/internal/api/handlers.go`: `dispatchRun` → `SubmitScenarioResult`) — the real production path for technique execution. The agent receives a whole scenario in **one** WebSocket message and executes every step internally, reporting back **once** when the entire scenario finishes. The orchestrator has zero visibility into individual technique timing inside that window — confirmed by Phase 0A's real measurement (dispatch→result span of 27.3s for a 30-step run, matching the agent's own reported elapsed time almost exactly, with no internal structure visible from the server side).

2. **`internal/exercise`** (`Plan`/`PlanStep`/`Execution`/`StepExecution`, `executor.go`'s `tick()`/`advance()`) — a separate DAG engine for multi-step exercises (`send_email`, `agent_task`, `wait_for_detection`, etc.). Already has `StepExecution` as a partial per-step attempt-state analog, and gained 4 timestamp fields during Phase 0A's original (mis-scoped) instrumentation attempt: `PollSelectedAt`, `DispatchSentAt`, `ResultReceivedAt`, `ScoringCompletedAt`.

## Scope decision

**Unified across BOTH engines**, but explicitly **not unified granularity**:

| Execution type | ExecutionAttempt granularity | Why |
|---|---|---|
| `internal/exercise` | Per-step | `StepExecution` already tracks this |
| ART/Caldera (current) | Per-run | Agent gives one aggregate result; per-technique visibility does not exist server-side |
| ART/Caldera (future) | Per-technique, if agent protocol changes to stream step results | Schema supports this without redesign — see `technique_id` below |

**Design principle:** an `ExecutionAttempt` represents the smallest unit of execution evidence *actually available*, never a manufactured technique-level record where the agent only gave us a run-level aggregate. Pretending otherwise would fabricate precision Phase 0C's prerequisite evaluation would then trust incorrectly.

## Schema

```sql
CREATE TABLE execution_attempts (
    id                  UUID PRIMARY KEY,
    source              TEXT NOT NULL CHECK (source IN ('art', 'caldera', 'exercise')),
    granularity         TEXT NOT NULL CHECK (granularity IN ('run', 'step')),
    source_execution_id TEXT NOT NULL,
    source_attempt_id   TEXT NOT NULL,
    technique_id        TEXT,  -- nullable, no CHECK constraint — see rationale below

    status              TEXT NOT NULL CHECK (status IN (
        'pending','dispatched','running','completed','timed_out',
        'cancelled','abandoned','failed_to_dispatch','skipped'
    )),
    skip_reason         TEXT,

    created_at          TIMESTAMPTZ NOT NULL,
    dispatch_queued_at  TIMESTAMPTZ,
    dispatch_sent_at    TIMESTAMPTZ,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    decision_at         TIMESTAMPTZ,

    result              JSONB,

    CONSTRAINT execution_attempts_skip_reason_ck CHECK (
        (status = 'skipped' AND skip_reason IS NOT NULL) OR
        (status <> 'skipped' AND skip_reason IS NULL)
    ),
    CONSTRAINT execution_attempts_decision_at_ck CHECK (
        (status = 'skipped' AND decision_at IS NOT NULL) OR
        (status <> 'skipped' AND decision_at IS NULL)
    ),
    UNIQUE (source, source_attempt_id)
);

CREATE INDEX idx_execution_attempts_execution ON execution_attempts(source_execution_id);
CREATE INDEX idx_execution_attempts_technique ON execution_attempts(technique_id) WHERE technique_id IS NOT NULL;
CREATE INDEX idx_execution_attempts_status ON execution_attempts(status);
```

### Field rationale

- **`source_execution_id` not a real FK.** It points into either `scenario_runs.id` or `exercise.Execution.id` depending on `source` — those live in different logical domains, and a real FK constraint would force picking one, breaking the unification. The polymorphic relationship is documented here, not enforced by the schema.
- **`technique_id` nullable, no CHECK requiring it for `granularity='step'`.** `internal/exercise` has legitimate non-technique steps: `send_email`, `wait_for_approval`, `webhook`, `slack`/`teams` notify. Only `StepTypeAgentTask` (via `AgentTaskConfig.TechniqueID`) carries a real MITRE technique ID. A constraint here would break every non-agent-task exercise step.
- **`skipped` is a first-class status, not the absence of a row.** Semantic: *"the orchestrator made a decision about whether an executable unit should run — not necessarily that bytes were dispatched to an agent."* This matters directly for Phase 0C: `"SKIPPED because domain_joined=false"` needs a row to query. Silence (no row) would give Phase 0C's prerequisite-evaluation reporting nowhere to look.
- **`decision_at` distinct from `completed_at`.** `completed_at` means *agent execution actually completed*; `decision_at` means *the orchestrator finished deciding not to execute at all*. Conflating them would make a skip look like a completion.
- **`UNIQUE (source, source_attempt_id)`** is the idempotency guard against duplicate inserts on retry of the write-side call itself (not to be confused with retry of the underlying technique — see the known gap below). The *producer* (dispatchRun, or the exercise executor) is responsible for supplying a stable `source_attempt_id`; the table does not infer identity from other columns, because a future protocol change (streaming per-technique ART results) could legitimately produce multiple attempts for the same technique within one run, which any inferred key would wrongly collapse.
- **No timestamp/status transition CHECKs beyond the two above.** The lifecycle has legitimate intermediate states and enforcing every transition at the DB layer would make write-side integration brittle. The application owns the state machine; the DB only guards the one invariant (skip-consistency) that's cheap and unambiguous.

### Status enum semantics

Deliberately **separate from scoring verdict** (`PASS`/`FAIL`/`ERROR`/`SKIPPED`, see `project_scoring_verdicts` in project memory). `ExecutionAttempt.status` answers *"did execution happen?"*; scoring answers *"what did the execution mean?"*. Example: `ExecutionAttempt.status = completed` can coexist with `verdict = FAIL` (the technique ran, the control let it through) — the execution table is never responsible for scoring semantics. A scoring verdict of `SKIPPED` would be *derived/projected* from an `ExecutionAttempt` with `status = skipped`, not stored redundantly here.

```
pending             — created, not yet dispatched
dispatched          — sent to agent, WS send confirmed
running             — agent confirmed execution started (where available)
completed           — agent returned a result (technique success/failure is scoring's concern, not this)
timed_out           — execution deadline hit (StepTermination.reason=execution_timeout)
cancelled           — operator/scenario cancel (StepTermination.reason=scenario_cancelled)
abandoned           — agent went offline mid-execution, never confirmed (ReapAbandonedRuns case)
failed_to_dispatch  — never reached the agent at all (offline, WS send failed)
skipped             — eligible for consideration, but intentionally not executed (prerequisite/condition)
```

`skip_reason` values (extensible, not a DB enum — application-level vocabulary): `condition_false`, `prerequisite_unsatisfied`, `scenario_cancelled_before_dispatch`, `dependency_failed`.

## Write-side integration

| Engine | `source` | `granularity` | `source_execution_id` | `source_attempt_id` |
|---|---|---|---|---|
| ART/Caldera | `art` or `caldera` (per scenario framework) | `run` | `scenario_runs.id` | `scenario_runs.id` (same value — exactly one row per run) |
| Exercise | `exercise` | `step` | `Execution.ID` | `StepExecution.ID` |

**ART/Caldera write points** (same locations as Phase 0A's `[perf]` logging, `orchestrator/internal/api/handlers.go`):
- Insert row (`status='pending'`, `created_at=NOW()`) immediately after the `scenario_runs` INSERT in `dispatchRun`
- Update to `status='dispatched'`, `dispatch_sent_at=NOW()` after `SendToAgent` succeeds (both the posture/local_check branch and the live ART/Caldera branch)
- Update to `status='completed'`, `completed_at=NOW()`, `result=<raw payload>` at the start of `SubmitScenarioResult`
- Terminal-status updates for `timed_out`/`cancelled`/`abandoned`/`failed_to_dispatch` map onto the existing `ReapStaleRuns`/`cancelScenarioRun`/`ReapAbandonedRuns`/offline-`SendToAgent`-failure code paths respectively — each already exists and already transitions `scenario_runs.status`; this adds a mirrored transition on the new table at the same call sites.

**Exercise write points** (`orchestrator/internal/exercise/executor.go`, alongside existing `UpsertStepExecution` calls):
- Insert/update mirrored at each place `UpsertStepExecution` is called, mapping `StepStatus` → the new enum (`StepPending`→`pending`, `StepRunning`→`dispatched`/`running`, `StepCompleted`→`completed`, `StepCancelled`→`cancelled`, `StepSkipped`→`skipped` with `skip_reason='condition_false'`, `StepFailed`→ nearest matching terminal status based on the failure's actual cause)

## Known gap, deliberately accepted (Option A)

**`internal/exercise` does not preserve attempt history today.** Investigated during this design: `UpsertStepExecution`'s SQL is `INSERT ... ON CONFLICT (execution_id, step_id) DO UPDATE` — a retried step reuses the same row (`same .ID`), and the `StepExecution.Attempt` field, while it exists in the Go struct, **is never incremented anywhere in the package** (confirmed by an exhaustive grep — dead field). A step that fails, retries, and succeeds leaves zero trace of the failed attempt; only the final state survives.

**Consequence:** using `source_attempt_id = StepExecution.ID` means every retry of the same step collapses into the *same* `execution_attempts` row via the `UNIQUE` constraint, so for `internal/exercise`, this table captures **latest known state, not full attempt-by-attempt history** — for this engine only. ART/Caldera is unaffected (one row per run, no retry concept at that granularity today).

**Decision: accept this gap for Phase 0B.** Fixing `internal/exercise`'s retry-tracking (making `Attempt` real, incrementing it, changing `UpsertStepExecution`'s conflict key) is a separate, genuine piece of work in a different subsystem — bundling it into this phase would be scope creep the project has deliberately avoided elsewhere (see `feedback_adapt_dont_stop` in project memory: minimal-first-pass, don't build ahead of what's actually needed). Revisit only if a concrete downstream consumer (Phase 0C or later) demonstrably needs real exercise-step retry history and the gap becomes a blocker, not speculatively.

## Explicitly out of scope for Phase 0B

- Changing the ART/Caldera agent protocol to stream per-technique results (would enable true per-technique granularity there — noted as a possible *future* phase in the schema's design, not built now)
- Fixing `internal/exercise`'s retry/attempt tracking (see gap above)
- Any change to scoring, verdict computation, or the existing `scenario_runs`/`exercise_step_executions` tables — this is a pure addition alongside them
- Prerequisite evaluation logic itself (Phase 0C consumes this table; Phase 0B only makes the table exist and get populated correctly)
- Any UI/dashboard surfacing of `execution_attempts` data (not requested, no current consumer beyond future Phase 0C)

## Testing

- Unit tests: `source_attempt_id`/`source_execution_id` population is correct for each write point, for both engines
- Constraint tests: skip-consistency CHECK constraints reject a `skipped` row missing `skip_reason`/`decision_at`, and reject a non-skipped row that has either set
- Idempotency test: calling the same write-point insert logic twice with the same `source_attempt_id` does not create a duplicate row (exercises the `UNIQUE` constraint's actual purpose)
- Integration test: trigger a real scenario run (or use the existing container-backed test harness pattern from `pause_resume_handlers_test.go`/`liveness_test.go`), confirm exactly one `execution_attempts` row exists per run with the expected status transitions

## Success criteria

1. `execution_attempts` table exists with the schema above, migration applied
2. ART/Caldera runs produce exactly one row each, transitioning through `pending`→`dispatched`→`completed` (or a terminal failure status) matching `scenario_runs.status`
3. Exercise steps produce a row per `StepExecution`, transitioning through the mapped statuses
4. Skipped steps produce a row with `status='skipped'`, populated `skip_reason` and `decision_at`, null `dispatch_queued_at`/`dispatch_sent_at`/`started_at`/`completed_at`
5. No existing behavior changes — `scenario_runs`, `exercise_step_executions`, scoring, and dispatch are untouched; this is purely additive
6. Table is ready for Phase 0C to query (not yet consumed by anything in Phase 0B itself)
