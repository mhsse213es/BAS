# Representative Factory Validation — Design

**Status:** approved 2026-11-03 (user directive is the binding authority)
**Author:** validation-lab work, 2026-11-03

## Problem

Factory validation dispatches generated content to the lab agent and judges
whether it executes. The content is tiny (~1.8 KB) but the orchestrator's
`scenario.BuildSteps` resolves each ART technique reference into every local
atomic variant **server-side**, so a few-technique artifact becomes a
462-step live run. The lab's run timeout is 10 minutes; a 462-step live
Windows run needs ~23. So routine validations never reach `completed` — they
time out / get reaped `partial`/`failed`, and nothing reaches
`validated_coverage`. Validation cost and reliability scale with scenario
length, which is the wrong design.

## Decision

Implement **representative, bounded** factory validation. A bounded subset
passing must **not** imply the entire scenario was validated.

### Requirements (binding)

1. **Deterministic selection** — a reproducible subset of steps, covering
   distinct techniques and execution paths where possible. Same immutable
   content version ⇒ same subset.
2. **Hard limits** — cap selected steps and wall-clock duration.
3. **Coverage accounting** — record total, selected, skipped, and techniques
   represented.
4. **Version binding** — bind the result to the exact immutable
   `content_version_id` and the validation profile.
5. **Honest outcomes** — PASS means *the selected validation profile passed*,
   not that every step/variant was tested. The profile and its coverage
   limits stay visible in the evidence.
6. **Failure semantics** — timeout, incomplete execution, missing telemetry,
   and infrastructure failure must never produce PASS.

### Architectural requirement — explicit validation profile

- `representative` — bounded subset, the routine factory-validation profile.
- `full` — complete scenario execution, reserved for deeper validation.

The lifecycle `VALIDATED` state means **"the recorded validation profile
passed."** When it was `representative`, the profile and its coverage
limitations remain in the evidence (the `content_validations` row for that
version, and the `validation_resulted` SLA event). `full` is defined but the
routine lab does not dispatch it yet.

### Timeout

`VALIDATION_LAB_TIMEOUT_MINUTES` becomes configurable **with a conservative
hard maximum** (30 min). Configuration must never turn an unbounded execution
into an accepted validation — bounding (requirement 1–2) is the real control,
not the timeout.

## How the current code shapes the fix

- Expansion is **orchestrator-side**: `handlers.go` `dispatchRun` →
  `scenario.BuildSteps(...)` ("all framework logic resolved server-side");
  `stepsTotalBase := len(steps)` is the honest full count (462). The agent is
  a dumb executor that runs the concrete `[]scenario.ScenarioStep` it is sent.
  **⇒ the cap lives in the orchestrator, after BuildSteps + existing filters,
  before `persistStepMeta`/dispatch.** No agent change.
- `scenario.ScenarioStep` carries `TaskID` (stable content-bound hash —
  reproducible sort key), `TechniqueID`, `ProxyTechniqueID` (exec-path
  wrapper), `Framework`, `Fidelity`.
- `scenario_runs` already has `steps_total_base` / `steps_eligible_base`
  coverage columns and a per-agent single-slot guard; it gains
  `validation_profile` + `validation_coverage` (jsonb).
- Validation verdict (`validationlab.classifyCompletedRun`) already satisfies
  requirement 6: PASS only when ≥1 step executed and none errored; nothing
  executed → NO_DATA; errored/non-completed/timeout/offline → FAIL/ERROR,
  never PASS. This is preserved unchanged; we only add profile+coverage to the
  recorded evidence.

## Selection algorithm (deterministic)

Input: the runnable `[]ScenarioStep` (after lab-only / MaxPrivilege /
prerequisite filters), plus the honest full-expansion total.

1. Stable-sort by `(TechniqueID, ProxyTechniqueID, TaskID)`.
2. Keep at most `PerTechnique` (default **1**) step per distinct `TechniqueID`
   — a representative atomic per technique, covering distinct techniques and
   exec paths.
3. Apply a global hard cap `MaxSteps` (default **25**) over the result, in the
   same stable order.

`TaskID` is a stable hash of the resolved step, so selection is reproducible
for a fixed content version. Coverage records
`{profile, total_steps, selected_steps, skipped_steps, techniques_total,
techniques_selected, truncated}`.

## Evidence & honesty

- Coverage + profile persist on `scenario_runs` at dispatch, and are copied
  into the `content_validations` row's `detail` and the `validation_resulted`
  SLA-event payload when the outcome is recorded. A representative PASS is
  therefore self-describing: "representative profile, N of M steps, T of U
  techniques". `validated_coverage` (the lifecycle milestone event) stays
  minimal; the authoritative coverage evidence is the `content_validations`
  row bound to the exact version.

## Non-goals

- No change to the agent, to `BuildSteps` expansion, or to the verdict logic.
- `full`-profile dispatch wiring (reserved; defined only).
- Per-tenant or per-content custom limits (defaults only for now).

## Acceptance criteria

A 462-step scenario completes representative validation within a predictable
budget, produces a reproducible selection and auditable coverage, binds the
result to the exact version + profile, and never claims full validation when
only a subset ran. Timeout/incomplete/infra failure never PASS.
