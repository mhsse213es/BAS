# Phase 1: Exercise Detection Parity — Design

**Goal**

`internal/exercise` has no automated detection attribution today — bring it to parity with the
ART/Caldera `scenario_runs` path (`detect.Correlate`/`detect.Score`, the reference behavior) via
two tracks that converge on the same primitives:

- **Track 1 (BAS-backed):** `agent_task` steps already dispatch through `scenario_runs` — reuse its
  already-computed detection result instead of duplicating correlation logic.
- **Track 2 (exercise-native, this phase's scope: `phishing_reported` only):** normalize the
  existing phishing-report tracking signal into the same verdict/scoring vocabulary. No new
  external security-provider integration in this phase — that is a separate, later capability with
  its own scope (mail/SMS gateway APIs, credentials, polling, provider-specific attribution
  signals), not something Phase 1 is bounded by.

`wait_for_detection`/`bridgeVerifiedDetections` (human-verified SOC-analyst evidence) is a
different, existing mechanism and stays untouched — Phase 1 adds an automated path alongside it,
not a replacement.

## Context: what exists today, confirmed against real code

**ART/Caldera's reference pipeline** (`internal/api/detection_handlers.go`,
`SubmitRunDetections`, agent-authed `POST /api/scenarios/runs/{runId}/detections`):

1. Agent posts its post-run alert sweep (`[]detect.AlertRecord`).
2. Server loads `scenario_runs.results`, projects each into `detect.ExecutedStep{TechniqueID,
   Verdict, ExecutedAt, DurationMs}`.
3. `detect.Correlate(steps, alerts, 5*time.Minute, detect.DefenderDetectIDs())` — window-matches
   alerts to steps, then `attribution.go`'s `attributionSignals` decides whether a matched alert is
   evidence of a real control reaction (five signals today, all endpoint-security concepts:
   `defenderDetectId`, `threatName`, `edrProvider`, `kernelDenial`, `securitySubsystem`).
4. `detect.Score(dets)` aggregates into `DetectionRate/UndetectedRate/Logged/LoggedRate/MTTDMs`.
5. Verdicts merge back onto each `models.SimulationResult` (`DetectionVerdict`/`DetectionAlert`/
   `BlockingControl`).
6. Persisted onto `scenario_runs` (`detections_raw`, `detection_summary`, `detection_rate`,
   `undetected_rate`, `mttd_ms`, `alerts_total`, `alerts_high_fidelity`, `noise_score`).
7. Findings refreshed (`upsertFindingsForRun` — a caught fail flips to `detected_only`).

**Critical timing fact this design depends on** (`agent/agent.go:842-871`,
`collectAndSubmitDetections`): the agent waits a fixed 90s grace period, sweeps its alert sources
once, and **only calls `/detections` at all if `len(alerts) > 0`**. A clean run that triggers no
EDR alert — a completely normal, common outcome — never reaches this endpoint, and
`scenario_runs.detections_raw` stays `NULL` forever. "Detection data eventually appears" is
therefore not a valid wait condition; a bounded timeout is required.

**`internal/exercise` today** (`internal/exercise/executor.go`):

- `handleAgentTask` (line 415) dispatches into `scenario_runs` (`e.dispatch(...)`) and marks the
  step `StepCompleted` **the instant dispatch is sent** — before the underlying run even executes,
  let alone before any detection correlation happens. `StepExecution.Result` (an untyped
  `map[string]interface{}`, already holding `bas_run_id` today — no schema migration needed to add
  keys to it) never receives a detection verdict of any kind. `StepExecution.Status` is a pure
  execution-lifecycle enum (pending/running/waiting/completed/failed/cancelled/skipped), orthogonal
  to prevention/detection semantics.
- `wait_for_detection`/`triggerWaitForDetection`/`bridgeVerifiedDetections` (lines 606-675) is a
  **different, existing** mechanism: it bridges human-verified evidence
  (`e.verification.CurrentApprovedForRun`, a SOC-analyst-approval workflow) into exercise evidence,
  for plans that explicitly author a companion `wait_for_detection` step referencing an
  `execution_step_id`. It does not call `detect.Correlate` and shares no code with the reference
  pipeline. This mechanism is explicitly out of scope for Phase 1 — it stays as-is.
- `phishing_reported` is already a real, working signal (`Executor.evalCondition`'s
  `step:{id}:reported` predicate reads it via `hasEvidenceType(ctx, se.ID, "phishing_reported")`),
  sourced from the tracking-pixel/link-click infrastructure (`internal/exercise/tracker`). It is
  not currently connected to `detect.Correlate`/`Score` or any `DetectionVerdict` vocabulary.

## Track 1: BAS-backed steps reuse the existing pipeline

No new correlation logic. `handleAgentTask` changes from "dispatch, then immediately complete" to
"dispatch, then wait for the underlying run's detection state to settle, then propagate":

```
handleAgentTask (existing goroutine, executor.go:423-460)
  dispatch → runID
  (existing: SetStepResult {"bas_run_id": runID}, DispatchSentAt recorded)
  NEW: poll scenario_runs (status, results) for this runID:
    - every tick, check status IN ('completed','partial','failed') (completed_at IS NOT NULL)
    - once terminal: start a bounded grace window (matching the agent's own ~90s+sweep timing --
      see Error handling below for the exact value and its justification)
    - after terminal AND (detections arrived OR grace window elapsed): read
      scenario_runs.results[TechniqueID].DetectionVerdict/DetectionAlert/MTTDMs (already computed
      by SubmitRunDetections if it ran at all) and copy onto StepExecution.Result under new
      well-known keys: detection_verdict, detection_confidence, detection_mttd_ms,
      detection_alert (nested: channel/provider/eventId/threatName)
  mark StepCompleted (as today) only once this is done
```

This reuses the polling shape `triggerWaitForDetection` already established (a trigger checked on
the executor's existing tick cadence, `PollScheduler`) rather than inventing a new mechanism — the
difference from `wait_for_detection` is that this trigger is **built into `handleAgentTask`
itself**, automatic for every `agent_task` step, not something a plan author opts into by adding a
companion step. That matches the "BAS-backed steps get parity for free" intent — an exercise
author should not need to know detection correlation exists to get it.

**A step whose scenario_run status query fails, or whose run row simply doesn't exist yet** (a
transient race between the WS dispatch ack and the `scenario_runs` INSERT — extremely unlikely
given `insertExecutionAttempt`'s ordering, but not impossible) is treated as "not ready yet," not
an error — same non-terminating-poll discipline `bridgeVerifiedDetections` already uses for a
referenced step with no `StepExecution` row yet.

## Track 2: exercise-native, `phishing_reported` only

**The small conceptual generalization**, per the collaborative design: `detect.Correlate`'s
five-signal attribution model is entirely endpoint-security-shaped. Rather than inventing a
parallel scoring path, add **one new signal**:

`internal/detect/attribution.go`, `attributionSignals`, new case:

```go
// A simulated-phishing recipient reported it through the exercise's own
// tracking/report mechanism -- a real, human-confirmed control reaction,
// just not an endpoint one. Distinct from the five signals above (which are
// all endpoint/EDR/kernel-audit concepts) but participates in the exact
// same attribution/verdict/scoring model.
if a.Channel == "exercise-report" {
	out = append(out, "userReported")
}
```

No change to the five existing signals, no change to `Correlate`'s or `Score`'s core mechanics —
this is additive, and the existing `IsAttributable`/`Correlate` call sites for the ART/Caldera path
are untouched (a `Channel: "exercise-report"` alert never appears in that path's real alert
streams, so this is inert there).

**The adapter** (new function, `internal/exercise`, called from the executor's existing tick —
poll-based, reusing the exact `wait_for_detection`-style cadence rather than firing synchronously
when evidence is appended, per the collaborative decision to reuse the existing pattern rather than
add new event-driven plumbing):

```
for each StepExecution of type send_email/StepTypeSendEmail whose step is StepCompleted and has
not yet been detection-scored (no detection_verdict key in Result):
    reported, reportedAt := hasEvidenceType(ctx, se.ID, "phishing_reported") -- already exists
    alerts := []detect.AlertRecord{}
    if reported {
        alerts = append(alerts, detect.AlertRecord{
            Channel: "exercise-report", Provider: "exercise-tracking",
            Timestamp: reportedAt, Message: "recipient reported the simulated phishing email",
        })
    }
    steps := []detect.ExecutedStep{{TechniqueID: <the step's tagged technique, e.g. T1566.001>,
        Verdict: "completed", ExecutedAt: <send time>, DurationMs: 0}}
    dets := detect.Correlate(steps, alerts, <window -- see below>, nil) // no DefenderDetectIDs; irrelevant here
    sum := detect.Score(dets)
    write detection_verdict/detection_confidence onto StepExecution.Result, same keys Track 1 uses
```

Both tracks write the **same** `StepExecution.Result` keys — a report or UI consuming exercise
results does not need to know which track produced them.

**Window duration** for Track 2's `Correlate` call is deliberately not the ART/Caldera path's fixed
5-minute post-execution window — a phishing report can arrive hours or days after the email was
sent (this is normal; awareness-training reporting is not a race). The correlation "window" here is
really just "has a report evidence record appeared for this step at all," so `Correlate` is called
with a window wide enough to never be the limiting factor (e.g., the plan/execution's own
configured lifetime), not reused as a literal 5-minute constant from the endpoint path.

**Which step types are in scope for Track 2 in this phase:** only `send_email`
(`StepTypeSendEmail`), since `phishing_reported` is the one signal this phase covers.
`send_sms`/`slack`/`teams` steps get no Track 2 detection scoring yet — extending the pattern to
another step type is additive (new evidence type + new adapter branch), not a redesign, and
deliberately deferred rather than spec'd here without a concrete second signal to design against.

## Data model

No schema migration. `StepExecution.Result` (`map[string]interface{}`) gains well-known keys,
written by both tracks identically:

```json
{
  "bas_run_id": "...",              // Track 1 only, unchanged from today
  "detection_verdict": "detected",  // "prevented" | "detected" | "undetected" | "logged"
  "detection_confidence": "high",   // "high" | "medium" | "low" -- from detect.TechniqueDetection.Confidence
  "detection_mttd_ms": 4200,        // omitted when there was no alert to time
  "detection_alert": {              // omitted when there was no alert
    "channel": "...", "provider": "...", "eventId": 0, "threatName": "..."
  }
}
```

## Error handling

- **Track 1's grace-window duration:** match the agent's own `graceWait` (90s,
  `agent/agent.go:847`) plus enough margin for the sweep + network round-trip to land server-side —
  120s total is a reasonable starting bound (evidence-adjustable later the same way T1018/T1087.002's
  timeout budgets were, not asserted as final here). After that window with no detections row
  populated, the step completes with `detection_verdict` **absent** (not a fabricated "undetected"
  verdict) — absence here means "no alert arrived to correlate against," which is different from
  "correlated and found nothing," and reports must not conflate the two, matching this whole
  session's running discipline (nil means not-reported, never inferred as a negative signal).
- **A `scenario_run` that never reaches a terminal status** (e.g., agent went offline mid-run,
  caught by the existing reaper paths in `liveness.go`) — Track 1's poll keeps checking on the
  normal tick cadence; once the reaper marks it `partial`/`failed`, Track 1 proceeds from there.
  No new stuck-forever risk: the existing reaper infrastructure already bounds this.
- **A step tagged with no recognizable technique ID** (Track 2) — skip detection scoring for that
  step entirely (no `detect.ExecutedStep` can be built without one), do not fabricate a verdict.

## Explicitly out of scope for Phase 1

- Any external security-provider integration (mail-security gateway APIs, SMS-carrier block
  signals, or any other non-endpoint alert *source*) — this is a separate, future capability
  ("Mail Security Detection Integrations" or similar), with its own scope (auth/credentials,
  provider schemas, polling/webhooks, its own attribution signals). Track 2 in this phase only
  wires the tracking signal the platform *already collects*.
- `send_sms`/`slack`/`teams`/any step type besides `send_email` for Track 2.
- Any change to `wait_for_detection`/`bridgeVerifiedDetections` (human-verified evidence) — stays
  exactly as it is.
- Any change to the five existing endpoint attribution signals or to `Correlate`/`Score`'s core
  mechanics.
- UI/report surfacing of the new `StepExecution.Result` detection keys — this phase makes the data
  exist and be queryable/correlatable, matching the precedent set by `CleanupError` earlier this
  session; a dedicated UI pass is separate follow-up work if wanted.

## Testing

- `internal/detect`: a unit test for the new `userReported` signal (`Channel: "exercise-report"`
  alert → signal present; any other channel → signal absent), mirroring the existing per-signal
  test shapes in this package.
- `internal/exercise`: a container-backed test driving a real `agent_task` step through a fake
  agent to a terminal `scenario_run` with a real `SubmitRunDetections` call, then asserting Track
  1's poll picks up the resulting `DetectionVerdict` onto `StepExecution.Result` — and a sibling
  test asserting the grace-window-elapsed-with-nothing case completes with the key absent, not a
  fabricated verdict.
- `internal/exercise`: a container-backed test seeding `phishing_reported` evidence on a completed
  `send_email` step and asserting Track 2's adapter produces the correct `detection_verdict` on the
  next tick.

## Success criteria

1. A completed `agent_task` step's `StepExecution.Result` carries the same `DetectionVerdict` the
   underlying `scenario_run`'s report already shows — no duplicated correlation logic exists
   anywhere in `internal/exercise`.
2. A `send_email` step with `phishing_reported` evidence produces a `detected`-class verdict via
   the same `detect.Correlate`/`Score` functions the ART/Caldera path uses, through the new
   `userReported` signal — not a second, parallel scoring interpretation.
3. `wait_for_detection`'s existing human-verification behavior is provably unchanged (its own
   existing tests still pass unmodified).
4. Zero new external integrations, zero new schema migrations, zero changes to the five existing
   endpoint attribution signals.
