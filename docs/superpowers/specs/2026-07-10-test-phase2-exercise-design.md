# Test Generation Phase 2 — `exercise` Package Design

**Status:** Design (spec) — approved for planning
**Date:** 2026-07-10
**Master strategy:** `docs/superpowers/specs/2026-07-09-test-generation-strategy-design.md` (Phase 2 row: `exercise`, 90%+, "workflow orchestration, execution state, cancellation, retries, concurrency, transactional behavior")
**Predecessors:** Phase 0 (`internal/testutil` harness + CI) and Phase 1 (`verification`/`relationships` store tests) — both DONE and pushed.

---

## 1. Goal

Add high-confidence regression tests for `orchestrator/internal/exercise` (the exercise/BAS-tabletop orchestration engine) and the pure-logic units of its `tracker` sub-package. Characterization testing of working code: tests encode the store and executor's **actual** behavior. No product-code changes except one approved shared-harness improvement (§4).

Primary objective is a regression safety net for the DAG executor's state machine, the tamper-evident evidence hash chain, plan validation, and variable resolution — the parts whose silent breakage would corrupt an exercise run or its audit trail.

## 2. Scope

**In scope (this phase):**
- `internal/exercise` package: `validator.go`, `variables.go`, `registry.go`, `triggers.go`, `scheduler.go`, `evidence.go`, `store.go`, `executor.go` (state machine + lifecycle + score + condition evaluation), and the pure helpers in `webhook.go`.
- `internal/exercise/tracker`: **pure logic only** — `token.go` (`MintToken`), `links.go` (`GenerateLinks`/`rewriteLinks`/`injectPixel`) driven through a fake in-memory `TokenStore`.

**Out of scope (deferred):**
- `internal/exercise/tracker/handler.go` and the other HTTP-endpoint files (`pixel.go`, `redirect.go`, `landing.go`, `credential.go`) — these are `httptest`-shaped HTTP handlers; they belong with the Phase 3 `api` HTTP-handler testing patterns.
- `smtp.go`'s live-network `Send` path — only its nil/config-guard branches are reachable without a live SMTP server; we do **not** stand up a mail server or refactor the injector (see §7 coverage ceiling).
- The real executor step handlers' `go func()` async happy-paths (`handleSendEmail`, `handleAgentTask`) beyond their synchronous entry/guard branches — the state machine is tested with synchronous fake handlers instead (§5.3).
- Any `api`-layer handlers that wrap the exercise store — Phase 3.

## 3. Architecture

Identical harness to Phase 1, so no new infrastructure:

- **One container per package** via `TestMain` + `testutil.MustSharedTestDB()`; `flag.Parse()` before `testing.Short()`; `sharedDB.Cleanup()` on exit.
- **`RunWithPool`** for truncate-isolation between DB tests (the `Store` wraps `*pgxpool.Pool`, so `RunInTx` is unusable — same as Phase 1).
- **`-short` skip guard** (`if testing.Short() { t.Skip(...) }`) on every DB-backed test. Pure-logic tests carry **no** guard, so `go test -short ./internal/exercise/...` still exercises the validator/variables/registry/tracker logic with zero Docker dependency.
- **White-box (in-package) tests** (`package exercise`, `package tracker`). This is load-bearing: it lets the executor tests drive the unexported `advance(ctx, *Execution)` tick function directly and register synchronous fake handlers via the exported `Registry`, making the state machine deterministic without the `PollScheduler` goroutine or handler `go func()` races.

The `TestMain` lives in `store_test.go`; `evidence_test.go` and `executor_test.go` share the same package-level `sharedDB`.

## 4. Approved harness change (one non-test edit)

The shared harness currently applies `db.EnsureSchema` + `db.EnsureContentSchema` but **not** `db.EnsureExerciseSchema`, so the exercise tables (`exercise_plans`, `exercise_executions`, `exercise_step_executions`, `exercise_evidence`, `exercise_events`, `exercise_templates`, `exercise_track_tokens`, `exercise_webhook_calls`) are absent from the test DB.

**Change:** add `db.EnsureExerciseSchema(ctx, pool)` to `testutil.newTestDB` (`orchestrator/internal/testutil/testdb.go`), immediately after the existing `EnsureContentSchema` call, with matching error-wrap. The canonical test DB then carries the full production schema — which Phase 3 (`api`) will also need. This is the only product-adjacent edit; it is committed first, on its own, and verified by the existing `testutil` self-tests plus the new exercise store tests.

The store's only cross-package table dependency is `scenario_runs` (read by `BASRunStatus`), which is already created by `EnsureSchema`.

## 5. Test files

Seven new files. Coverage percentages are directional targets, not CI gates.

### 5.1 `validator_test.go` — pure, no DB

Table-driven tests for `ValidatePlan` and `validateCondition`:
- valid linear + valid diamond DAG → no errors
- missing step id; duplicate step id (early-return path — asserts graph analysis is skipped)
- `depends_on` an unknown step
- cycle (self-loop and 2-node back-edge) → "circular dependency"
- unreachable node (depends on a node inside a cycle)
- condition-syntax matrix: `""`/`always`/`true`/`false`/`never` accepted; `step:<id>:clicked` valid; wrong arity, non-`step` prefix, empty step id, unknown step id, unknown predicate each rejected with the specific message
- negative `timeout_secs`; unparseable `wait_duration`; `${...}` wait_duration skipped (not validated)
- variable refs only checked when `p.Variables` non-empty: undeclared `${X}` flagged; system vars (`ExecutionID`/`Timestamp`/`CurrentUser`) always allowed; duplicate variable name flagged

### 5.2 `variables_test.go` — pure, no DB

- `NewResolver` precedence: system vars present; plan default applied; operator-provided overrides default; `VarTypeRuntime` not pre-populated; `VarTypeSecret` read from env via `t.Setenv(SecretEnv, ...)`; `Set` injects a runtime value visible to later `Sub`
- `Sub`: known ref replaced, unknown ref left literal (`${X}` verbatim)
- `ResolveStepConfig`: substitution inside nested `StepConfig` string fields; **quote-injection safety** — a value containing `"` / `\` / newline stays valid JSON and round-trips into the right field
- `ValidateVars`: required-and-missing → error naming the vars; required secret/runtime skipped; default satisfies required; provided satisfies required
- `ExtractVarRefs`: unique refs across a step config, de-duplicated, empty when none

### 5.3 `registry_test.go` — pure / light concurrency, no DB

- `Registry`: `Register`+`Dispatch` invokes the handler; `Has`; unknown type → "no handler registered" error; re-`Register` overwrites
- `StepHandlerFunc` adapter calls through
- `TriggerRegistry`: `Check` with a registered fn returns its verdict; `Check` with no registration → `(false, nil, nil)`; `Has`
- `PollScheduler`: `Start` fires the tick fn at least once (short interval, wait on a channel/`WaitGroup`, then `Stop`); `Stop` is idempotent (double-`Stop` doesn't panic — exercises the `select` default branch)
- helpers: `mergeMaps` (b wins on key conflict, inputs unmutated); `mintHookToken` returns 32-hex chars; error path by stubbing the package-level `cryptoRandRead` to return an error, restored via `t.Cleanup`

### 5.4 `evidence_test.go` — DB, correctness-critical

- `EvidenceChain.Append` N times → each record has monotonic `seq` (1..N), correct `prev_hash` (empty for seq 1, prior `SHA256` thereafter), and a chained `SHA256` matching `sha256(payloadHash + prevHash)` recomputed in the test
- `Verify` returns nil for an intact chain
- **tamper detection:** mutate one persisted evidence row's payload (direct SQL `UPDATE`), then `Verify` returns an error naming the correct `seq`
- `Record` (the `tracker.Recorder` adapter) appends and returns nil
- `Append` marshal-error path is not reachable with map payloads (documented, not forced)

### 5.5 `store_test.go` — DB, holds `TestMain`

- **Plans:** `CreatePlan` sets id/timestamps; `GetPlan` round-trips steps/variables; `UpdatePlan`; `ListPlans` ordering; `DeletePlan`; `GetPlan` missing → error
- **Executions:** `CreateExecution` (targets/metadata/variables JSON round-trip, `plan_version` defaulted via `max1`); `GetExecution` incl. score JSON; `UpdateExecutionStatus` sets `started_at` for Running and `completed_at` for Completed/Aborted; `UpdateExecutionScore`; `ListExecutions` (default limit 50, DESC); `ListRunningExecutions` returns only running+paused
- **Templates:** `UpsertTemplate` insert then conflict-update; `GetTemplate`; `ListTemplates`; `SeedBuiltinTemplates` idempotent
- **Step executions:** `UpsertStepExecution` insert+update; `SetStepStatus` (+ error message); `SetStepResult` JSON; `ListStepExecutions`; `GetStepExecByStepID`; `stepExecIDForStep`
- **Events:** `RecordEvent` + `ListEvents` shape
- **Track tokens:** `InsertTrackToken` → `GetTrackToken` round-trip → `RecordTokenUse` increments `used_count`/sets `used_at`
- **Evidence counting/duration:** `CountEvidenceByType` map; `CountEvidenceForExec` (explicit types + default `[edr_detected, siem_alerted]` when empty); `SumDurationByType` across seeded evidence timestamps; `hasEvidenceType`
- **Webhook + BAS:** `InsertWebhookCall` → `WebhookCallCount`; `BASRunStatus` with a seeded `scenario_runs` row and the not-found→`("", nil)` contract
- **Error propagation:** closed-pool pattern (`pgxpool.New(...ConnString()); Close()`) across a representative set of read/write methods → error, never panic, never masked not-found

### 5.6 `executor_test.go` — DB + synchronous fake handlers

Constructs an `Executor` with the real `Store`/`EvidenceChain` but a **fake `Registry`** whose handlers complete synchronously (set status/result inline), and stub `AgentDispatchFn`/`TriggerRegistry` as needed. Drives `advance` / lifecycle methods directly:
- `LaunchExecution`: Draft/Scheduled → seeds a pending `StepExecution` per plan step, records "started", flips to Running; a non-Draft/Scheduled execution is a no-op
- `advance` dispatch readiness: a step with unmet `depends_on` is not dispatched; once deps are `done` it dispatches; a step whose `Condition` is false is set `StepSkipped` with a "skipped" event
- `advance` completion: when every step is terminal, score is computed+persisted, "completed" event recorded, status → Completed
- `evalCondition` full predicate matrix: `clicked`/`not_clicked`/`reported` (seed `link_clicked` / `phishing_reported` evidence on the step-exec id), `timeout`/`no_timeout` (via `Result["timed_out"]`), `succeeded`/`failed` (via status), nil-step-exec defaults, unknown predicate/format → default true
- timeouts: generic `wait` past `ScheduledAt` → Completed with `timed_out`; `approval` past `TimeoutSecs` → Completed "timeout"; event-wait (`wait_for_*`) past `TimeoutSecs` → Completed "timeout"
- trigger firing: with a fake trigger returning `triggered=true`, a `StepWaiting` step is completed, payload merged into result, `trigger_fired` evidence appended
- `ApproveStep`: records approval result + evidence + event, sets Completed
- `AbortExecution`: pending/waiting steps → Cancelled, others untouched, status → Aborted, "aborted" event
- `computeScore`: seeded evidence counts produce expected `HumanScore` (click/report rates), `TechnicalScore` flags, and `Overall = (1-clickRate)*60 + detBonus*40`
- the real handlers' **synchronous** guard branches: `handleSendEmail` with nil SMTP / nil email config → Failed; `handleAgentTask` with nil/empty config or nil dispatch → Failed; `handleSendSMS`/`handleNotify` → Completed (stub log-only)
- `webhook.go`: `fireWebhook` against an `httptest.Server` — success (2xx), `>=400` → error, default method/Content-Type applied, bad URL → request error

### 5.7 `tracker/tracker_test.go` — pure, no DB

Uses a fake in-memory `TokenStore` (implements the 3-method interface):
- `MintToken` returns a 32-hex token and calls `InsertTrackToken` with the right args; store-error propagates
- `GenerateLinks`: empty `BaseURL` → body unchanged; `TrackClicks` rewrites `http(s)` hrefs in `<a>` tags to `/x/click/<token>` and leaves relative/`mailto` hrefs alone; `TrackOpens` injects the 1×1 pixel before `</body>` (and appends when no `</body>`); both together; `BaseURL` trailing slash trimmed
- `rewriteLinks`/`injectPixel` edge cases exercised through `GenerateLinks` (href with no closing quote; case-insensitive `HREF`/`</BODY>`)

## 6. Determinism & conventions

- No `time.Sleep` in assertions. Scheduler test waits on a channel signalled by the tick fn, not a sleep.
- Timeout tests set `ScheduledAt`/`StartedAt` to a time in the **past** and call `advance` once — no wall-clock waiting.
- Randomness (`cryptoRandRead`, `crypto/rand` in tracker) is either asserted only on shape (length/hex) or stubbed for error paths and restored via `t.Cleanup`.
- Secrets via `t.Setenv` (auto-restored). Table-driven tests use subtests (`t.Run`) with descriptive names.
- Commit granularity mirrors Phase 1: harness change first, then one commit per test file (or per cohesive pair), pushed immediately after each (standing git-push rule).

## 7. Coverage expectation (stated honestly up front)

Target for the `exercise` package is **90%+**; the orchestration logic the strategy cares about (validator, variables, evidence chain, store, executor state machine) will land at **95%+**. Two areas cap the whole-package number and will **not** be chased by refactoring product code or standing up live network servers (Phase 1 precedent: honest ceiling over padding):

1. **`smtp.go` (~135 lines)** dials SMTP over the network inside a goroutine; only its nil/config guards are reachable in tests.
2. **`go func()` bodies** in `handleSendEmail`/`handleAgentTask` — covered at their synchronous entry/guard level only; the async success path writes results on a background goroutine.

Realistic whole-package ceiling: **high 80s to low 90s**. If `smtp.go` drags the package below ~88%, the final report will name it as the cause rather than inflate the number. `tracker` (pure subset) will report its own percentage; the deferred HTTP handlers there will show as uncovered and are explicitly Phase 3.

## 8. Verification (Task-N-final, same as Phase 1)

- `go test ./internal/exercise/... ./internal/exercise/tracker/... -cover` (both report `ok`, package ≥ target-or-documented-ceiling)
- `go test ./... ` full module green (no regressions from the harness change)
- `go test -short ./internal/exercise/...` passes with no Docker (pure tests run, DB tests skip)
- `gofmt -l internal/exercise`, `go vet ./...`, `staticcheck ./...`, `go build ./...` all clean
- push after every commit

## 9. Out of scope for this spec

- Phases 3–5 (api / integrity+scoring+siem+connector+ticketing / cross-cutting) — each its own spec+plan.
- The tracker HTTP endpoints and `smtp.go` network path — Phase 3 / not pursued (§2, §7).
- Any new fuzz/property/bench harness — Phase 5.
