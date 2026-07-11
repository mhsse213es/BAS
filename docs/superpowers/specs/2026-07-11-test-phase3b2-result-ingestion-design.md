# Phase 3b.2 — Result Ingestion Test Generation: Design

**Status:** Approved
**Package:** `orchestrator/internal/api`
**Handlers in scope:** `SubmitScenarioResult`, `ListScenarioRuns`, `CancelRun`

## Context

This is the second sub-phase of Phase 3b (Scenario & Run Lifecycle), per the
user's explicit risk-based ordering: 3b.1 Run Dispatch (done) → **3b.2 Result
Ingestion (this phase)** → 3b.3 Scenario Authoring (last). The ordering
reasoning: a bug in dispatch or result ingestion can produce wrong security
conclusions (silently-failed campaigns, incorrect scoring), which is a more
severe failure mode than a bug in scenario CRUD.

`SubmitScenarioResult` (handlers.go:1521-1790, ~270 lines) is the endpoint
agents POST results to. It updates the run row, computes score and hygiene
score, then fans out into five downstream subsystems: findings, variant
findings, campaign/variant-technique summary, compliance snapshot refresh,
and SIEM auto-correlation. Three of those fan-outs run synchronously before
the HTTP response is written; three run in background goroutines with no
client-visible contract.

`ListScenarioRuns` (handlers.go:1793-1853) is the primary read model for run
history. `CancelRun` (handlers.go:1859-1891) is a small state machine that
sends a WS cancel command to the agent, or marks the run `partial` if the
agent is unreachable.

## Scope Boundary

**In scope — SubmitScenarioResult's own responsibilities:**
- MAC/tamper-detection auth gate
- Request payload validation
- Idempotent REPLACE semantics (no status guard; retries and late
  submissions converge, per `project_run_reconciliation` memory)
- Status transitions (`completed` / `partial`)
- Score computation *orchestration* (when it fires, what `prevScore` it
  picks up) — not `ComputeScore`'s internal correctness, which already has
  dedicated coverage in `internal/models/score_test.go`
- Hygiene score computation (computed entirely within this handler, no
  external dependency — in scope for correctness, not just orchestration)
- The three **synchronous** fan-outs' *trigger conditions* (fired vs.
  skipped, e.g. findings-healing skipped when `Partial=true`) — never their
  internal correctness
- WebSocket broadcast contract (`BroadcastBrowsers` message shape)

**Explicitly out of scope:**
- The three **asynchronous** fan-outs (compliance snapshot refresh, SIEM
  auto-correlate, campaign/variant-technique summary) — fire-and-forget
  goroutines with no synchronous contract. No invocation testing, no
  polling, no sleeping. Each gets its own dedicated phase later (compliance,
  SIEM, campaign summary are all separate items on the 2026H2 platform
  roadmap).
- Internal correctness of `upsertFindingsForRun`, `upsertVariantFindingsForRun`,
  `persistVariantResults` — verified only via observable DB side effects
  (a row appeared or didn't), never their derivation logic.
- `scenario.Interpret`'s internal correctness (separate, already-scoped
  logic) — only that `SubmitScenarioResult` picks the right interpretation
  path (`Checks` vs `Results`) and falls back correctly on an unknown
  `TaskID`.
- `CancelRun`'s `h.auditLog` call — fire-and-forget goroutine, same
  async-fan-out exclusion as `SubmitScenarioResult`'s three background
  fan-outs; audit logging's own correctness is 3a's territory.

## File Structure

| File | Responsibility |
|---|---|
| `result_mac_test.go` | Dedicated MAC/tamper-detection security-boundary matrix |
| `submit_scenario_result_test.go` | Payload validation, idempotent REPLACE, status transitions, score/hygiene orchestration, sync-fan-out trigger conditions, WS broadcast contract |
| `list_scenario_runs_test.go` | Filter combinations, ordering/LIMIT, projection correctness, graceful degradation |
| `cancel_run_test.go` | Full run-status state machine, online/offline agent branches, WS command contract |
| `result_ingestion_helpers_test.go` | Infrastructure only: MAC-signing helper, request/body builders, fake-browser WS helper. No assertions or product-behavior logic — if a helper starts encoding expected product behavior, that logic belongs in the test file instead. |

### Fake-browser WS helper (`result_ingestion_helpers_test.go`)

Mirrors the fake-agent helper built in 3b.1 (`run_dispatch_helpers_test.go`),
dialing `hub.ServeBrowserWS` instead of `hub.ServeAgentWS`. Treated as
reusable WS test infrastructure, not tied to result ingestion specifically —
future phases touching browser-facing broadcast (reporting, notifications)
can reuse it.

```go
type fakeBrowser struct {
    conn *websocket.Conn
    msgs chan wsEnvelope
    done chan struct{}
}

func startFakeBrowser(t *testing.T, hub *ws.Hub) *fakeBrowser
func (b *fakeBrowser) WaitForMessage(t *testing.T, timeout time.Duration) wsEnvelope
func (b *fakeBrowser) Disconnect(t *testing.T)
func (b *fakeBrowser) Reconnect(t *testing.T, hub *ws.Hub)
```

Reuses the existing `wsEnvelope` type from `run_dispatch_helpers_test.go`
(same wire shape, `Data json.RawMessage` for two-stage decoding). Unlike the
agent handshake (`wsProbeMessage`), a browser connection has no analogous
probe message since `ServeBrowserWS` never sends unsolicited traffic to a
freshly-connected browser — connection readiness is confirmed by polling
`len(hub.browsers)` indirectly via a `BroadcastBrowsers` round-trip in the
helper's own self-test, OR (preferred, simpler) by giving the hub a small
test-only accessor. Concretely: since `hub.browsers` is unexported and
`internal/ws` and `internal/api` are different packages, the helper cannot
poll hub internals directly. Instead `startFakeBrowser` will poll by sending
a zero-cost `hub.BroadcastBrowsers` probe message from the *test* immediately
after dialing and asserting it arrives within a short bounded retry loop
(same bounded-poll pattern already proven acceptable for connection-readiness
checks, distinct from the disallowed "poll for eventual business-logic side
effects" pattern) before the test proceeds to the real assertions.

## MAC Signing Helper

```go
func signResultMAC(secret string, body []byte) string
```
Wraps `hmac.New(sha256.New, []byte(secret))` — mirrors
`integrity.VerifyResultMAC`'s construction exactly so tests build valid MACs
without importing test-only knowledge of the production implementation
beyond what's already public API shape (HMAC-SHA256 over raw body bytes,
hex-encoded).

## Test Matrices

### `result_mac_test.go`

1. `TestSubmitScenarioResult_MAC_Valid` — correct MAC → accepted
2. `TestSubmitScenarioResult_MAC_MissingHeader` → 401, no DB mutation
3. `TestSubmitScenarioResult_MAC_Empty` → 401
4. `TestSubmitScenarioResult_MAC_Wrong` → 401
5. `TestSubmitScenarioResult_MAC_MalformedHex` → 401
6. `TestSubmitScenarioResult_MAC_WrongSecret` → 401
7. `TestSubmitScenarioResult_MAC_TamperedBody` — MAC signed for body A, submitted with body B → 401
8. `TestSubmitScenarioResult_MAC_ByteExact` — same JSON, different key order/whitespace, MAC from the original bytes → rejected (boundary is raw bytes, not parsed JSON)
9. `TestSubmitScenarioResult_MAC_EmptySecretBypass` — `agentSecret=""`, no header → accepted (documented backward-compat bypass)
10. `TestSubmitScenarioResult_MAC_RejectionPrecedesMutation` — seed a `running` run, submit with a bad MAC, assert the row is completely unchanged afterward

Replay is intentionally not tested as a rejection case — REPLACE semantics
make duplicate valid-MAC submissions idempotent by design. Documented via a
comment in this file pointing at the idempotency tests in
`submit_scenario_result_test.go`, so a future reader doesn't mistake the
omission for a gap.

### `submit_scenario_result_test.go`

**Payload validation:**
1. `TestSubmitScenarioResult_MissingRunID` → 400
2. `TestSubmitScenarioResult_MalformedJSON` → 400
3. `TestSubmitScenarioResult_UnknownRunID` — `UPDATE ... WHERE id = $3` against a nonexistent run affects 0 rows; pgx's `Exec` does not surface a "no rows affected" error, so `dbErr` stays nil and the handler proceeds through the rest of the function (score/hygiene compute against an empty result set, sync fan-outs no-op internally since their own row lookups miss, WS broadcast still fires with the submitted data) and returns **200 OK**. This test locks down that no-op-accept behavior explicitly, so a future change to add existence-checking is a deliberate, visible diff against this test rather than an unnoticed behavior change.

**Idempotent REPLACE:**
4. `TestSubmitScenarioResult_REPLACENotAppend` — submit twice with different result sets, final `results` matches only the second payload
5. `TestSubmitScenarioResult_LateSubmissionHealsPartialToCompleted` — run already `partial`, a late valid submission flips it back to `completed`
6. `TestSubmitScenarioResult_PartialFlag_SetsPartialStatus` — `raw.Partial=true` → status `partial`, `completed_at` still set

**Results vs. Checks branch:**
7. `TestSubmitScenarioResult_ResultsInterpretedViaSteps`
8. `TestSubmitScenarioResult_ChecksTakePriorityOverResults` — both populated, `Checks` wins
9. `TestSubmitScenarioResult_UnknownTaskIDFallsBackToCustom`

**Score orchestration:**
10. `TestSubmitScenarioResult_ScoreComputedWhenResultsNonEmpty`
11. `TestSubmitScenarioResult_ScoreSkippedWhenResultsEmpty`
12. `TestSubmitScenarioResult_PrevScorePickedFromSameScenarioAgent`
13. `TestSubmitScenarioResult_PrevScoreExcludesOtherAgentsAndScenarios`

**Hygiene score:**
14. `TestSubmitScenarioResult_HygieneScore_NoCleanableSteps_Is100`
15. `TestSubmitScenarioResult_HygieneScore_AllReverted_Is100`
16. `TestSubmitScenarioResult_HygieneScore_PartialLeaked_Proportional`

**Sync fan-out trigger conditions:**
17. `TestSubmitScenarioResult_FindingsFireOnCompletedRun`
18. `TestSubmitScenarioResult_FindingsSkippedOnPartialRun`
19. `TestSubmitScenarioResult_VariantFanOutsFireForVariantRun`
20. `TestSubmitScenarioResult_VariantFanOutsNoOpForNonVariantRun`

**WS broadcast contract:**
21. `TestSubmitScenarioResult_BroadcastsToConnectedBrowser` — fake browser receives one `MsgScenarioResult` with correct fields
22. `TestSubmitScenarioResult_NoBrowsersConnected_StillReturns200`

### `list_scenario_runs_test.go`

1. `TestListScenarioRuns_NoFilters`
2. `TestListScenarioRuns_FilterByAgentID`
3. `TestListScenarioRuns_FilterByScenarioID`
4. `TestListScenarioRuns_FilterByBoth`
5. `TestListScenarioRuns_FilterMatchesNeither_ReturnsEmptyArray` (not `null`)
6. `TestListScenarioRuns_OrderedByStartedAtDesc`
7. `TestListScenarioRuns_LimitOneHundred`
8. `TestListScenarioRuns_DetectedTechsProjection`
9. `TestListScenarioRuns_ProgressProjection`
10. `TestListScenarioRuns_ScoreProjection` (including `NULL` score)
11. `TestListScenarioRuns_MalformedResultsJSON_DegradesGracefully`
12. `TestListScenarioRuns_DBError` — closed pool → 500

### `cancel_run_test.go`

1. `TestCancelRun_NotFound` → 404
2. `TestCancelRun_TerminalStatus` — table-driven: `completed`, `partial`, `failed` → each 409, row unchanged
3. `TestCancelRun_Running_AgentOnline` — fake agent receives `MsgCommandCancel{runId}`; response `{runId, status:"cancelling"}`; DB row still `running` after the call
4. `TestCancelRun_Running_AgentOffline` — DB flips to `partial` with `completed_at` set; response `{runId, status:"partial"}`
Note: `h.auditLog` is fire-and-forget (dispatches its DB insert in a
goroutine — see `audit.go:39`), so it falls under the same async-fan-out
exclusion already agreed for `SubmitScenarioResult`. No test asserts on the
audit-log row for `CancelRun`; audit logging's own correctness is 3a's
territory.

## Verification

Same rigor as 3b.1: `go build ./...`, full `go test ./...`, `go vet ./...`,
`staticcheck ./...`, gofmt-blob check on all new/changed files, `-count=10`
on `internal/api`, coverage review of the four in-scope symbols
(`SubmitScenarioResult`, `ListScenarioRuns`, `CancelRun`, plus
`signResultMAC`/fake-browser helper self-tests), scratch coverage file
removed, working tree clean before commit.
