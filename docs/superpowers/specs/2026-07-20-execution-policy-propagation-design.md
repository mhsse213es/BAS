# Campaign-Wide ExecutionPolicy Propagation — Design

## Context

The MaxPrivilege execution policy (2026-07-20, see `docs/superpowers/plans/2026-07-20-execution-policy-maxprivilege.md`) shipped dispatch-time privilege-tier filtering, but only on one entry point: `RunScenario`. The filtering logic itself — `scenario.PrivilegeExceeds`, the skip-synthesis helper, the `policy_skipped_results` persistence, and the submission-time merge — all lives inside the single shared `dispatchRun` function and is already framework-agnostic. It is **not** duplicated per dispatch path.

What's missing is that only `RunScenario`'s HTTP request struct reads a `MaxPrivilege` value and passes it into `dispatchOpts`. Four other launch points construct `dispatchOpts{}` without ever offering the operator a way to set it, even though every one of them already funnels into the same `dispatchRun`:

| Launch point | File | Notes |
|---|---|---|
| `RunScenario` | `internal/api/handlers.go` | Already wired (flat `maxPrivilege` field) |
| `CreateCampaign` | `internal/api/campaign_handlers.go` | Fans one `dispatchOpts` out across every agent in the campaign |
| `RunAdversaryTemplate` | `internal/api/handlers.go` | One shared `base := dispatchOpts{...}` reused by its BAS / ART / Caldera-adversary branches |
| `RunCalderaAdversary` | `internal/api/handlers.go` | Ad-hoc single-adversary Caldera run |
| Exercise Engine (`agent_task` steps) | `internal/api/handlers.go` (`WithExercise`), `internal/exercise/*` | Structurally different: dispatch happens via a callback (`exercise.AgentDispatchFn`) invoked later by the executor, not inline in an HTTP handler |

This plan closes that gap for all five, and generalizes the wire shape from a flat `maxPrivilege` field into a nested `ExecutionPolicy` object so a second constraint (e.g. `NetworkIsolation`) can be added later without another wire-format change.

## Goal

An operator can set an execution policy once, from any of the five launch surfaces, and have it enforced consistently by the same dispatch-time filtering that already exists — without any dispatch path re-implementing privilege limits on its own.

## Architecture

### Core type

`internal/scenario/types.go`, adjacent to `PrivSpec`/`PrivilegeExceeds`:

```go
// ExecutionPolicy carries operator-set execution constraints for a dispatch
// request. Today it has one field; it's the deliberate extension point for
// future constraints (NetworkIsolation, AllowReboot, etc.) without another
// wire-format change.
type ExecutionPolicy struct {
	MaxPrivilege string `json:"maxPrivilege,omitempty"`
}
```

`dispatchOpts.MaxPrivilege string` (already shipped, already tested) is unchanged — it stays a plain internal field. Every call site unwraps `req.ExecutionPolicy.MaxPrivilege` into it when building `dispatchOpts{}`. `dispatchRun`, `synthesizePolicySkipResult`, and the `SubmitScenarioResult` merge require **no changes** — they already operate purely on `dispatchOpts.MaxPrivilege` / `scenario_runs.policy_skipped_results` and don't care which HTTP handler populated them.

### The four straightforward call sites

Each gets `ExecutionPolicy scenario.ExecutionPolicy \`json:"executionPolicy,omitempty"\`` added to its request struct and wired into its existing `dispatchOpts{}` construction:

1. **`RunScenario`** (`internal/api/handlers.go`) — replaces the flat `MaxPrivilege string \`json:"maxPrivilege"\`` field shipped in the prior plan. No frontend (`wwwroot/`) reads that field yet (confirmed via search), so this is a free rename with zero consumers to migrate.
2. **`CreateCampaign`** (`internal/api/campaign_handlers.go`) — one `opts := dispatchOpts{...}` value is already reused inside the per-agent fan-out loop (`for _, agentID := range req.AgentIDs { h.dispatchRun(ctx, sc, agentID, opts) }`), so one wiring point covers the whole campaign. Also fold `req.ExecutionPolicy` into the `subset` jsonb blob already persisted on the `campaigns` row (which already records `techniques`/`abilities`/`steps`/`checks`) so the policy a campaign ran under is auditable from the campaign record itself, not just inferred from each child run's `policy_skipped_results`.
3. **`RunAdversaryTemplate`** (`internal/api/handlers.go`) — one `base := dispatchOpts{...}` is already shared by all three of its dispatch branches (BAS-native, ART-selective, Caldera-adversary); wiring `base.MaxPrivilege` once covers all three.
4. **`RunCalderaAdversary`** (`internal/api/handlers.go`) — same one-field pattern as `RunScenario`.

### Exercise Engine (the one structurally different path)

Exercise dispatch doesn't happen inline in an HTTP handler — an operator creates an `Execution` (`POST /api/exercises/executions`), then separately launches it by ID (`POST /api/exercises/executions/{id}/launch`, no body). The executor later fires `agent_task` steps asynchronously, each invoking a callback:

```go
// current
type AgentDispatchFn func(agentID, scenarioID, techniqueID string) (runID string, err error)
```

Because `LaunchExerciseExecution` takes no body, the policy must be set at **creation** time and persisted on the `Execution`, then read back by the executor when a step actually fires:

- `exercise.Execution` (`internal/exercise/types.go`) gains `ExecutionPolicy scenario.ExecutionPolicy \`json:"execution_policy,omitempty"\``.
- New `execution_policy_json` column on `exercise_executions`, following the table's existing per-field-jsonb-column pattern (`targets_json`, `variables_json`, `metadata_json`) rather than overloading the untyped `metadata_json` map — the executor needs typed access at read time, not just an audit blob.
- `CreateExerciseExecution`'s request struct (`internal/api/exercise_handlers.go`) gains `ExecutionPolicy scenario.ExecutionPolicy \`json:"execution_policy,omitempty"\``, copied onto the `exercise.Execution{}` before `CreateExecution`. (Note: `execution_policy` is snake_case here, `executionPolicy` is camelCase on the other four request structs — each matches its own package's existing JSON tag convention: `internal/exercise`'s wire types are already snake_case throughout, e.g. `plan_id`, `agent_id`; `internal/api`'s non-exercise handlers are already camelCase throughout, e.g. `confirmLive`, `agentId`. This is a deliberate match to existing local convention, not an inconsistency.)
- `exercise.AgentDispatchFn`'s signature changes to `func(agentID, scenarioID, techniqueID string, policy scenario.ExecutionPolicy) (runID string, err error)`. `internal/exercise` gains an import of `internal/scenario` for the type — confirmed no cycle (`internal/scenario` does not import `internal/exercise`).
- `executor.go`'s dispatch call site passes the in-flight Execution's `ExecutionPolicy` through the new parameter.
- `WithExercise`'s closure (`internal/api/handlers.go`) accepts the new `policy` argument and sets `dispatchOpts.MaxPrivilege: policy.MaxPrivilege` — landing at the exact same place every other path lands.

### Data flow

For the four straightforward paths:

```
HTTP request body (executionPolicy: {maxPrivilege})
  → typed request struct
  → dispatchOpts.MaxPrivilege
  → dispatchRun's existing filter (unchanged)
  → synthesizePolicySkipResult / policy_skipped_results (unchanged)
  → SubmitScenarioResult merge (unchanged)
```

Exercise adds one hop at the front, since launch is decoupled from creation:

```
HTTP request body (executionPolicy, at execution-CREATE time)
  → exercise.Execution.ExecutionPolicy (persisted)
  → [later, async] executor fires an agent_task step
  → AgentDispatchFn(..., policy)
  → dispatchOpts.MaxPrivilege
  → (same as above from here)
```

## Error handling / edge cases

- **No new validation.** An unrecognized `MaxPrivilege` value behaves exactly as it does today for `RunScenario` — `PrivilegeExceeds` treats unknown tiers as rank 0 (lowest), so it never filters anything out. This plan does not add tier-value validation anywhere; that's an explicit, unchanged gap, not scope creep.
- **Exercise `wait_for_agent` steps degrade safely.** If a policy filters out every step of a dispatched run, the prior plan's immediate-completion behavior already returns a valid, non-empty `runID` with `status=completed` synchronously. A downstream `wait_for_agent` step polling that run's status sees it complete immediately — no special-case handling needed in the executor.
- **Backward compatibility.** `RunScenario`'s flat `maxPrivilege` field is renamed, not deprecated-and-kept, since it has zero consumers (shipped hours before this design, no frontend reads it).

## Non-goals (explicitly deferred)

- Reporting: breaking out `Skipped` results by `SkipReason` in the Execution Summary, and executive-wording narrative ("N techniques were intentionally excluded...") — separate follow-up.
- Coverage math: exposing both "Scenario Coverage" (executed/total) and "Eligible Coverage" (executed/eligible) — separate follow-up; requires persisting a pre-filter step count that doesn't exist today.
- Any new `ExecutionPolicy` fields beyond `MaxPrivilege` (`NetworkIsolation`, `AllowReboot`, etc.) — the type is deliberately built as an extension point but only `MaxPrivilege` is populated in this plan.
- Tier-value validation (rejecting unrecognized `MaxPrivilege` strings) at any request layer.

## Testing approach

Each of the five call sites gets a container-backed integration test following the exact pattern established by `TestRunScenarioIntegration_MaxPrivilegeFiltersStep` (mixed eligible/filtered steps, assert only eligible steps reach the fake agent, assert `policy_skipped_results` is populated correctly) and `TestRunScenarioIntegration_MaxPrivilegeAllFilteredCompletesImmediately` (all-filtered case completes without an agent round-trip). For Exercise specifically, an additional test exercises the full async path: create an `Execution` with an `ExecutionPolicy`, launch it, and confirm the resulting BAS run was policy-filtered — proving the policy survives the create → persist → launch → executor → callback hop.
