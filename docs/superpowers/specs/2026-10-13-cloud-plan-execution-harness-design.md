# Cloud Plan Execution Harness — Design

**Date:** 2026-10-13
**New file:** `orchestrator/internal/cloudrun/executor.go` (package `cloudrun`)
**Modified file:** `orchestrator/internal/db/cloudrun_store_test.go` (one additive test, no production code change)

## Context and motivation

This is sub-project #2 of the 5-part decomposition described in `docs/superpowers/specs/2026-10-13-cloud-run-data-model-design.md`'s Context section. Sub-project #1 built the `cloud_runs` persistence layer (`cloudrun.CloudRun`, `db.InsertCloudRun`/`GetCloudRun`/`UpdateCloudRunStatus`/`ListCloudRuns`) but deliberately left "what actually produces a result" entirely out of scope.

Grounding this sub-project in the real `cloudgraph` code surfaced that "the execution harness" as originally named is itself too broad for one increment: `cloudgraph` has four structurally different entry points (`CloudPlan`, `CloudReachable`, `ExecuteCloudRansomwareScenario`, `ComposeHybridPath`) with four different result shapes, plus `RunMultiAccount` as a generic multi-account fan-out wrapper. Building one harness to cover all of them now would repeat the mistake sub-project #1 avoided by deferring result-shape. It also surfaced a real, undecided mismatch: `CloudChildRun.Status` (used by `RunMultiAccount`) includes `"skipped"`, a value `cloud_runs.status`'s CHECK constraint does not allow — multi-account wiring will need to resolve this, but not here.

This spec narrows sub-project #2 to the smallest meaningful slice: wire exactly **`CloudPlan`**, for a single account, against caller-supplied (test-fixture, in this increment) graph data, end-to-end into `cloud_runs`. `CloudReachable`, `ExecuteCloudRansomwareScenario`, `ComposeHybridPath`, multi-account fan-out, and real cloud discovery are all explicitly deferred to later increments. No HTTP/API surface is built here — that is sub-project #3's job; this increment's entry point is a plain Go function.

## Scope

- **In scope:** `cloudrun.ExecuteCloudPlanRun`, its request type, the provider→evaluator mapping, result serialization, and the full test suite below.
- **Out of scope (explicitly deferred):**
  - `CloudReachable`, `ExecuteCloudRansomwareScenario`, `ComposeHybridPath` — different result shapes; each is its own future increment once this pattern proves out.
  - Multi-account fan-out (`RunMultiAccount`) and the `CloudChildRun.Status` `"skipped"` / `cloud_runs.status` CHECK-constraint mismatch it would surface.
  - Real cloud discovery (`AzureDiscoveryClient` et al.) — this increment's tests use hand-built fixture edges only; no live cloud calls, no cloud mutations, and the harness never claims a simulated path was observed in reality (`CloudPlan`'s own `PathState` vocabulary — `PolicySupported` vs. `Observed` — already keeps this distinction; the harness adds nothing on top of it).
  - Any HTTP endpoint, router change, or API surface — sub-project #3's job entirely.
  - Retry semantics for a run stuck at `StatusRunning` after a failed terminal update — no caller needs this yet.

## Function signature & input shape

New file `orchestrator/internal/cloudrun/executor.go`, package `cloudrun` (alongside sub-project #1's `types.go`):

```go
package cloudrun

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/db"
)

// CloudPlanRunRequest is the input to ExecuteCloudPlanRun. The caller
// supplies the graph data directly -- this package holds no embedded
// fixtures; fixtures exist only in this package's own tests.
type CloudPlanRunRequest struct {
	ScenarioID  string
	Account     cloudgraph.AccountScope
	Edges       []*cloudgraph.CloudPermission
	Held        []string
	Target      string
	MaxHops     int
	InitiatedBy string
}

// ExecuteCloudPlanRun runs cloudgraph.CloudPlan for one account and records
// the outcome as a cloud_runs row. It is a plain Go function, not an HTTP
// handler -- sub-project #3 decides how (or whether) this is exposed over
// the API.
func ExecuteCloudPlanRun(ctx context.Context, pool *pgxpool.Pool, req CloudPlanRunRequest) (*CloudRun, error)
```

`req.Account.Provider` ("aws"/"azure"/"gcp") selects the evaluator internally:

```go
func evaluatorFor(provider string) (cloudgraph.AuthorizationEvaluator, error) {
	switch provider {
	case "aws":
		return &cloudgraph.AWSEvaluator{}, nil
	case "azure":
		return &cloudgraph.AzureEvaluator{}, nil
	case "gcp":
		return &cloudgraph.GCPEvaluator{}, nil
	default:
		return nil, fmt.Errorf("cloudrun: unknown provider %q", provider)
	}
}
```

All three evaluators are zero-arg structs with pointer-receiver `EvaluatePermission` methods (confirmed from `aws_evaluator.go`/`azure_evaluator.go`/`gcp_evaluator.go` — `type AWSEvaluator struct{}` with `func (e *AWSEvaluator) EvaluatePermission(...)` etc.), so `evaluatorFor` returns a pointer to a freshly constructed zero-value struct; no configuration is needed. This keeps evaluator selection internal rather than pushing it onto the caller, consistent with `cloud_runs.provider` already being the column of record for which one was used.

`InsertCloudRun` (sub-project #1) requires the caller to pre-populate `run.ID` — it does not rely on the column's `DEFAULT gen_random_uuid()`. `ExecuteCloudPlanRun` generates its own ID the same way `internal/api/handlers.go`'s existing `newID()` does (that function is unexported to its own package, so this is a small, duplicated one-liner, not a shared import):

```go
func newRunID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
```

## Execution flow & status mapping

```
1. Build a CloudRun{ID: newRunID(), ScenarioID: req.ScenarioID, Provider: req.Account.Provider,
   AccountID: req.Account.AccountID, TenantID: req.Account.TenantID, Region: req.Account.Region,
   Status: StatusRunning, InitiatedBy: req.InitiatedBy, StartedAt: time.Now().UTC()}.
2. db.InsertCloudRun(ctx, pool, run) -- on error, return it directly. Nothing to update; no row exists.
3. evaluator, err := evaluatorFor(req.Account.Provider) -- on error, the row already exists
   (step 2 succeeded), so this is NOT left silently stuck: call
   db.UpdateCloudRunStatus(ctx, pool, run.ID, StatusFailed, nil, err.Error()) so the persisted
   row honestly reflects "this could not run," then return the original error to the caller.
   An unrecognized provider is a caller bug, not a cloud-side outcome -- but the row must still
   say so, not sit at StatusRunning forever with nothing but a returned Go error no one is
   necessarily watching.
4. path, ok := cloudgraph.CloudPlan(req.Edges, req.Held, req.Target, evaluator,
   &cloudgraph.RequestContext{}, req.MaxHops).
5. Marshal path to JSON (path may be nil when ok=false -- json.Marshal(nil) produces "null",
   which InsertCloudRun/UpdateCloudRunStatus already handle as a nil-equivalent jsonb value,
   proven by sub-project #1's TestInsertCloudRun_NilResultRoundTrips). A marshal failure is
   handled the same way as step 3's error: mark the row StatusFailed with the error recorded,
   then return the error (see "Result serialization" below for why this path has no test).
6. status := StatusCompleted if ok, else StatusPartial. CloudPlan has no error return -- ok=false
   is a legitimate negative result ("no path could be confirmed from available evidence," per
   cloud_reachability.go's own doc comment), never StatusFailed.
7. db.UpdateCloudRunStatus(ctx, pool, run.ID, status, resultJSON, "") -- on error, return it
   directly. The row is left at StatusRunning: honest ("we don't know if the result got
   recorded") rather than a second write that could itself fail.
8. On success, db.GetCloudRun(ctx, pool, run.ID) and return that -- the caller sees exactly what
   was persisted, not just what's in memory.
```

`StatusFailed` is reachable only via step 3's or step 5's error path (an unrecognized provider, or -- defensively -- a marshal failure) -- never from `CloudPlan`'s own output, and never from step 2 (no row exists yet to mark failed) or step 7 (a second write there could itself fail, so the row is left at `StatusRunning` instead). This is the harness's central honesty guarantee: it never adds confidence `CloudPlan` didn't produce, and never collapses "policy-supported" into "observed" -- both remain exactly as distinct as `cloudgraph.PathState` already keeps them.

## Result serialization

`CloudPath{Hops []*CloudHop, OverallState PathState}` / `CloudHop{Edge *CloudPermission, Result *EvaluationResult}` are marshaled with plain `json.Marshal` -- no custom envelope, no field renaming, default Go JSON encoding (exported field names verbatim).

A true marshal failure is not realistically constructible for this struct shape (no channels, functions, or cycles in any of `CloudPath`'s fields or their transitive fields) without modifying `cloudgraph`'s types, which is out of scope. The implementation still checks the `json.Marshal` error and treats it identically to a terminal-update failure (return the error; attempt `StatusFailed` the same way as the `evaluatorFor` error path) -- the code handles it, but no test manufactures it, since doing so would require an artificial, unrealistic fixture.

## Error handling summary

| Failure point | Row state after | Caller sees |
|---|---|---|
| `InsertCloudRun` fails | no row exists | the error |
| `evaluatorFor` rejects an unknown provider | `StatusFailed`, `Error` set | the error |
| `json.Marshal` fails (unrealistic, handled defensively) | `StatusFailed`, `Error` set | the error |
| Terminal `UpdateCloudRunStatus` fails | `StatusRunning` (unchanged) | the error |
| `CloudPlan` returns `ok=false` | `StatusPartial` | `nil` error, a `*CloudRun` |
| `CloudPlan` returns `ok=true` | `StatusCompleted` | `nil` error, a `*CloudRun` |

## Testing

New file `orchestrator/internal/cloudrun/executor_test.go`, using hand-built fixture edges (not borrowed from `cloudgraph`'s own test file, to keep this package's tests self-contained) against the real Postgres harness (same `sharedDB`/`TestMain` pattern as `internal/db`'s tests -- this package's test binary needs its own `TestMain`/`sharedDB` since `cloudrun` is a different package from `db`).

1. **Valid path found** -- fixture edges form a confirmable chain; assert `StatusCompleted`, and that `Result` deserializes to a `CloudPath` with the expected hops and `OverallState`.
2. **No path found** -- fixture edges never reach the target within `MaxHops`; assert `StatusPartial` (not `StatusFailed`), and that `Result` is still recorded (whatever `CloudPlan` returned, including a `null`/nil case).
3. **Blocked/Unknown hops present but a path is still found via a different edge** -- proves the persisted result reflects only the viable hops `CloudPlan` actually used, never a non-advancing edge.
4. **`MaxHops` is plumbed through, not hardcoded** -- identical fixture edges with `MaxHops=1` yield `StatusPartial`; with `MaxHops=5` yield `StatusCompleted`. (Hop-limit/cycle *correctness* itself is already proven at the `cloudgraph` layer by the intra-cloud multi-hop reachability work; this test only proves the harness forwards the caller's value instead of ignoring it.)
5. **Insert failure propagates as a real error, not a false success** -- a pre-canceled `context.Context` makes the initial `InsertCloudRun` fail; assert `ExecuteCloudPlanRun` returns a non-nil error and no row is created.
6. **Unknown provider produces `StatusFailed`, not a silent stuck `StatusRunning`** -- `req.Account.Provider = "unknown"` triggers the `evaluatorFor` error path; assert the persisted row is `StatusFailed` with `Error` set, and the function returns a non-nil error.

One test originally planned differently: isolating "the row is inserted successfully, then *specifically* the terminal update call fails" through the full `ExecuteCloudPlanRun` wrapper has no clean, deterministic trigger -- there is no dependency-injection seam in this design (by choice: adding one solely to manufacture this one scenario would be over-engineering for this increment), and a timing-based trick (racing a context cancellation against the DB calls) would be flaky. Instead, that exact code path -- "a DB error from `UpdateCloudRunStatus` is returned as-is, not swallowed" -- is covered by a new, additive test in the *already-shipped* `orchestrator/internal/db/cloudrun_store_test.go` (no production code change there, just one more test case): calling `db.UpdateCloudRunStatus` directly with a pre-canceled context and asserting the wrapped error is non-nil. `ExecuteCloudPlanRun`'s own step 7 does nothing beyond `return err` on that call, which is verifiable by reading the four-line step, not by an integration test.
