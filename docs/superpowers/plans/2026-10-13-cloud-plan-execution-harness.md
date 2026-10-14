# CloudPlan Execution Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the one Go function that actually runs a cloud reachability search (`cloudgraph.CloudPlan`) for one account against caller-supplied fixture data, and records the outcome into the `cloud_runs` table sub-project #1 built.

**Architecture:** One new file, `orchestrator/internal/cloudrun/executor.go`, adding `ExecuteCloudPlanRun` to the `cloudrun` package alongside sub-project #1's `types.go`. It validates the request, calls `cloudgraph.CloudPlan` with an evaluator selected from `req.Account.Provider`, and maps the result to `Completed`/`Partial`/`Failed` via a small, separately-tested pure function. No HTTP surface, no real cloud discovery — both explicitly deferred.

**Tech Stack:** Go, `cloudgraph` (already shipped), `cloudrun`/`db` packages (already shipped, sub-project #1), Postgres via `pgx/v5`/`pgxpool`, `testcontainers-go` for tests (needs Docker running).

**Spec:** `docs/superpowers/specs/2026-10-13-cloud-plan-execution-harness-design.md` (including its 2026-10-13 same-day Amendment — read both; the amendment reverses part of the original design and is binding).

## Global Constraints

- TDD throughout: every test is written, watched fail (for the stated reason), then made to pass.
- Narrow verification after each step; one full `go test ./internal/cloudrun/... ./internal/db/...` gate at the end of the last task.
- Minimal changes only: exactly 3 new files (`orchestrator/internal/cloudrun/executor.go`, `orchestrator/internal/cloudrun/executor_test.go`, `orchestrator/internal/cloudrun/executor_internal_test.go`) plus one strengthened test in the already-shipped `orchestrator/internal/db/cloudrun_store_test.go`. No change to `cloudrun/types.go` or `db/cloudrun_store.go`'s existing production code.
- No subagents needed except the final whole-plan review; Sonnet only, never Opus.
- Git push immediately after every commit. Before each push, `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, then confirm `go build ./internal/cloudgraph/... && go test ./internal/cloudgraph/...` still pass before pushing.
- `executor_test.go` is package `cloudrun_test` (external, black-box) and declares the package's **only** `TestMain`/`sharedDB` — `executor_internal_test.go` (package `cloudrun`, same directory) compiles into the same test binary and does not need its own, since its tests are pure and never touch `sharedDB`.
- **Test boundary (binding from the spec):** `AWSEvaluator`/`AzureEvaluator`/`GCPEvaluator` are hand-coded string-matching logic with zero network calls or credentials. Every path-behavior test uses them (or a hand-built `EvaluationResult` for the `Partial` case) against hand-built fixture edges. Only `cloud_runs` persistence touches anything external (the Postgres testcontainer). No test in this plan may call a live cloud API.

## Review Focus

- **Status semantics are reversed from the original spec draft** — `CloudPlan`'s `ok=false` (no path confirmed) is `StatusCompleted`, not `StatusPartial`. Every test asserting on this must use the corrected expectation; a test still expecting `StatusPartial` for a no-path result is testing the wrong, already-rejected design.
- `StatusPartial`'s trigger condition (`EvaluationResult.UnresolvedConds` non-empty) is **unreachable through any of today's three real evaluators** — this must be tested as a standalone unit test of the extracted mapping function with a hand-built `EvaluationResult`, not as an integration test through `ExecuteCloudPlanRun`, since no real evaluator can produce it.
- The provider/edge-mismatch rejection (`validateEdgesMatchProvider`) must be proven with a real mismatched fixture (an edge whose `AccountScope.Provider` differs from `req.Account.Provider`), and the persisted row's `Status`/`Error` must be checked, not just the returned Go error.
- `MaxHops` plumbing can no longer be proven by comparing `Status` between a 1-hop and a 5-hop budget (both are now `StatusCompleted`) — it must be proven by whether a path was actually found (`Result` populated vs. literally `"null"`).
- A persistence (update) failure must be proven to leave the row's `Status` **unchanged**, not merely to return a non-nil error — a test that only checks the error return could pass even if the row were silently corrupted.

---

## File Structure

- **Create** `orchestrator/internal/cloudrun/executor.go` — `CloudPlanRunRequest`, `evaluatorFor`, `validateEdgesMatchProvider`, `newRunID`, `statusForPath`, `ExecuteCloudPlanRun`.
- **Create** `orchestrator/internal/cloudrun/executor_test.go` — `TestMain`/`sharedDB`, fixture helpers, integration tests.
- **Create** `orchestrator/internal/cloudrun/executor_internal_test.go` — pure unit tests of `statusForPath` (package `cloudrun`, needs access to the unexported function).
- **Modify** `orchestrator/internal/db/cloudrun_store_test.go` — strengthen one existing test to also assert the row's status is unchanged after a failed update.

## Task 1: Scaffolding + core `ExecuteCloudPlanRun` (valid path, no path, insert failure)

**Files:**
- Create: `orchestrator/internal/cloudrun/executor.go`
- Create: `orchestrator/internal/cloudrun/executor_test.go`

**Interfaces:**
- Consumes: `cloudrun.CloudRun`/`Status` (sub-project #1), `db.InsertCloudRun`/`GetCloudRun`/`UpdateCloudRunStatus` (sub-project #1), `cloudgraph.AccountScope`/`CloudPermission`/`CloudIdentity`/`CloudResource`/`RequestContext`/`AuthorizationEvaluator`/`AWSEvaluator`/`AzureEvaluator`/`GCPEvaluator`/`CloudPlan`/`CloudPath`/`CloudHop`/`EvaluationResult`/`PathState` constants (already shipped, `cloudgraph` package).
- Produces: `cloudrun.CloudPlanRunRequest{ScenarioID, Account, Edges, Held, Target, MaxHops, InitiatedBy}`, `cloudrun.ExecuteCloudPlanRun(ctx, pool, req) (*CloudRun, error)`, and the unexported `statusForPath`/`validateEdgesMatchProvider`/`evaluatorFor` that Tasks 2-4 consume directly (Task 4) or indirectly (Tasks 2-3, via `ExecuteCloudPlanRun`).

- [ ] **Step 1: Write the test scaffolding and the first three failing tests**

Create `orchestrator/internal/cloudrun/executor_test.go`:

```go
package cloudrun_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudrun"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func identity(canonicalID, kind string) *cloudgraph.CloudIdentity {
	return &cloudgraph.CloudIdentity{CanonicalID: canonicalID, Kind: kind}
}

func resource(canonicalID, kind string) *cloudgraph.CloudResource {
	return &cloudgraph.CloudResource{CanonicalID: canonicalID, Kind: kind}
}

// allowEdge returns a CloudPermission that AWSEvaluator evaluates to PolicySupported:
// an identity-policy with an explicit Allow statement for action, and SourceType
// "identity-policy" (not "role-trust", so principalMatches short-circuits to true).
func allowEdge(source *cloudgraph.CloudIdentity, target *cloudgraph.CloudResource, action string) *cloudgraph.CloudPermission {
	return &cloudgraph.CloudPermission{
		Source: source, Target: target, Action: action, SourceType: "identity-policy",
		Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"` + action + `"}]}`},
	}
}

// denyEdge returns a CloudPermission that AWSEvaluator evaluates to Blocked
// (explicit deny) for action.
func denyEdge(source *cloudgraph.CloudIdentity, target *cloudgraph.CloudResource, action string) *cloudgraph.CloudPermission {
	return &cloudgraph.CloudPermission{
		Source: source, Target: target, Action: action, SourceType: "identity-policy",
		Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Deny","Action":"` + action + `"}]}`},
	}
}

func TestExecuteCloudPlanRun_ValidPathFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		alice := identity("arn:aws:iam::111:user/alice", "iam-user")
		adminRole := resource("arn:aws:iam::111:role/admin", "iam-role")
		req := cloudrun.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Edges:      []*cloudgraph.CloudPermission{allowEdge(alice, adminRole, "sts:AssumeRole")},
			Held:       []string{alice.CanonicalID},
			Target:     adminRole.CanonicalID,
			MaxHops:    3,
		}
		run, err := cloudrun.ExecuteCloudPlanRun(ctx, pool, req)
		if err != nil {
			t.Fatalf("ExecuteCloudPlanRun: %v", err)
		}
		if run.Status != cloudrun.StatusCompleted {
			t.Fatalf("status: got %s want completed", run.Status)
		}
		var path cloudgraph.CloudPath
		if err := json.Unmarshal(run.Result, &path); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if len(path.Hops) != 1 {
			t.Fatalf("hops: got %d want 1", len(path.Hops))
		}
		if path.Hops[0].Result.State != cloudgraph.PolicySupported {
			t.Fatalf("hop state: got %s want policy_supported", path.Hops[0].Result.State)
		}
		if path.OverallState != cloudgraph.PolicySupported {
			t.Fatalf("overallState: got %s want policy_supported", path.OverallState)
		}
	})
}

func TestExecuteCloudPlanRun_NoPathFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		alice := identity("arn:aws:iam::111:user/alice", "iam-user")
		adminRole := resource("arn:aws:iam::111:role/admin", "iam-role")
		unreachable := resource("arn:aws:iam::111:role/unreachable", "iam-role")
		req := cloudrun.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Edges:      []*cloudgraph.CloudPermission{allowEdge(alice, adminRole, "sts:AssumeRole")},
			Held:       []string{alice.CanonicalID},
			Target:     unreachable.CanonicalID,
			MaxHops:    3,
		}
		run, err := cloudrun.ExecuteCloudPlanRun(ctx, pool, req)
		if err != nil {
			t.Fatalf("ExecuteCloudPlanRun: %v", err)
		}
		// A confirmed no-path result is a successfully completed search, not a
		// failure or an incomplete one -- see the spec's amendment.
		if run.Status != cloudrun.StatusCompleted {
			t.Fatalf("status: got %s want completed", run.Status)
		}
		if string(run.Result) != "null" {
			t.Fatalf("result: got %s want null (no path confirmed)", run.Result)
		}
	})
}

func TestExecuteCloudPlanRun_InsertFailurePropagates(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req := cloudrun.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Edges:      nil,
			Held:       []string{"x"},
			Target:     "y",
			MaxHops:    1,
		}
		_, err := cloudrun.ExecuteCloudPlanRun(ctx, pool, req)
		if err == nil {
			t.Fatal("want non-nil error, got nil")
		}
	})
}
```

Add `"encoding/json"` to the import block (needed for `json.Unmarshal` in the first two tests).

- [ ] **Step 2: Run the tests to verify they fail**

Ensure Docker Desktop is running. Run: `go test ./internal/cloudrun/... -run TestExecuteCloudPlanRun -v`
Expected: compile failure — `undefined: cloudrun.CloudPlanRunRequest` (nothing in `executor.go` exists yet).

- [ ] **Step 3: Implement `executor.go`**

Create `orchestrator/internal/cloudrun/executor.go`:

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

// evaluatorFor maps a cloud_runs.provider value to the concrete evaluator
// that understands it. All three evaluators are zero-arg structs with
// pointer-receiver EvaluatePermission methods. No fallback: an unrecognized
// provider is always rejected, never silently evaluated by another provider's
// logic.
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

// validateEdgesMatchProvider rejects an edge whose Source/Target explicitly
// claims a different provider than the run is scoped to. A nil AccountScope
// makes no claim and is not a mismatch.
func validateEdgesMatchProvider(edges []*cloudgraph.CloudPermission, provider string) error {
	for _, edge := range edges {
		for _, scope := range []*cloudgraph.AccountScope{edge.Source.AccountScope, edge.Target.AccountScope} {
			if scope != nil && scope.Provider != "" && scope.Provider != provider {
				return fmt.Errorf("cloudrun: edge references provider %q, run is scoped to %q", scope.Provider, provider)
			}
		}
	}
	return nil
}

func newRunID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

// statusForPath maps a CloudPlan result to a cloud_runs status. ok=false is
// a confirmed no-path result -- a successfully completed search, not a
// failure or an incomplete one. Partial is reserved for a hop whose
// evaluation rode through an unresolved condition; none of today's three
// evaluators ever populate UnresolvedConds, so this branch is unreachable
// through ExecuteCloudPlanRun as currently wired -- it is still coded,
// correctly, against EvaluationResult's own documented meaning.
func statusForPath(path *cloudgraph.CloudPath, ok bool) Status {
	if !ok {
		return StatusCompleted
	}
	for _, hop := range path.Hops {
		if len(hop.Result.UnresolvedConds) > 0 {
			return StatusPartial
		}
	}
	return StatusCompleted
}

// ExecuteCloudPlanRun runs cloudgraph.CloudPlan for one account and records
// the outcome as a cloud_runs row. It is a plain Go function, not an HTTP
// handler -- a later sub-project decides how (or whether) this is exposed
// over the API.
func ExecuteCloudPlanRun(ctx context.Context, pool *pgxpool.Pool, req CloudPlanRunRequest) (*CloudRun, error) {
	run := &CloudRun{
		ID:          newRunID(),
		ScenarioID:  req.ScenarioID,
		Provider:    req.Account.Provider,
		AccountID:   req.Account.AccountID,
		TenantID:    req.Account.TenantID,
		Region:      req.Account.Region,
		Status:      StatusRunning,
		InitiatedBy: req.InitiatedBy,
		StartedAt:   time.Now().UTC(),
	}
	if err := db.InsertCloudRun(ctx, pool, run); err != nil {
		return nil, err
	}

	evaluator, err := evaluatorFor(req.Account.Provider)
	if err != nil {
		_ = db.UpdateCloudRunStatus(ctx, pool, run.ID, StatusFailed, nil, err.Error())
		return nil, err
	}
	if err := validateEdgesMatchProvider(req.Edges, req.Account.Provider); err != nil {
		_ = db.UpdateCloudRunStatus(ctx, pool, run.ID, StatusFailed, nil, err.Error())
		return nil, err
	}

	path, ok := cloudgraph.CloudPlan(req.Edges, req.Held, req.Target, evaluator, &cloudgraph.RequestContext{}, req.MaxHops)

	resultJSON, marshalErr := json.Marshal(path)
	if marshalErr != nil {
		_ = db.UpdateCloudRunStatus(ctx, pool, run.ID, StatusFailed, nil, marshalErr.Error())
		return nil, marshalErr
	}

	status := statusForPath(path, ok)
	if err := db.UpdateCloudRunStatus(ctx, pool, run.ID, status, resultJSON, ""); err != nil {
		return nil, err
	}

	return db.GetCloudRun(ctx, pool, run.ID)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/cloudrun/... -run TestExecuteCloudPlanRun -v`
Expected: `PASS` on `TestExecuteCloudPlanRun_ValidPathFound`, `TestExecuteCloudPlanRun_NoPathFound`, `TestExecuteCloudPlanRun_InsertFailurePropagates`.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/cloudrun/executor.go orchestrator/internal/cloudrun/executor_test.go
git commit -m "$(cat <<'EOF'
feat(cloudrun): add ExecuteCloudPlanRun

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, confirm `go build ./internal/cloudgraph/... && go test ./internal/cloudgraph/...` still pass, then push. Otherwise push directly: `git push`.

## Task 2: Blocked-edge coexistence + `MaxHops` plumbing

**Files:**
- Modify: `orchestrator/internal/cloudrun/executor_test.go` (append tests only — no production code change)

**Interfaces:**
- Consumes: `cloudrun.ExecuteCloudPlanRun`/`CloudPlanRunRequest`, `identity`/`resource`/`allowEdge` helpers (Task 1).
- Produces: nothing new for later tasks.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/cloudrun/executor_test.go`:

```go
func TestExecuteCloudPlanRun_BlockedEdgeDoesNotPreventPathViaAnotherEdge(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		alice := identity("arn:aws:iam::111:user/alice", "iam-user")
		deniedRole := resource("arn:aws:iam::111:role/denied", "iam-role")
		adminRole := resource("arn:aws:iam::111:role/admin", "iam-role")
		req := cloudrun.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Edges: []*cloudgraph.CloudPermission{
				denyEdge(alice, deniedRole, "sts:AssumeRole"),
				allowEdge(alice, adminRole, "sts:AssumeRole"),
			},
			Held:    []string{alice.CanonicalID},
			Target:  adminRole.CanonicalID,
			MaxHops: 3,
		}
		run, err := cloudrun.ExecuteCloudPlanRun(ctx, pool, req)
		if err != nil {
			t.Fatalf("ExecuteCloudPlanRun: %v", err)
		}
		if run.Status != cloudrun.StatusCompleted {
			t.Fatalf("status: got %s want completed", run.Status)
		}
		var path cloudgraph.CloudPath
		if err := json.Unmarshal(run.Result, &path); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if len(path.Hops) != 1 {
			t.Fatalf("hops: got %d want 1 (the blocked edge must not appear)", len(path.Hops))
		}
		if path.Hops[0].Edge.Target.CanonicalID != adminRole.CanonicalID {
			t.Fatalf("hop target: got %s want %s", path.Hops[0].Edge.Target.CanonicalID, adminRole.CanonicalID)
		}
		if path.Hops[0].Result.State != cloudgraph.PolicySupported {
			t.Fatalf("hop state: got %s want policy_supported", path.Hops[0].Result.State)
		}
	})
}

func TestExecuteCloudPlanRun_MaxHopsIsPlumbedThroughNotHardcoded(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		alice := identity("arn:aws:iam::111:user/alice", "iam-user")
		middleRole := identity("arn:aws:iam::111:role/middle", "iam-role")
		middleResource := resource("arn:aws:iam::111:role/middle", "iam-role")
		targetRole := resource("arn:aws:iam::111:role/target", "iam-role")
		// Edges are listed in REVERSE dependency order on purpose: CloudPlan tries
		// edges in slice order within a single pass, and a legitimate hop can
		// advance reachedAsSource mid-pass -- if hop2 (middle->target) were listed
		// BEFORE hop1 (alice->middle), a single pass could cascade through both
		// hops at once, making MaxHops=1 behave identically to MaxHops=5 and
		// proving nothing. Listing hop2 first means pass 1 tries hop2 while
		// "middle" is not yet a reachable source, so only hop1 advances in pass 1.
		edges := []*cloudgraph.CloudPermission{
			allowEdge(middleRole, targetRole, "sts:AssumeRole"), // hop2
			allowEdge(alice, middleResource, "sts:AssumeRole"),  // hop1
		}
		reqOneHop := cloudrun.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Edges:      edges,
			Held:       []string{alice.CanonicalID},
			Target:     targetRole.CanonicalID,
			MaxHops:    1,
		}
		run, err := cloudrun.ExecuteCloudPlanRun(ctx, pool, reqOneHop)
		if err != nil {
			t.Fatalf("ExecuteCloudPlanRun (MaxHops=1): %v", err)
		}
		if run.Status != cloudrun.StatusCompleted {
			t.Fatalf("MaxHops=1 status: got %s want completed", run.Status)
		}
		if string(run.Result) != "null" {
			t.Fatalf("MaxHops=1 result: got %s want null (hop budget exhausted before reaching target)", run.Result)
		}

		reqFiveHops := reqOneHop
		reqFiveHops.MaxHops = 5
		run, err = cloudrun.ExecuteCloudPlanRun(ctx, pool, reqFiveHops)
		if err != nil {
			t.Fatalf("ExecuteCloudPlanRun (MaxHops=5): %v", err)
		}
		if run.Status != cloudrun.StatusCompleted {
			t.Fatalf("MaxHops=5 status: got %s want completed", run.Status)
		}
		var path cloudgraph.CloudPath
		if err := json.Unmarshal(run.Result, &path); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if len(path.Hops) != 2 {
			t.Fatalf("MaxHops=5 hops: got %d want 2", len(path.Hops))
		}
		// Hop ordering: alice->middle must come before middle->target, matching
		// the logical traversal order -- not the reversed order the edges slice
		// happens to be listed in.
		if path.Hops[0].Edge.Target.CanonicalID != middleResource.CanonicalID {
			t.Fatalf("hop 0 target: got %s want %s", path.Hops[0].Edge.Target.CanonicalID, middleResource.CanonicalID)
		}
		if path.Hops[1].Edge.Target.CanonicalID != targetRole.CanonicalID {
			t.Fatalf("hop 1 target: got %s want %s", path.Hops[1].Edge.Target.CanonicalID, targetRole.CanonicalID)
		}
		if path.Hops[0].Result.State != cloudgraph.PolicySupported || path.Hops[1].Result.State != cloudgraph.PolicySupported {
			t.Fatalf("hop states: got %s/%s want policy_supported/policy_supported", path.Hops[0].Result.State, path.Hops[1].Result.State)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail or pass for the right reason**

Run: `go test ./internal/cloudrun/... -run 'TestExecuteCloudPlanRun_BlockedEdgeDoesNotPreventPathViaAnotherEdge|TestExecuteCloudPlanRun_MaxHopsIsPlumbedThroughNotHardcoded' -v`
Expected: both tests run against Task 1's already-correct implementation. If `TestExecuteCloudPlanRun_MaxHopsIsPlumbedThroughNotHardcoded` fails, it is almost certainly the fixture's edge ordering, not `executor.go` — re-check the comment above before touching production code.

- [ ] **Step 3: Confirm both pass (no production code change in this task)**

Run: `go test ./internal/cloudrun/... -run 'TestExecuteCloudPlanRun_BlockedEdgeDoesNotPreventPathViaAnotherEdge|TestExecuteCloudPlanRun_MaxHopsIsPlumbedThroughNotHardcoded' -v`
Expected: `PASS` on both.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/cloudrun/executor_test.go
git commit -m "$(cat <<'EOF'
test(cloudrun): cover blocked-edge coexistence and MaxHops plumbing

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, confirm `go build ./internal/cloudgraph/... && go test ./internal/cloudgraph/...` still pass, then push. Otherwise push directly: `git push`.

## Task 3: Invalid-input rejection (unsupported provider, mismatched provider)

**Files:**
- Modify: `orchestrator/internal/cloudrun/executor_test.go` (append tests)

**Interfaces:**
- Consumes: `cloudrun.ExecuteCloudPlanRun`, `db.ListCloudRuns` (sub-project #1), `identity`/`resource`/`allowEdge` helpers (Task 1).
- Produces: nothing new for later tasks.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/cloudrun/executor_test.go` (add `"github.com/audspect/bas/internal/db"` to the import block):

```go
func TestExecuteCloudPlanRun_UnsupportedProviderMarksRowFailed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		req := cloudrun.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "unknown", AccountID: "111"},
			Held:       []string{"x"},
			Target:     "y",
			MaxHops:    1,
		}
		_, err := cloudrun.ExecuteCloudPlanRun(ctx, pool, req)
		if err == nil {
			t.Fatal("want non-nil error, got nil")
		}

		rows, listErr := db.ListCloudRuns(ctx, pool, 1)
		if listErr != nil {
			t.Fatalf("list: %v", listErr)
		}
		if len(rows) != 1 {
			t.Fatalf("len: got %d want 1", len(rows))
		}
		if rows[0].Status != cloudrun.StatusFailed {
			t.Fatalf("status: got %s want failed", rows[0].Status)
		}
		if rows[0].Error == "" {
			t.Fatal("want Error set, got empty string")
		}
	})
}

func TestExecuteCloudPlanRun_MismatchedProviderEdgeMarksRowFailed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		alice := identity("arn:aws:iam::111:user/alice", "iam-user")
		azureRole := &cloudgraph.CloudResource{
			CanonicalID:  "arn:azure:role/admin",
			Kind:         "iam-role",
			AccountScope: &cloudgraph.AccountScope{Provider: "azure"},
		}
		req := cloudrun.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			// The run is scoped to aws, but the only edge's Target explicitly
			// claims azure -- this must be rejected before any evaluation.
			Account: cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Edges:   []*cloudgraph.CloudPermission{allowEdge(alice, azureRole, "sts:AssumeRole")},
			Held:    []string{alice.CanonicalID},
			Target:  azureRole.CanonicalID,
			MaxHops: 1,
		}
		_, err := cloudrun.ExecuteCloudPlanRun(ctx, pool, req)
		if err == nil {
			t.Fatal("want non-nil error, got nil")
		}

		rows, listErr := db.ListCloudRuns(ctx, pool, 1)
		if listErr != nil {
			t.Fatalf("list: %v", listErr)
		}
		if len(rows) != 1 {
			t.Fatalf("len: got %d want 1", len(rows))
		}
		if rows[0].Status != cloudrun.StatusFailed {
			t.Fatalf("status: got %s want failed", rows[0].Status)
		}
		if rows[0].Error == "" {
			t.Fatal("want Error set, got empty string")
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `go test ./internal/cloudrun/... -run 'TestExecuteCloudPlanRun_UnsupportedProviderMarksRowFailed|TestExecuteCloudPlanRun_MismatchedProviderEdgeMarksRowFailed' -v`
Expected: `PASS` on both, against Task 1's already-complete implementation (both `evaluatorFor` and `validateEdgesMatchProvider` were written in Task 1, Step 3).

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/cloudrun/executor_test.go
git commit -m "$(cat <<'EOF'
test(cloudrun): cover unsupported-provider and provider-mismatch rejection

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, confirm `go build ./internal/cloudgraph/... && go test ./internal/cloudgraph/...` still pass, then push. Otherwise push directly: `git push`.

## Task 4: `statusForPath`'s `Partial` branch (standalone unit tests)

**Files:**
- Create: `orchestrator/internal/cloudrun/executor_internal_test.go` (package `cloudrun` — needs access to the unexported `statusForPath`)

**Interfaces:**
- Consumes: `statusForPath` (unexported, Task 1), `cloudgraph.CloudPath`/`CloudHop`/`EvaluationResult`/`PathState` constants.
- Produces: nothing new for later tasks. This is the plan's last task touching `cloudrun`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/cloudrun/executor_internal_test.go`:

```go
package cloudrun

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

// TestStatusForPath_UnresolvedConditionYieldsPartial exercises a branch no
// real evaluator can trigger today (AWSEvaluator/AzureEvaluator/GCPEvaluator
// never populate EvaluationResult.UnresolvedConds) -- a hand-built
// EvaluationResult is the only way to prove this mapping logic is correct
// against the type's own documented meaning. See the spec's amendment.
func TestStatusForPath_UnresolvedConditionYieldsPartial(t *testing.T) {
	path := &cloudgraph.CloudPath{
		Hops: []*cloudgraph.CloudHop{
			{Result: &cloudgraph.EvaluationResult{State: cloudgraph.PolicySupported, UnresolvedConds: []string{"mfa-required"}}},
		},
		OverallState: cloudgraph.PolicySupported,
	}
	if got := statusForPath(path, true); got != StatusPartial {
		t.Fatalf("status: got %s want partial", got)
	}
}

func TestStatusForPath_NoPathFoundYieldsCompleted(t *testing.T) {
	if got := statusForPath(nil, false); got != StatusCompleted {
		t.Fatalf("status: got %s want completed", got)
	}
}

func TestStatusForPath_AllHopsResolvedYieldsCompleted(t *testing.T) {
	path := &cloudgraph.CloudPath{
		Hops:         []*cloudgraph.CloudHop{{Result: &cloudgraph.EvaluationResult{State: cloudgraph.PolicySupported}}},
		OverallState: cloudgraph.PolicySupported,
	}
	if got := statusForPath(path, true); got != StatusCompleted {
		t.Fatalf("status: got %s want completed", got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cloudrun/... -run TestStatusForPath -v`
Expected: `PASS` immediately — `statusForPath` was already written correctly in Task 1. This step exists to add dedicated, isolated coverage for a branch the integration tests cannot reach, not to drive new behavior. If any of the three fails, it is a real defect in Task 1's `statusForPath` — fix it there using systematic-debugging, don't patch the test to match wrong behavior.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/cloudrun/executor_internal_test.go
git commit -m "$(cat <<'EOF'
test(cloudrun): add standalone coverage for statusForPath's Partial branch

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, confirm `go build ./internal/cloudgraph/... && go test ./internal/cloudgraph/...` still pass, then push. Otherwise push directly: `git push`.

## Task 5: Strengthen the persistence-honesty test (additive, no production code change)

**Files:**
- Modify: `orchestrator/internal/db/cloudrun_store_test.go` (append a new test — nothing from sub-project #1's final review actually added production or test code beyond what's already shipped; this test does not exist yet)

**Interfaces:**
- Consumes: `db.InsertCloudRun`, `db.GetCloudRun`, `db.UpdateCloudRunStatus` (sub-project #1, unchanged).
- Produces: nothing — this is the plan's last task.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/db/cloudrun_store_test.go`:

```go
func TestUpdateCloudRunStatus_PropagatesContextCancellation(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &cloudrun.CloudRun{ID: "ctx-cancel-case", ScenarioID: "x", Provider: "aws", Status: cloudrun.StatusRunning, StartedAt: time.Now().UTC()}
		if err := db.InsertCloudRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}
		canceledCtx, cancel := context.WithCancel(ctx)
		cancel()
		err := db.UpdateCloudRunStatus(canceledCtx, pool, "ctx-cancel-case", cloudrun.StatusCompleted, nil, "")
		if err == nil {
			t.Fatal("want non-nil error from a canceled context, got nil")
		}

		// A failed write must never be mistaken for a successful one: the row's
		// status must be exactly what it was before the failed call, not
		// StatusCompleted and not some corrupted in-between state.
		got, getErr := db.GetCloudRun(ctx, pool, "ctx-cancel-case")
		if getErr != nil {
			t.Fatalf("get: %v", getErr)
		}
		if got.Status != cloudrun.StatusRunning {
			t.Fatalf("status after failed update: got %s want running (unchanged)", got.Status)
		}
	})
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `go test ./internal/db/... -run TestUpdateCloudRunStatus_PropagatesContextCancellation -v`
Expected: `PASS` — `UpdateCloudRunStatus`'s existing implementation (sub-project #1, unchanged) already behaves this way; this step proves it explicitly rather than assuming it. If it fails, that is a real defect in already-shipped code — use systematic-debugging, don't weaken the assertion to match.

- [ ] **Step 4: Run the full gate across both packages**

Run: `go build ./... && go test ./internal/cloudrun/... ./internal/db/...`
Expected: build succeeds; every test in both packages passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/db/cloudrun_store_test.go
git commit -m "$(cat <<'EOF'
test(cloudrun): prove a failed UpdateCloudRunStatus leaves the row's status unchanged

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, confirm `go build ./internal/cloudgraph/... && go test ./internal/cloudgraph/...` still pass, then push. Otherwise push directly: `git push`.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-13-cloud-plan-execution-harness.md`, rewritten to match the spec's same-day amendment. Execution method: **Native/inline**, per this session's established pattern and your explicit "proceed with this increment." Does this capture your four conditions correctly?

**REQUIRED SUB-SKILL:** Use superpowers:executing-plans.
