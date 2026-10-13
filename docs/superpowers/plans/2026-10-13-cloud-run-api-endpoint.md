# Cloud Run API Endpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the already-shipped `db.ExecuteCloudPlanRun`/`ListCloudRuns`/`GetCloudRun` (sub-projects #1/#2) over HTTP: a trigger endpoint and two read endpoints, following this codebase's existing scenario-run conventions exactly.

**Architecture:** One new handler file (`internal/api/cloudrun_handlers.go`) with three thin handlers, two new route registrations in `routes.go` (plus two corresponding `rbac_matrix_test.go` rows), JSON tags added directly to the real `cloudgraph`/`cloudrun`/`db` types (no DTO layer), and one narrow, explicitly-authorized widening of `ExecuteCloudPlanRun`'s return contract so a failed run can still be correlated by ID.

**Tech Stack:** Go, `chi` router, `pgx/v5`, Postgres via `testcontainers-go` for tests (Docker must be running).

**Spec:** `docs/superpowers/specs/2026-10-13-cloud-run-api-endpoint-design.md`

## Global Constraints

- TDD throughout: every test is written, watched fail, then made to pass.
- Narrow verification per edit; one full `go build ./... && go test ./internal/db/... ./internal/api/... ./internal/cloudgraph/... ./internal/cloudrun/...` gate at the plan's end.
- Minimal changes only: exactly the files named in each task below. No unrelated refactoring of `handlers.go`/`routes.go` beyond the new route registrations and their `rbac_matrix_test.go` rows.
- Sonnet only for any subagent work (the final whole-plan review); never Opus.
- Git push immediately after every commit. Before each push: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, then `go build ./...` as a quick sanity check, then push. This repo has concurrent pushes from another, unrelated active session throughout the day — never touch or investigate that session's own files, just pull cleanly past them.
- Tasks are strictly sequential: Task 1 must land before Task 2 (Task 2's mismatch-provider test asserts on Task 1's widened return contract). Tasks 3 and 4 depend on Task 2's new file and route-registration pattern existing, but not on its specific test content.

## Review Focus

1. **`evaluatorFor`/`json.Marshal` branches stay honestly untestable through integration.** `evaluatorFor`'s rejection branch is shadowed by `cloud_runs.provider`'s own CHECK constraint catching an unsupported value at `InsertCloudRun` first (sub-project #2's own finding); `json.Marshal`'s branch is spec-documented as deliberately untestable without modifying `cloudgraph`'s types. Task 1 changes both call sites but proves neither through a new integration test — it relies on their *own* functions' existing direct unit tests (`TestEvaluatorFor_UnsupportedProviderIsRejected`, already shipped) plus code inspection, matching this session's established precedent. No task should invent mock/fault-injection machinery to force these.
2. **`InitiatedBy`'s `json:"-"` tag must actually block a client override, not merely be untested by omission.** Task 2's test sends a *different*, deliberately wrong value for `initiatedBy` in the request body and asserts the persisted/returned value is still the authenticated caller's claim — not a test that simply never sets the field (which would pass even if the tag were missing).
3. **The audit log's `resource` column must carry the real row ID end-to-end** for a Task-1-affected failure case (`validateEdgesMatchProvider` mismatch) — from `currentRunOrNil` through the handler into the `audit_logs` row. A test that only checks the HTTP status code would miss a regression here entirely.
4. **`limit` clamping must silently fall back, never return 400**, matching every other list endpoint in this codebase (`GetCoverageAnalytics` et al.). A test asserting `400` for a bad `limit` would be testing against the wrong convention.
5. **The two new `GET` routes get no permission wrapper beyond the baseline authenticated-user middleware**, matching `ListScenarioRuns`'s own precedent (`routes.go:242`) — not `auth.RequirePermission(auth.CanRunScenario)`, which only the `POST` gets. `rbac_matrix_test.go`'s `TestRBACMatrix_NoDrift` enforces this at the table level; getting the tier wrong there fails an existing test, not just a new one.
6. **A double failure (the terminal `UpdateCloudRunStatus` write fails, *and* `currentRunOrNil`'s own re-fetch also fails) must still preserve the run ID as text, without fabricating a struct.** `currentRunOrNil` correctly returns `nil` in this case — there's no reliable persisted row to hand back — but `ExecuteCloudPlanRun`'s returned *error* must still name the run ID (`fmt.Errorf("cloud run %s: %w", run.ID, err)`), so a human reading the error string or the handler's `500` body still has something to correlate against, even when the struct genuinely can't be trusted. This is distinct from the `InsertCloudRun`-failure branch, where no row was ever created and the ID must *not* appear in the error (naming an ID that was never persisted would be the fabrication this point warns against) — Task 1 wraps the error only in the four branches that already call `currentRunOrNil`, never in the `InsertCloudRun`-failure branch.

---

## Task 1: Widen `ExecuteCloudPlanRun`'s return contract (Decision 10)

**Files:**
- Modify: `orchestrator/internal/db/cloudrun_executor.go`
- Modify: `orchestrator/internal/db/cloudrun_executor_test.go` (strengthen one existing test)
- Modify: `orchestrator/internal/db/cloudrun_executor_internal_test.go` (add a new unit test)

**Interfaces:**
- Consumes: `db.InsertCloudRun`, `db.GetCloudRun`, `db.UpdateCloudRunStatus` (all already shipped, unchanged).
- Produces: `currentRunOrNil(ctx context.Context, pool *pgxpool.Pool, id string) *cloudrun.CloudRun` (unexported) — Task 2 does **not** call this directly; it only relies on `ExecuteCloudPlanRun`'s widened return value (a non-nil `*cloudrun.CloudRun` on the branches this task changes).

- [ ] **Step 1: Write the failing test — strengthen the existing mismatch test**

In `orchestrator/internal/db/cloudrun_executor_test.go`, find `TestExecuteCloudPlanRun_MismatchedProviderEdgeMarksRowFailed` and add this block immediately after its existing `rows[0].Error == ""` check, still inside the `sharedDB.RunWithPool` closure:

```go
		// Decision 10: ExecuteCloudPlanRun's own return value must also carry
		// the row's true persisted state now, not just a bare error -- so a
		// caller (the API handler, Task 2 of this plan) can correlate a
		// failure back to its row without a second query.
		run, err := db.ExecuteCloudPlanRun(ctx, pool, req)
		if run == nil {
			t.Fatal("want non-nil run (a row was already inserted before the mismatch was caught), got nil")
		}
		if err == nil {
			t.Fatal("want non-nil error even though run is non-nil -- the error is the authoritative failure signal")
		}
		if run.Status != cloudrun.StatusFailed {
			t.Fatalf("run.Status: got %s want failed", run.Status)
		}
		if run.Error == "" {
			t.Fatal("want run.Error set, got empty string")
		}
		if run.ID != rows[0].ID {
			t.Fatalf("run.ID: got %s want %s (must match the row ListCloudRuns found)", run.ID, rows[0].ID)
		}
		if !strings.Contains(err.Error(), run.ID) {
			t.Fatalf("error %q does not mention run ID %s -- correlation must survive in the error text even when the struct can't be trusted (Review Focus 6)", err.Error(), run.ID)
		}
```

Add `"strings"` to `cloudrun_executor_test.go`'s imports if it isn't already there.

Note: the existing test already calls `db.ExecuteCloudPlanRun(ctx, pool, req)` once near its top and discards the run value (`_, err := ...`); change that line to capture `run` too if it doesn't already, so the block above can reuse the same `req`/`ctx`/`pool` — or simply call `ExecuteCloudPlanRun` a second time as shown (idempotent here since the request is pure input, no shared mutable state between calls other than creating a second row, which is fine since the test only reads `rows[0]` from the *first* `ListCloudRuns` call before this block runs — call this block's `ExecuteCloudPlanRun` and switch the existing `_, err :=` line to `run, err :=` to avoid creating a redundant second row, then use that single `run`/`err` pair for both the original assertions and the new ones below the existing `ListCloudRuns` check).

- [ ] **Step 2: Add the failing direct unit test of `currentRunOrNil`**

Append to `orchestrator/internal/db/cloudrun_executor_internal_test.go`:

```go
func TestCurrentRunOrNil_ReturnsTheRealPersistedRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &cloudrun.CloudRun{ID: "current-run-or-nil-case", ScenarioID: "x", Provider: "aws", Status: cloudrun.StatusRunning, StartedAt: time.Now().UTC()}
		if err := InsertCloudRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got := currentRunOrNil(ctx, pool, "current-run-or-nil-case")
		if got == nil {
			t.Fatal("want non-nil run, got nil")
		}
		if got.ID != "current-run-or-nil-case" || got.Status != cloudrun.StatusRunning {
			t.Fatalf("got ID=%s Status=%s, want ID=current-run-or-nil-case Status=running", got.ID, got.Status)
		}
	})
}

func TestCurrentRunOrNil_ReturnsNilWhenTheRowCannotBeFetched(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if got := currentRunOrNil(ctx, pool, "no-such-run-id"); got != nil {
			t.Fatalf("want nil for a nonexistent id, got %+v", got)
		}
	})
}
```

This internal test file (package `db`) needs `"time"` and `pgxpool` imports alongside its existing `testing`/`cloudgraph`/`cloudrun`/`strings` imports — check its current import block and add any missing ones (`"time"`, `"context"`, `"github.com/jackc/pgx/v5/pgxpool"`).

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/db/... -run 'TestExecuteCloudPlanRun_MismatchedProviderEdgeMarksRowFailed|TestCurrentRunOrNil' -v`
Expected: `TestExecuteCloudPlanRun_MismatchedProviderEdgeMarksRowFailed` fails on the new `run == nil` check (current code returns `nil` on this branch). `TestCurrentRunOrNil_ReturnsTheRealPersistedRow`/`TestCurrentRunOrNil_ReturnsNilWhenTheRowCannotBeFetched` fail to compile (`undefined: currentRunOrNil`) — that compile failure is itself the expected RED for those two.

- [ ] **Step 4: Implement `currentRunOrNil`, widen the four branches, and wrap their errors with the run ID**

In `orchestrator/internal/db/cloudrun_executor.go`, add this function after `statusForPath` and before `ExecuteCloudPlanRun`:

```go
// currentRunOrNil re-fetches id's row to report its true persisted state
// alongside an error -- never a locally-guessed value, since a best-effort
// status write (see the call sites below) may itself have failed, leaving
// the row's actual status different from what was intended. Returns nil,
// not a stale/wrong struct, if even the re-fetch isn't reliable.
func currentRunOrNil(ctx context.Context, pool *pgxpool.Pool, id string) *cloudrun.CloudRun {
	run, err := GetCloudRun(ctx, pool, id)
	if err != nil {
		return nil
	}
	return run
}
```

Then change exactly these four branches inside `ExecuteCloudPlanRun` (the `InsertCloudRun`-failure `return nil, err` at the top and the final `return GetCloudRun(ctx, pool, run.ID)` success path are both unchanged). Each error is wrapped with `run.ID` so the ID survives in the error text even in the rare case `currentRunOrNil` itself returns `nil` (Review Focus 6) — this is deliberately different from the `InsertCloudRun`-failure branch above these, which never mentions an ID, since no row was ever created there:

```go
	evaluator, err := evaluatorFor(req.Account.Provider)
	if err != nil {
		_ = UpdateCloudRunStatus(ctx, pool, run.ID, cloudrun.StatusFailed, nil, err.Error())
		return currentRunOrNil(ctx, pool, run.ID), fmt.Errorf("cloud run %s: %w", run.ID, err)
	}
	if err := validateEdgesMatchProvider(req.Edges, req.Account.Provider); err != nil {
		_ = UpdateCloudRunStatus(ctx, pool, run.ID, cloudrun.StatusFailed, nil, err.Error())
		return currentRunOrNil(ctx, pool, run.ID), fmt.Errorf("cloud run %s: %w", run.ID, err)
	}

	path, ok := cloudgraph.CloudPlan(req.Edges, req.Held, req.Target, evaluator, &cloudgraph.RequestContext{}, req.MaxHops)

	resultJSON, marshalErr := json.Marshal(path)
	if marshalErr != nil {
		_ = UpdateCloudRunStatus(ctx, pool, run.ID, cloudrun.StatusFailed, nil, marshalErr.Error())
		return currentRunOrNil(ctx, pool, run.ID), fmt.Errorf("cloud run %s: %w", run.ID, marshalErr)
	}

	status := statusForPath(path, ok)
	if err := UpdateCloudRunStatus(ctx, pool, run.ID, status, resultJSON, ""); err != nil {
		return currentRunOrNil(ctx, pool, run.ID), fmt.Errorf("cloud run %s: %w", run.ID, err)
	}
```

Add `"fmt"` to `cloudrun_executor.go`'s imports if it isn't already there (it already is, used by `evaluatorFor`/`validateEdgesMatchProvider`/`newRunID`).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/db/... -run 'TestExecuteCloudPlanRun|TestCurrentRunOrNil|TestStatusForPath|TestEvaluatorFor' -v`
Expected: `PASS` on all, including every pre-existing `TestExecuteCloudPlanRun_*` test from sub-project #2 (none of their assertions on the `InsertCloudRun`-failure branch or the success path change).

- [ ] **Step 6: Run the full package gate**

Run: `go build ./... && go test ./internal/db/...`
Expected: build succeeds; every test in `internal/db` passes.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/cloudrun_executor.go orchestrator/internal/db/cloudrun_executor_test.go orchestrator/internal/db/cloudrun_executor_internal_test.go
git commit -m "$(cat <<'EOF'
feat(cloudrun): report a failed run's true persisted state, not nil

ExecuteCloudPlanRun now re-fetches and returns the row on every error
branch where InsertCloudRun already succeeded, instead of discarding
it. currentRunOrNil re-fetches rather than guessing locally, since a
best-effort status write can itself fail -- the final branch's row may
still be StatusRunning, not Failed, and only a re-fetch reports that
truthfully. The error remains the sole authoritative failure signal in
every branch; a non-nil run is never evidence of success.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, then `go build ./...` to confirm, then push. Otherwise push directly: `git push`.

## Task 2: `POST /api/cloud-runs` — trigger endpoint

**Files:**
- Create: `orchestrator/internal/api/cloudrun_handlers.go`
- Create: `orchestrator/internal/api/cloudrun_handlers_test.go`
- Modify: `orchestrator/internal/cloudgraph/types.go` (add JSON tags)
- Modify: `orchestrator/internal/cloudrun/types.go` (add JSON tags)
- Modify: `orchestrator/internal/db/cloudrun_executor.go` (add JSON tags to `CloudPlanRunRequest`)
- Modify: `orchestrator/internal/api/routes.go` (register the route)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (add the route's row)

**Interfaces:**
- Consumes: `db.ExecuteCloudPlanRun(ctx, pool, req) (*cloudrun.CloudRun, error)` (Task 1's widened version), `db.CloudPlanRunRequest`, `auth.ClaimsFrom(r.Context())`, `auth.RequirePermission(auth.CanRunScenario)`, `h.auditLog`, `respondStatus`, `jsonError`.
- Produces: `func (h *Handler) TriggerCloudPlanRun(w http.ResponseWriter, r *http.Request)` — Tasks 3/4 don't call this, but reuse its file and its JSON-tag additions.

- [ ] **Step 1: Add JSON tags to the real types**

In `orchestrator/internal/cloudgraph/types.go`, replace the `AccountScope` through `CloudPermission` struct bodies (the comment-only lines are preserved verbatim, just reformatted to fit the added tags):

```go
// AccountScope identifies the cloud account/subscription/project owning a resource
type AccountScope struct {
	Provider  string `json:"provider"`            // "aws", "azure", "gcp"
	AccountID string `json:"accountId"`           // AWS account ID, Azure subscription ID, GCP project ID
	TenantID  string `json:"tenantId,omitempty"`  // Azure tenant ID (if applicable)
	Region    string `json:"region,omitempty"`    // Optional: geographic scope
}

// Provenance tracks where an observation came from and its freshness
type Provenance struct {
	Source        string        `json:"source"`
	ObservedAt    time.Time     `json:"observedAt"`
	CollectionAge time.Duration `json:"collectionAge"`
	Confidence    string        `json:"confidence"`
	ErrorDetail   string        `json:"errorDetail,omitempty"`
}

// CloudResource represents a normalized cloud resource (S3 bucket, storage account, role, etc.)
type CloudResource struct {
	CanonicalID  string            `json:"canonicalId"`
	Kind         string            `json:"kind"`
	AccountScope *AccountScope     `json:"accountScope,omitempty"`
	DisplayName  string            `json:"displayName,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	Provenance   *Provenance       `json:"provenance,omitempty"`
}

// CloudIdentity represents a cloud principal (IAM user, role, service principal, etc.)
type CloudIdentity struct {
	CanonicalID  string            `json:"canonicalId"`
	Kind         string            `json:"kind"`
	AccountScope *AccountScope     `json:"accountScope,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	Provenance   *Provenance       `json:"provenance,omitempty"`
}

// Condition represents a prerequisite or constraint on authorization (IP restriction, MFA, etc.)
type Condition struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	EvaluatedAs string `json:"evaluatedAs"`
}

// CloudPermission represents an authorization edge from identity to resource
type CloudPermission struct {
	Source     *CloudIdentity    `json:"source"`
	Target     *CloudResource    `json:"target"`
	Action     string            `json:"action"`
	Conditions []*Condition      `json:"conditions,omitempty"`
	SourceType string            `json:"sourceType,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Provenance *Provenance       `json:"provenance,omitempty"`
}
```

In `orchestrator/internal/cloudrun/types.go`, replace the `CloudRun` struct body:

```go
type CloudRun struct {
	ID          string          `json:"id"`
	ScenarioID  string          `json:"scenarioId"`
	Provider    string          `json:"provider"`
	AccountID   string          `json:"accountId"`
	TenantID    string          `json:"tenantId,omitempty"`
	Region      string          `json:"region,omitempty"`
	Status      Status          `json:"status"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
	InitiatedBy string          `json:"initiatedBy,omitempty"`
	StartedAt   time.Time       `json:"startedAt"`
	CompletedAt *time.Time      `json:"completedAt,omitempty"`
}
```

In `orchestrator/internal/db/cloudrun_executor.go`, replace the `CloudPlanRunRequest` struct body:

```go
type CloudPlanRunRequest struct {
	ScenarioID  string                        `json:"scenarioId"`
	Account     cloudgraph.AccountScope       `json:"account"`
	Edges       []*cloudgraph.CloudPermission `json:"edges"`
	Held        []string                      `json:"held"`
	Target      string                        `json:"target"`
	MaxHops     int                           `json:"maxHops"`
	InitiatedBy string                        `json:"-"`
}
```

These are additive metadata-only changes with no behavior change — do not run tests yet; Step 2 below is this task's real RED.

- [ ] **Step 2: Write the failing tests**

Create `orchestrator/internal/api/cloudrun_handlers_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudrun"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func triggerCloudPlanRunReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) (*http.Request, string) {
	t.Helper()
	userID := seedUser(t, pool, fmt.Sprintf("cloudrun-op-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/cloud-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
	return req, userID
}

func validCloudPlanRunBody() map[string]any {
	return map[string]any{
		"scenarioId": "test-scenario",
		"account":    map[string]any{"provider": "aws", "accountId": "111"},
		"edges": []map[string]any{
			{
				"source": map[string]any{"canonicalId": "arn:aws:iam::111:user/alice", "kind": "iam-user"},
				"target": map[string]any{"canonicalId": "arn:aws:iam::111:role/admin", "kind": "iam-role"},
				"action": "sts:AssumeRole", "sourceType": "identity-policy",
				"attributes": map[string]any{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`},
			},
		},
		"held":    []string{"arn:aws:iam::111:user/alice"},
		"target":  "arn:aws:iam::111:role/admin",
		"maxHops": 3,
	}
}

func TestTriggerCloudPlanRun_Success(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req, _ := triggerCloudPlanRunReq(t, pool, validCloudPlanRunBody())
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var run cloudrun.CloudRun
		if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if run.ID == "" {
			t.Fatal("want non-empty run ID")
		}
		if run.Status != cloudrun.StatusCompleted && run.Status != cloudrun.StatusPartial {
			t.Fatalf("status: got %s want completed or partial", run.Status)
		}
	})
}

func TestTriggerCloudPlanRun_MissingScenarioID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validCloudPlanRunBody()
		delete(body, "scenarioId")
		req, _ := triggerCloudPlanRunReq(t, pool, body)
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerCloudPlanRun_MissingTarget(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validCloudPlanRunBody()
		delete(body, "target")
		req, _ := triggerCloudPlanRunReq(t, pool, body)
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerCloudPlanRun_InvalidProvider(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validCloudPlanRunBody()
		body["account"] = map[string]any{"provider": "not-a-real-provider", "accountId": "111"}
		req, _ := triggerCloudPlanRunReq(t, pool, body)
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var count int
		_ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM cloud_runs WHERE scenario_id = 'test-scenario'`).Scan(&count)
		if count != 0 {
			t.Fatalf("rows created: got %d want 0 (the handler's pre-check must run before any insert)", count)
		}
	})
}

func TestTriggerCloudPlanRun_InitiatedByIsAlwaysServerControlled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validCloudPlanRunBody()
		body["initiatedBy"] = "someone-else-entirely"
		req, userID := triggerCloudPlanRunReq(t, pool, body)
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var run cloudrun.CloudRun
		if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if run.InitiatedBy != userID {
			t.Fatalf("InitiatedBy: got %q want %q (the authenticated caller, not the request body's spoofed value)", run.InitiatedBy, userID)
		}
	})
}

func TestTriggerCloudPlanRun_MismatchFailsWith500AndAuditsTheRealRowID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{
			"scenarioId": "mismatch-scenario",
			"account":    map[string]any{"provider": "aws", "accountId": "111"},
			"edges": []map[string]any{
				{
					"source": map[string]any{"canonicalId": "arn:aws:iam::111:user/alice", "kind": "iam-user"},
					"target": map[string]any{
						"canonicalId": "arn:azure:role/admin", "kind": "iam-role",
						"accountScope": map[string]any{"provider": "azure"},
					},
					"action": "sts:AssumeRole",
				},
			},
			"held":   []string{"arn:aws:iam::111:user/alice"},
			"target": "arn:azure:role/admin",
		}
		req, _ := triggerCloudPlanRunReq(t, pool, body)
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var errBody struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
			t.Fatalf("decode error body: %v", err)
		}
		if errBody.Error == "" {
			t.Fatal("want a non-empty error message in the response body")
		}
		var runID string
		var status string
		ctx := context.Background()
		if err := pool.QueryRow(ctx, `SELECT id, status FROM cloud_runs WHERE scenario_id = 'mismatch-scenario'`).Scan(&runID, &status); err != nil {
			t.Fatalf("query row: %v", err)
		}
		if status != string(cloudrun.StatusFailed) {
			t.Fatalf("status: got %s want failed", status)
		}
		if !strings.Contains(errBody.Error, runID) {
			t.Fatalf("response error %q does not mention the real run ID %s -- Task 1's error-wrapping must reach the HTTP response", errBody.Error, runID)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			var n int
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'cloudrun.plan.run' AND resource = $1 AND outcome = 'error'`, runID).Scan(&n)
			if n == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("audit rows for resource=%s = %d, want 1 (the handler must pass the real row ID through to the audit log on failure)", runID, n)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}

func TestTriggerCloudPlanRun_SuccessAudits(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req, _ := triggerCloudPlanRunReq(t, pool, validCloudPlanRunBody())
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var run cloudrun.CloudRun
		if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode: %v", err)
		}
		ctx := context.Background()
		deadline := time.Now().Add(2 * time.Second)
		for {
			var n int
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'cloudrun.plan.run' AND resource = $1 AND outcome = 'ok'`, run.ID).Scan(&n)
			if n == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("audit rows for resource=%s = %d, want 1", run.ID, n)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}
```

This test file uses `auth.RoleAnalyst` (`internal/auth/jwt.go:15`, `Role = "analyst"`), already confirmed to exist.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/api/... -run TestTriggerCloudPlanRun -v`
Expected: compile failure — `undefined: Handler.TriggerCloudPlanRun` (nothing in `cloudrun_handlers.go` exists yet) or `undefined: auth.RoleAnalyst`/similar if the role-constant name needs correcting first — fix any such naming mismatch against the real `internal/auth` package before treating the remaining compile failure as this step's RED.

- [ ] **Step 4: Implement `TriggerCloudPlanRun`**

Create `orchestrator/internal/api/cloudrun_handlers.go`:

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
)

// POST /api/cloud-runs — runs cloudgraph.CloudPlan for one account against a
// caller-supplied permission graph and persists the outcome as a cloud_runs
// row. Synchronous: CloudPlan has no I/O today, so there is nothing to poll.
func (h *Handler) TriggerCloudPlanRun(w http.ResponseWriter, r *http.Request) {
	var req db.CloudPlanRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ScenarioID == "" {
		jsonError(w, "scenarioId required", http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		jsonError(w, "target required", http.StatusBadRequest)
		return
	}
	switch req.Account.Provider {
	case "aws", "azure", "gcp":
		// ok
	default:
		jsonError(w, "invalid provider — use aws | azure | gcp", http.StatusBadRequest)
		return
	}

	// InitiatedBy is never trusted from the request body -- always the
	// authenticated caller, matching RunScenario's own convention.
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		req.InitiatedBy = c.UserID
	}

	run, err := db.ExecuteCloudPlanRun(r.Context(), h.db, req)
	if err != nil {
		// run is non-nil whenever a row actually exists (it's always nil only
		// when InsertCloudRun itself never created one) -- use its ID for
		// audit correlation when available, "" otherwise.
		failedRunID := ""
		if run != nil {
			failedRunID = run.ID
		}
		h.auditLog(r, "cloudrun.plan.run", failedRunID, map[string]any{
			"scenarioId": req.ScenarioID, "provider": req.Account.Provider, "error": err.Error(),
		}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "cloudrun.plan.run", run.ID, map[string]any{
		"scenarioId": req.ScenarioID, "provider": req.Account.Provider, "status": string(run.Status),
	}, "ok")
	respondStatus(w, run, http.StatusCreated)
}
```

`h.db` is confirmed as the `Handler`'s pool field (`internal/api/handlers.go:80`, `db *pgxpool.Pool`).

- [ ] **Step 5: Register the route**

In `orchestrator/internal/api/routes.go`, immediately after the `/api/scenarios/{id}/run` registration (`routes.go:408`), add:

```go
		r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/cloud-runs", h.TriggerCloudPlanRun)
```

- [ ] **Step 6: Add the RBAC matrix row**

In `orchestrator/internal/api/rbac_matrix_test.go`, add this row to `routeMatrix` near the existing `/api/scenarios/{id}/run` row:

```go
	{http.MethodPost, "/api/cloud-runs", tierPermission, auth.CanRunScenario},
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/api/... -run 'TestTriggerCloudPlanRun|TestRBACMatrix_NoDrift' -v`
Expected: `PASS` on all `TestTriggerCloudPlanRun_*` tests and on `TestRBACMatrix_NoDrift`.

- [ ] **Step 8: Run the full gate**

Run: `go build ./... && go test ./internal/db/... ./internal/api/... ./internal/cloudgraph/... ./internal/cloudrun/...`
Expected: build succeeds; every test passes.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/api/cloudrun_handlers.go orchestrator/internal/api/cloudrun_handlers_test.go orchestrator/internal/cloudgraph/types.go orchestrator/internal/cloudrun/types.go orchestrator/internal/db/cloudrun_executor.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "$(cat <<'EOF'
feat(cloudrun): add POST /api/cloud-runs trigger endpoint

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, then `go build ./...`, then push. Otherwise push directly: `git push`.

## Task 3: `GET /api/cloud-runs` — list endpoint

**Files:**
- Modify: `orchestrator/internal/api/cloudrun_handlers.go`
- Modify: `orchestrator/internal/api/cloudrun_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `db.ListCloudRuns(ctx, pool, limit) ([]*cloudrun.CloudRun, error)` (already shipped, unchanged).
- Produces: `func (h *Handler) ListCloudRuns(w http.ResponseWriter, r *http.Request)` — Task 4 doesn't call this.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/cloudrun_handlers_test.go` (add `"strconv"` and `"net/url"` to imports if needed — `net/url` is not needed since query params are appended via plain string concatenation below):

```go
func TestListCloudRuns_RoundTripsATriggeredRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		triggerReq, _ := triggerCloudPlanRunReq(t, pool, validCloudPlanRunBody())
		triggerRec := callAuthed(h.TriggerCloudPlanRun, triggerReq)
		if triggerRec.Code != http.StatusCreated {
			t.Fatalf("setup trigger failed: status = %d, body = %s", triggerRec.Code, triggerRec.Body.String())
		}
		var triggered cloudrun.CloudRun
		if err := json.Unmarshal(triggerRec.Body.Bytes(), &triggered); err != nil {
			t.Fatalf("decode trigger response: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/cloud-runs", nil, auth.RoleAnalyst, "any-authenticated-user")
		rec := callAuthed(h.ListCloudRuns, listReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var runs []*cloudrun.CloudRun
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		found := false
		for _, r := range runs {
			if r.ID == triggered.ID {
				found = true
			}
		}
		if !found {
			t.Fatalf("triggered run %s not found in list of %d runs", triggered.ID, len(runs))
		}
	})
}

func TestListCloudRuns_LimitBoundaryValues(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		// Seed 3 rows so the "honored, small limit" case (limit=1) has
		// something real to clamp against -- a test that never seeds more
		// rows than the default can't distinguish "honored" from "ignored".
		for i := 0; i < 3; i++ {
			h2 := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
			triggerReq, _ := triggerCloudPlanRunReq(t, pool, validCloudPlanRunBody())
			if rec := callAuthed(h2.TriggerCloudPlanRun, triggerReq); rec.Code != http.StatusCreated {
				t.Fatalf("seed trigger %d failed: status = %d, body = %s", i, rec.Code, rec.Body.String())
			}
		}

		cases := []struct {
			name        string
			limitParam  string
			wantMaxRows int // 0 means "don't check row count, only status"
		}{
			{"malformed", "not-a-number", 0},
			{"zero", "0", 0},
			{"negative", "-1", 0},
			{"justOverMax", "101", 0},
			{"exactlyMax", "100", 0},
			{"validSmall", "1", 1},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				listReq := authedRequest(t, http.MethodGet, "/api/cloud-runs?limit="+c.limitParam, nil, auth.RoleAnalyst, "any-authenticated-user")
				rec := callAuthed(h.ListCloudRuns, listReq)
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, body = %s (an invalid limit must silently fall back to the default, never 400)", rec.Code, rec.Body.String())
				}
				if c.wantMaxRows > 0 {
					var runs []*cloudrun.CloudRun
					if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
						t.Fatalf("decode: %v", err)
					}
					if len(runs) != c.wantMaxRows {
						t.Fatalf("rows: got %d want exactly %d (limit=%s must be honored, not ignored)", len(runs), c.wantMaxRows, c.limitParam)
					}
				}
			})
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/api/... -run TestListCloudRuns -v`
Expected: compile failure — `undefined: Handler.ListCloudRuns`.

- [ ] **Step 3: Implement `ListCloudRuns`**

Append to `orchestrator/internal/api/cloudrun_handlers.go` (add `"strconv"` to its imports):

```go
// GET /api/cloud-runs — lists cloud runs, most recent first. Any
// authenticated user may read this, matching ListScenarioRuns' own
// precedent -- only the trigger endpoint is permission-gated.
func (h *Handler) ListCloudRuns(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	runs, err := db.ListCloudRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []*cloudrun.CloudRun{}
	}
	respond(w, runs)
}
```

Add `"github.com/audspect/bas/internal/cloudrun"` to `cloudrun_handlers.go`'s import block.

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, immediately after the `/api/scenarios/runs` registration (`routes.go:242`), add:

```go
		r.Get("/api/cloud-runs", h.ListCloudRuns)
```

- [ ] **Step 5: Add the RBAC matrix row**

In `orchestrator/internal/api/rbac_matrix_test.go`, add this row near the existing `/api/scenarios/runs` row:

```go
	{http.MethodGet, "/api/cloud-runs", tierAny, ""},
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/api/... -run 'TestListCloudRuns|TestRBACMatrix_NoDrift' -v`
Expected: `PASS` on both.

- [ ] **Step 7: Run the full gate**

Run: `go build ./... && go test ./internal/db/... ./internal/api/... ./internal/cloudgraph/... ./internal/cloudrun/...`
Expected: build succeeds; every test passes.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/cloudrun_handlers.go orchestrator/internal/api/cloudrun_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "$(cat <<'EOF'
feat(cloudrun): add GET /api/cloud-runs list endpoint

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, then `go build ./...`, then push. Otherwise push directly: `git push`.

## Task 4: `GET /api/cloud-runs/{id}` — get-by-ID endpoint

**Files:**
- Modify: `orchestrator/internal/api/cloudrun_handlers.go`
- Modify: `orchestrator/internal/api/cloudrun_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `db.GetCloudRun(ctx, pool, id) (*cloudrun.CloudRun, error)` (already shipped, unchanged), `withURLParam` (already shipped, `event_handlers_test.go`), `pgx.ErrNoRows`.
- Produces: `func (h *Handler) GetCloudRun(w http.ResponseWriter, r *http.Request)` — this plan's last task.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/cloudrun_handlers_test.go` (add `"github.com/go-chi/chi/v5"` to imports if `withURLParam` needs it directly here — it doesn't, `withURLParam` is already defined elsewhere in package `api` and usable as-is):

```go
func TestGetCloudRun_RoundTripsASingleRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		triggerReq, _ := triggerCloudPlanRunReq(t, pool, validCloudPlanRunBody())
		triggerRec := callAuthed(h.TriggerCloudPlanRun, triggerReq)
		if triggerRec.Code != http.StatusCreated {
			t.Fatalf("setup trigger failed: status = %d, body = %s", triggerRec.Code, triggerRec.Body.String())
		}
		var triggered cloudrun.CloudRun
		if err := json.Unmarshal(triggerRec.Body.Bytes(), &triggered); err != nil {
			t.Fatalf("decode trigger response: %v", err)
		}

		getReq := authedRequest(t, http.MethodGet, "/api/cloud-runs/"+triggered.ID, nil, auth.RoleAnalyst, "any-authenticated-user")
		getReq = withURLParam(getReq, "id", triggered.ID)
		rec := callAuthed(h.GetCloudRun, getReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var got cloudrun.CloudRun
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.ID != triggered.ID {
			t.Fatalf("ID: got %s want %s", got.ID, triggered.ID)
		}
	})
}

func TestGetCloudRun_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		getReq := authedRequest(t, http.MethodGet, "/api/cloud-runs/no-such-id", nil, auth.RoleAnalyst, "any-authenticated-user")
		getReq = withURLParam(getReq, "id", "no-such-id")
		rec := callAuthed(h.GetCloudRun, getReq)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/api/... -run TestGetCloudRun -v`
Expected: compile failure — `undefined: Handler.GetCloudRun`.

- [ ] **Step 3: Implement `GetCloudRun`**

Append to `orchestrator/internal/api/cloudrun_handlers.go` (add `"errors"` and `"github.com/go-chi/chi/v5"` and `"github.com/jackc/pgx/v5"` to its imports):

```go
// GET /api/cloud-runs/{id} — fetches a single cloud run. Same baseline-only
// access as ListCloudRuns.
func (h *Handler) GetCloudRun(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetCloudRun(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "cloud run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, run)
}
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, immediately after the `/api/cloud-runs` list registration added in Task 3, add:

```go
		r.Get("/api/cloud-runs/{id}", h.GetCloudRun)
```

- [ ] **Step 5: Add the RBAC matrix row**

In `orchestrator/internal/api/rbac_matrix_test.go`, add:

```go
	{http.MethodGet, "/api/cloud-runs/{id}", tierAny, ""},
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/api/... -run 'TestGetCloudRun|TestRBACMatrix_NoDrift' -v`
Expected: `PASS` on both.

- [ ] **Step 7: Run the full gate**

Run: `go build ./... && go test ./internal/db/... ./internal/api/... ./internal/cloudgraph/... ./internal/cloudrun/...`
Expected: build succeeds; every test passes.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/cloudrun_handlers.go orchestrator/internal/api/cloudrun_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "$(cat <<'EOF'
feat(cloudrun): add GET /api/cloud-runs/{id} endpoint

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Before pushing: `git fetch && git log --oneline main..origin/main` — if anything landed, `git pull`, then `go build ./...`, then push. Otherwise push directly: `git push`.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-13-cloud-run-api-endpoint.md`. Execution method: **Native/inline**, as you already specified. Each task runs its own RED→GREEN cycle, a diff review, and a commit; after Task 4, the full build/test gate (Global Constraints) runs once, then a fresh independent review (most capable model, not this session) checks the whole branch before anything is considered ready to merge — matching the process this session's last two sub-projects already used. Does this capture what you want?

**REQUIRED SUB-SKILL:** Use superpowers:executing-plans.
