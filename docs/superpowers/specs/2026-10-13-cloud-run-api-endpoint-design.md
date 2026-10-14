# Cloud Run API Endpoint — Design Spec

## Context

Part 3 of the 5-part decomposition of the Cloud BAS wiring initiative (see `docs/superpowers/specs/2026-10-13-cloud-run-data-model-design.md` for the full list). Part 1 (the `cloud_runs` data model/lifecycle) and Part 2 (the `CloudPlan` execution harness, `db.ExecuteCloudPlanRun`) are both done, reviewed, and merged to `main`. Neither has any HTTP exposure — they are pure Go, callable only from tests.

This part exposes `db.ExecuteCloudPlanRun`, `db.ListCloudRuns`, and `db.GetCloudRun` (all already shipped and tested) over HTTP, following the conventions the existing scenario-run endpoints already establish. Part 4 (multi-account campaign fan-out via `RunMultiAccount`) and Part 5 (hybrid AD-to-cloud / cloud-ransomware scenario wiring) remain separate, later sub-projects.

## Grounded facts (verified against real code during brainstorming, not assumed)

- `POST /api/scenarios/{id}/run` (`RunScenario`, `internal/api/handlers.go:2228`) is the model for a trigger endpoint: `chi` router, registered via `r.With(auth.RequirePermission(auth.CanRunScenario)).Post(...)` in `internal/api/routes.go:408`. It is strictly **async**: it dispatches and returns `{runId, status:"dispatched", mode}` immediately; results are polled afterward via separate `GET` endpoints. It does the handler's own explicit pre-validation (agent state, OS compatibility, mode, confirm flags) *before* calling the shared `dispatchRun` core, and maps every error that core itself returns uniformly to `500`.
- `InitiatedBy`/the audit actor is always read server-side from `auth.ClaimsFrom(r.Context())` (`c.UserID`) — never a client-supplied request field.
- `GET /api/scenarios/runs` (`ListScenarioRuns`, `internal/api/handlers.go:3153`) has **no** `auth.RequirePermission(...)` wrapper beyond the route group's baseline `r.Use(auth.Middleware(jwtSecret))` (`internal/api/routes.go:181-182`) — any authenticated user can list runs, regardless of role. Write/trigger endpoints get an explicit permission gate; reads in this codebase's convention do not, by default.
- The limit-query-param convention, seen identically across a dozen existing handlers (e.g. `GetCoverageAnalytics`, `internal/api/handlers.go:4552-4558`): `limit := <default>; if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= <max> { limit = l }`. A malformed, zero, negative, or oversized value is **silently ignored and the default is used** — it is never a `400`. No endpoint in this codebase treats a bad `limit` as a client error.
- `h.auditLog` (`internal/api/audit.go:57`) is fire-and-forget by design: it runs the `INSERT INTO audit_logs` in a `go func()` and discards that insert's own error (`_, _ = h.db.Exec(...)`). This is the established audit contract — an audit-log failure must never fail or alter the outcome of the HTTP request it's describing. `RunScenario` only calls it on its success path; it does not audit its own error returns.
- `cloudgraph.AccountScope`, `CloudPermission`, `CloudIdentity`, `CloudResource` (`internal/cloudgraph/types.go`) and `cloudrun.CloudRun` (`internal/cloudrun/types.go`) currently have **zero** JSON struct tags.
- `db.ExecuteCloudPlanRun` (`internal/db/cloudrun_executor.go`) already threads `ctx` through every DB call (`InsertCloudRun`, `UpdateCloudRunStatus`, `GetCloudRun`) — pgx respects context cancellation, proven directly by sub-project #2's own `TestUpdateCloudRunStatus_PropagatesContextCancellation`. `cloudgraph.CloudPlan` itself takes no context and performs no I/O — it is pure in-memory evaluation against caller-supplied data, so it cannot block.
- The HTTP server (`cmd/server/main.go:1032-1033` and 3 similar blocks) sets `ReadTimeout: 30s, WriteTimeout: 90s` globally. No route-specific `context.WithTimeout` or `chi/middleware.Timeout` exists anywhere in `routes.go`.
- `ExecuteCloudPlanRun`'s return shape is exactly one of two cases, never a third: `(run, nil)` where `run.Status` is `Completed` or `Partial` (the search itself concluded, however its verdict came out), or `(nil, err)` where every one of its five internal error-producing branches (`InsertCloudRun` failure, `evaluatorFor` rejection, `validateEdgesMatchProvider` rejection, JSON marshal failure, final `UpdateCloudRunStatus`/`GetCloudRun` failure) returns before ever reaching a state where a `Failed`-status row could be returned alongside a `nil` error. A `Failed` row and a non-nil error are always paired.

## Decisions (each a real trade-off surfaced and resolved during brainstorming)

1. **Synchronous execution, not async/poll.** `ExecuteCloudPlanRun` has no I/O to wait on today (pure in-memory evaluation against caller-supplied fixtures); wrapping it in an async dispatch-and-poll pattern now would be dishonest about what's actually happening. Revisit once real, network-bound cloud discovery replaces fixture data.
2. **Caller supplies the full graph in the POST body, not a `scenario_id` resolved server-side.** No registry of pre-built account graphs exists; building one is a distinct, undecided sub-project of its own, not disguised API work here.
3. **Reuse `auth.CanRunScenario` for the trigger endpoint; no new permission.** Matches the established reuse pattern (e.g. `technique_verification_handlers.go` reuses this same permission for an unrelated action). The two `GET` endpoints get no additional permission gate, matching `ListScenarioRuns`'s own precedent exactly (see Grounded Facts).
4. **Include `GET` list/single endpoints in this sub-project.** The underlying `db.ListCloudRuns`/`db.GetCloudRun` are already shipped and tested; exposing them is a small, low-risk addition, not a new sub-project.
5. **JSON tags added directly to the real types (`cloudgraph`, `cloudrun`, `db.CloudPlanRunRequest`), not a parallel DTO layer.** Tags are inert metadata — no behavior change, nothing in sub-project #1/#2's tests touches serialization. Avoids a conversion layer that could drift from the real types for no benefit, since nothing else consumes these types as JSON today.
6. **`ExecuteCloudPlanRun`'s own errors map uniformly to `500`.** Distinguishing "bad input" from "infra failure" from a plain `error` would require exporting `db`-internal validation functions or duplicating their logic — not justified yet for a fixture-only feature. This is narrowed slightly by Decision 7 below (provider is pre-validated in the handler, so it no longer reaches this uniform-500 case), but the edge-provider-mismatch case still does.
7. **Provider is explicitly allowlist-validated in the handler before calling `ExecuteCloudPlanRun`, using a local literal set — not by exporting `evaluatorFor`.** Mirrors `RunScenario`'s own `mode` validation (`switch mode { case "posture","telemetry","lab": // ok; default: jsonError(...) }`) exactly: a plain, local `switch`/`case` against known values, same shape, same file convention, no new exports from package `db`. This still leaves the edge-provider-mismatch case (an edge whose `AccountScope` claims a different provider than the account) unreachable to pre-validate this cheaply — it still falls through to Decision 6's uniform `500`.
8. **Audit logging happens on both the success and failure paths**, extending `RunScenario`'s pattern (which only audits success) because the request explicitly asked for the run's outcome, not just its success, to be recorded. The call stays fire-and-forget per the established `auditLog` contract (Grounded Facts) — its own failure never alters the HTTP response. Because of the Grounded-Facts return-shape guarantee above, the handler's own `err == nil`/`err != nil` branch is already exactly the line between "ok" and "error" — there is no way for it to audit a failed execution as a success.
9. **No new execution timeout is added.** `r.Context()` flows into `ExecuteCloudPlanRun` and is already respected by every DB call it makes; `CloudPlan` itself has no I/O and cannot block. The server's existing global `WriteTimeout: 90s` is the de facto ceiling on this synchronous handler. This is a documented, deliberate limitation, not an oversight: once real discovery (slow, network-bound) replaces fixture data, this must be revisited — most likely via the async/poll pattern Decision 1 explicitly defers, not by bolting on an ad hoc per-route timeout now.

10. **`ExecuteCloudPlanRun` is widened to return the row's true persisted state alongside an error, whenever a row exists.** Resolved in favor of auditability: a `500` response or a failure audit entry with no way to correlate back to the row it describes is a real gap, not a formality. The fix is narrow and mechanical — see "Executor change" below — and does not touch sub-project #2's broader design: `InsertCloudRun`'s own failure (no row was ever created) still returns `nil`, and the error remains the sole authoritative signal that execution failed in every branch; a non-nil run is never evidence of success.

## Type changes (additive only — struct tags, no field renames, no behavior change)

`internal/cloudgraph/types.go`:
```go
type AccountScope struct {
	Provider  string `json:"provider"`
	AccountID string `json:"accountId"`
	TenantID  string `json:"tenantId,omitempty"`
	Region    string `json:"region,omitempty"`
}

type Provenance struct {
	Source        string        `json:"source"`
	ObservedAt    time.Time     `json:"observedAt"`
	CollectionAge time.Duration `json:"collectionAge"`
	Confidence    string        `json:"confidence"`
	ErrorDetail   string        `json:"errorDetail,omitempty"`
}

type CloudResource struct {
	CanonicalID  string            `json:"canonicalId"`
	Kind         string            `json:"kind"`
	AccountScope *AccountScope     `json:"accountScope,omitempty"`
	DisplayName  string            `json:"displayName,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	Provenance   *Provenance       `json:"provenance,omitempty"`
}

type CloudIdentity struct {
	CanonicalID  string            `json:"canonicalId"`
	Kind         string            `json:"kind"`
	AccountScope *AccountScope     `json:"accountScope,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	Provenance   *Provenance       `json:"provenance,omitempty"`
}

type Condition struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	EvaluatedAs string `json:"evaluatedAs"`
}

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
(`PathState`, `EvaluationResult`, `CloudPath`, `CloudHop` etc. already appear only in the *response* `Result` blob, which travels as an opaque `json.RawMessage` — already-shipped `cloudrun.CloudRun.Result` — so they need no tags to be exposed correctly; they're serialized once by `ExecuteCloudPlanRun`'s own `json.Marshal(path)` call using their exported field names, which is already how the stored `Result` column's JSON looks today and is not changing.)

`internal/cloudrun/types.go`:
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

`internal/db/cloudrun_executor.go`:
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
`InitiatedBy` is tagged `json:"-"` deliberately — it must never be settable from a request body under any field name; the handler always sets it itself, after decoding, from `auth.ClaimsFrom(r.Context())`.

## Executor change (`internal/db/cloudrun_executor.go`) — in scope for this sub-project

Decision 10 requires `ExecuteCloudPlanRun` to return the run's *true persisted state* — never a guess — alongside the error on every branch where `InsertCloudRun` already succeeded. A new unexported helper re-fetches the row rather than reconstructing it from local state, because the local `run` struct's `Status`/`Error` fields may not match what was actually written — most notably in the final-write-failure branch, where the best-effort `UpdateCloudRunStatus(ctx, pool, run.ID, status, resultJSON, "")` call itself can fail, leaving the row still `StatusRunning` in the database regardless of what `status` was locally computed to be (exactly the scenario sub-project #2's own `TestUpdateCloudRunStatus_PropagatesContextCancellation` proved at the primitive level — a failed write leaves the prior status untouched). Re-fetching is the only way to report that truthfully instead of asserting a status that was never actually written:

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

`ExecuteCloudPlanRun`'s four affected branches change from `return nil, err` / `return nil, marshalErr` to `return currentRunOrNil(ctx, pool, run.ID), err` (and `marshalErr` for the marshal branch). The `InsertCloudRun`-failure branch is unchanged (`return nil, err` — no row was ever created, so there is nothing to re-fetch). The success path (`return GetCloudRun(ctx, pool, run.ID)`) is unchanged — it was already doing the equivalent re-fetch.

This is the one piece of this sub-project that touches a file outside `internal/api`. It does not reopen sub-project #2's status semantics (Completed/Partial/Failed, the amendment's reversal, `statusForPath`) — those are untouched; this only changes what the function hands back on its existing error paths, which sub-project #2's own review explicitly left as "nil, acceptable, no caller needs the ID yet" — a judgment this sub-project's new caller now supersedes.

## API Surface

### `POST /api/cloud-runs`

Registered: `r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/cloud-runs", h.TriggerCloudPlanRun)` in `internal/api/routes.go`, alongside the existing `/api/scenarios/{id}/run` registration.

Handler (`internal/api/cloudrun_handlers.go`, new file):

```go
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
		// run is non-nil whenever a row actually exists (Decision 10) -- use
		// its ID for audit correlation when available, "" when InsertCloudRun
		// itself never created one.
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

Request body fields: `scenarioId` (string, required — a caller-chosen label stored on the row, not resolved against any registry per Decision 2), `account` (`{provider, accountId, tenantId?, region?}` — `provider` required and must be `aws`/`azure`/`gcp`), `edges` (array of `{source: {canonicalId, kind, accountScope?}, target: {canonicalId, kind, accountScope?, displayName?}, action, sourceType?, attributes?}`), `held` (array of canonical IDs the caller holds), `target` (canonical ID, required), `maxHops` (int).

Responses: `201` with the full `CloudRun` body on success (`run.Status` will be `Completed` or `Partial` per Grounded Facts — never `Failed`, since a `Failed` row is only ever paired with a non-nil `err`, which takes the `500` branch instead and returns no body). `400` for a missing/invalid `scenarioId`/`target`/`provider` (checked before any DB write). `500` for any other `ExecuteCloudPlanRun` error (Decision 6/7) — the client sees the error string but not a run ID, since `ExecuteCloudPlanRun` returns `nil` for the run pointer in every one of its error branches.

### `GET /api/cloud-runs`

Registered: `r.Get("/api/cloud-runs", h.ListCloudRuns)` — no additional permission wrapper beyond the route group's baseline authenticated-user middleware (Decision 3).

```go
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

A missing, malformed, zero, negative, or oversized `limit` silently falls back to the default of 20 (Grounded Facts) — never a `400`.

### `GET /api/cloud-runs/{id}`

Registered: `r.Get("/api/cloud-runs/{id}", h.GetCloudRun)` — same baseline-only gate as the list endpoint.

```go
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

## Testing

Integration tests against the real Postgres testcontainer (the same `sharedDB` pattern already established in `internal/db`'s own tests; API-layer handler tests in this codebase construct a `*Handler` directly against a real pool and call the handler function with an `httptest.NewRecorder()`, matching `run_scenario_gates_test.go`'s own pattern — confirm this exact harness shape when the plan is written, rather than assuming it, since this spec hasn't re-verified the handler-test scaffolding itself).

Required coverage, `internal/db` (executor-level, proving Decision 10 directly against real Postgres):
- Each of the four "row exists before the error" branches (`evaluatorFor` rejection via a still-DB-valid-but-handler-rejected case is not reachable here per sub-project #2's own Task 3 finding — this specifically covers `validateEdgesMatchProvider` rejection, marshal failure is untestable per sub-project #2's own documented boundary, and the final `UpdateCloudRunStatus` failure via a pre-canceled context on just that call) now returns a non-nil `*cloudrun.CloudRun` alongside the error, with `.ID` matching the row actually in the database.
- The final-write-failure branch specifically: the returned run's `Status` reflects what's *actually persisted* (`StatusRunning`, unchanged — matching sub-project #2's own `TestUpdateCloudRunStatus_PropagatesContextCancellation` finding), not the `status` value that failed to write — proving `currentRunOrNil` reports truth, not intent.
- `currentRunOrNil` returns `nil` (not a stale struct) when the re-fetch itself fails.
- The pre-existing `TestExecuteCloudPlanRun_MismatchedProviderEdgeMarksRowFailed` test (sub-project #2) is updated to assert directly on the returned run (`run.Status == StatusFailed`, `run.Error != ""`) in addition to its existing `db.ListCloudRuns` check — both must agree.

Required coverage, `internal/api` (HTTP-layer, integration tests against the real Postgres testcontainer, same `sharedDB` pattern; confirm the exact handler-test harness shape — e.g. `httptest.NewRecorder()` against a `*Handler` built with a real pool, matching `run_scenario_gates_test.go`'s own pattern — when the plan is written, rather than assuming it here):
- Successful trigger → `201`, response body is a populated `CloudRun` with `Status` `Completed` or `Partial`.
- Missing `scenarioId` → `400`. Missing `target` → `400`. Invalid `provider` (not `aws`/`azure`/`gcp`) → `400`, and no row is created (confirms the handler's pre-check runs before `ExecuteCloudPlanRun`/`InsertCloudRun` are ever reached).
- `InitiatedBy` in the persisted row reflects the authenticated caller's claim even when the request body sends a different value for it (proves the `json:"-"` tag plus the handler's post-decode overwrite both hold).
- A `validateEdgesMatchProvider`-triggered mismatch (valid account provider, an edge claiming a different one) → `500`, and the row is still persisted as `Failed` with `Error` set (proving the information isn't lost, just surfaced at `500` per Decision 6/7 — this is the one remaining case the handler's own `provider` pre-check cannot catch) — **and** the audit-log entry for this request carries that row's real ID, not an empty string, proving Decision 10's fix actually reaches the audit call.
- `GET /api/cloud-runs` round-trips a triggered run; `limit` parameter: a valid value is honored, an invalid/oversized one silently falls back to the default (no `400`).
- `GET /api/cloud-runs/{id}` round-trips a single run; a nonexistent ID → `404`.
- Both the success and failure paths of `TriggerCloudPlanRun` call `h.auditLog` with the correct `outcome` (`"ok"` vs `"error"`) — confirmed either via a test hook already used elsewhere for asserting on audit calls, or by querying `audit_logs` directly after a short wait, matching whatever this codebase's existing audit-log tests already do (ground this exactly when the plan is written).

## Out of scope (explicitly deferred)

- Async/poll execution pattern (Decision 1) — revisit once real, slow cloud discovery exists.
- A `scenario_id`-resolved, server-side graph-fixture registry (Decision 2) — a distinct, undecided sub-project.
- Exporting `evaluatorFor`/`validateEdgesMatchProvider` from package `db` for precise `400`s on every input class (Decision 6/7) — only the directly-pre-checkable `provider` case was pulled into the handler; the edge-provider-mismatch case still maps to `500`.
- A new, dedicated permission distinct from `auth.CanRunScenario` (Decision 3).
- Per-route execution timeouts / cancellation beyond what the global server `WriteTimeout` and `ctx` propagation already provide (Decision 9).
- Multi-account fan-out (`RunMultiAccount`) — sub-project #4.
- Hybrid AD-to-cloud / cloud-ransomware scenario wiring (`ComposeHybridPath`, `ExecuteCloudRansomwareScenario`) — sub-project #5.
- Real cloud discovery / live credentials — unchanged from sub-project #2's own deferral; everything in this spec is still fixture/caller-supplied-data only.
- Rate limiting on the trigger endpoint, pagination cursors beyond the single `limit` cap, and WebSocket/streaming result updates.
