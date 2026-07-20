# MaxPrivilege Execution Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator constrain a scenario run to a maximum privilege tier (e.g. "user only") so steps that require a higher tier are never dispatched to the agent — reported as a distinct, scored-out "skipped by policy" outcome instead of being silently attempted or omitted.

**Architecture:** A per-run `MaxPrivilege` option flows from `RunScenario`'s request body through `dispatchOpts` into `dispatchRun`, which filters `BuildSteps`' output using a pure tier-comparison function — mirroring the existing lab-only `Fidelity` filter that already runs at the exact same point in `dispatchRun`, right before `ScenarioCommand` is built. Steps that exceed the ceiling are never sent to the agent; instead, the server synthesizes a `models.SimulationResult` for each one via the existing `scenario.Interpret` function (already recognizes a `"SKIP:"` marker uniformly across every framework) and persists them into a new, dispatch-time-only column (`scenario_runs.policy_skipped_results`) that survives the agent's own result submission — which, by an existing, deliberate design documented in `SubmitScenarioResult`, *replaces* `scenario_runs.results` wholesale on every submission (idempotent retry handling). `SubmitScenarioResult` merges the two columns together before scoring, so every existing report/coverage/scoring code path sees the policy-skipped steps as ordinary (already-excluded-from-scoring) `Skipped` entries with zero changes required there.

**Tech Stack:** Go, Postgres (`pgx/v5`), the existing `internal/scenario`/`internal/api`/`internal/models` packages.

## Global Constraints

- **Tier order:** `user < admin < system`. `MaxPrivilege` is a ceiling — a step whose `RequiresPriv` is at or below the ceiling runs; anything above is filtered out. Empty `MaxPrivilege` (`""`) means unconstrained (today's exact behavior).
- **Only `RunScenario` is wired to accept `MaxPrivilege` from a request** (the primary ad-hoc "click Run" endpoint). The other 3 `dispatchOpts{}` call sites (campaign fan-out, adversary-template dispatch) are **not modified** — `dispatchOpts` is one shared struct, so they simply leave the new field at its zero value (`""`, unconstrained), byte-identical to current behavior. Wiring those is an explicit, separate future follow-up, not part of this plan.
- **Do not touch `scenario_runs.results` at dispatch time.** `SubmitScenarioResult`'s own code comment documents that the agent "always submits a COMPLETE snapshot... so REPLACE, never append" — a deliberate idempotent-retry design. Writing synthetic skip results into that column at dispatch time would be silently wiped out the moment the agent's real submission lands. Policy-skip results live in a **new, separate column** (`policy_skipped_results`), written once at dispatch time and never touched again; `SubmitScenarioResult` merges it in at submission time instead.
- **A run where every step gets filtered out must complete immediately, not hang or hard-fail.** Unlike the existing lab-only filter (which hard-fails the whole run — `handlers.go:1072-1076` — if literally nothing survives), an all-filtered privilege-constrained run is a legitimate, reportable outcome ("nothing was executable under this policy"). `dispatchRun` must detect this and mark the run `'completed'` directly, skipping the WebSocket dispatch entirely — there's nothing to send, and waiting for an agent submission that will never arrive would hang the run.
- **No report-template changes in this plan.** The existing "Execution Context (Privilege)" table (`internal/reporting/html.go`) and its builder (`internal/reporting/engine.go`) already render any `Skipped`-tagged `SimulationResult` correctly — policy-skipped steps show up there today, unmodified, just not yet broken out by the new `SkipReason` field. Extending that table is a separate, later plan.
- **No `ExecutionPolicy` struct.** Only `MaxPrivilege` exists as a capability today — it's plumbed as a plain `string`, not wrapped in a larger policy object with placeholder fields for future constraints (NetworkIsolation, AllowReboot, etc.) that don't exist yet. Introduce that wrapper when a second constraint is actually built.
- Run all `go` commands from `orchestrator/`. Docker Desktop is available on Windows this session — container-backed tests run directly, no VM needed (see `project_docker_windows` memory).

---

### Task 1: Tier comparison + `SkipReason` field

**Files:**
- Modify: `orchestrator/internal/scenario/types.go` (add a tier-comparison function near `PrivSpec`)
- Modify: `orchestrator/internal/models/schema.go:36-70` (`SimulationResult` struct)
- Test: `orchestrator/internal/scenario/types_test.go` (new file — no existing test file for `types.go` in this package)

**Interfaces:**
- Produces: `scenario.PrivilegeExceeds(stepTier, maxTier string) bool` — pure function, no I/O. `models.SimulationResult.SkipReason string` (new field) and `models.SkipReasonPolicyPrivilege` (well-known constant value `"policy-privilege"`).

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/scenario/types_test.go`:

```go
package scenario

import "testing"

func TestPrivilegeExceeds(t *testing.T) {
	cases := []struct {
		name     string
		stepTier string
		maxTier  string
		want     bool
	}{
		{"empty maxTier means unconstrained", "admin", "", false},
		{"empty stepTier (legacy/unannotated) never exceeds", "", "user", false},
		{"user step under user ceiling", "user", "user", false},
		{"admin step under admin ceiling", "admin", "admin", false},
		{"admin step exceeds user ceiling", "admin", "user", true},
		{"system step exceeds admin ceiling", "system", "admin", true},
		{"system step under system ceiling", "system", "system", false},
		{"user step never exceeds admin ceiling", "user", "admin", false},
		{"unrecognized stepTier treated as user (lowest)", "bogus", "user", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := PrivilegeExceeds(c.stepTier, c.maxTier); got != c.want {
				t.Errorf("PrivilegeExceeds(%q, %q) = %v, want %v", c.stepTier, c.maxTier, got, c.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestPrivilegeExceeds -v`
Expected: FAIL — `PrivilegeExceeds` doesn't exist yet (compile error).

- [ ] **Step 3: Add `PrivilegeExceeds` to `types.go`**

In `orchestrator/internal/scenario/types.go`, immediately after the `PrivSpec.IsZero()` method (after the closing `}` of `func (p PrivSpec) IsZero() bool { ... }`), add:

```go

// privilegeTierRank orders privilege tiers from lowest to highest. Unrecognized
// values (including "" — unannotated/legacy) rank as the lowest tier, "user" —
// an unknown or missing tier is never treated as more privileged than it
// actually is, so a MaxPrivilege ceiling never accidentally excludes it.
var privilegeTierRank = map[string]int{
	"user":   0,
	"admin":  1,
	"system": 2,
}

// PrivilegeExceeds reports whether stepTier is strictly above the maxTier
// ceiling. An empty maxTier means no ceiling (never exceeds). Used to decide
// whether a step must be filtered out of a run under an execution policy's
// MaxPrivilege constraint.
func PrivilegeExceeds(stepTier, maxTier string) bool {
	if maxTier == "" {
		return false
	}
	return privilegeTierRank[stepTier] > privilegeTierRank[maxTier]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestPrivilegeExceeds -v`
Expected: PASS (all 9 subtests).

- [ ] **Step 5: Add `SkipReason` to `SimulationResult`**

In `orchestrator/internal/models/schema.go`, the current field block ending with `ExecutedAs`:

```go
	// ExecutedAs records the actual privilege tier used: "user" | "user→admin" |
	// "admin" | "system" | "" (empty = legacy unannotated step).
	ExecutedAs string `json:"executedAs,omitempty"`
```

gets a new field added immediately after it:

```go
	// ExecutedAs records the actual privilege tier used: "user" | "user→admin" |
	// "admin" | "system" | "" (empty = legacy unannotated step).
	ExecutedAs string `json:"executedAs,omitempty"`
	// SkipReason distinguishes WHY a Result=ResultSkipped entry was skipped,
	// matching the lightweight plain-string classification style already used
	// by Framework/DetectionVerdict/CleanupVerdict/ExecutedAs on this struct.
	// Empty for all pre-existing skip causes (missing payload, technique not in
	// local store, etc.) — only set for skips this platform itself decided to
	// make, not ones discovered by parsing agent output.
	SkipReason string `json:"skipReason,omitempty"`
```

- [ ] **Step 6: Add the well-known constant**

Immediately after the `SimulationResult` struct's closing `}` in the same file, add:

```go

// SkipReasonPolicyPrivilege marks a SimulationResult synthesized server-side
// because a step's RequiresPriv exceeded the run's MaxPrivilege execution
// policy — the step was never dispatched to the agent at all.
const SkipReasonPolicyPrivilege = "policy-privilege"
```

- [ ] **Step 7: Verify the whole build still compiles**

Run: `cd orchestrator && go build ./... && go vet ./internal/scenario/... ./internal/models/...`
Expected: clean (no output).

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/scenario/types.go orchestrator/internal/scenario/types_test.go orchestrator/internal/models/schema.go
git commit -m "feat(policy): privilege tier comparison + SkipReason field for synthesized skips"
git push
```

---

### Task 2: Schema — `policy_skipped_results` column

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (the `scenario_runs` migration block — find via the existing `ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS tenant_id ...` line already in this file from the multi-tenancy work, and add the new column near the other `scenario_runs` ALTERs)

**Interfaces:**
- Produces: `scenario_runs.policy_skipped_results jsonb NOT NULL DEFAULT '[]'` — consumed by Task 3 (write) and Task 4 (read).

- [ ] **Step 1: Find the exact insertion point**

Run: `cd orchestrator && grep -n "ALTER TABLE scenario_runs" internal/db/postgres.go`

This shows every existing idempotent migration for the `scenario_runs` table (e.g. the `tenant_id` column added during Phase 7). Add the new column as one more entry in that same list, immediately after the last existing `ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS ...` line found by the grep above.

- [ ] **Step 2: Add the migration statement**

Insert this line into the `EnsureSchema` statement slice, right after the last `scenario_runs` ALTER found in Step 1:

```go
		// policy_skipped_results holds SimulationResults the server itself
		// synthesized at dispatch time for steps a run's MaxPrivilege execution
		// policy excluded before ever contacting the agent. Written once at
		// dispatch, never touched again — kept separate from `results` (which
		// the agent's own submission always REPLACES wholesale) so a later
		// agent submission can never silently wipe these out. Merged into
		// `results` by SubmitScenarioResult before scoring/persisting.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS policy_skipped_results jsonb NOT NULL DEFAULT '[]'`,
```

- [ ] **Step 3: Verify the migration compiles and applies**

Run: `cd orchestrator && go build ./... && go vet ./internal/db/...`
Expected: clean. (The migration itself is verified live in Task 3's integration test, which boots a real Postgres via `sharedDB.RunWithPool` and exercises `EnsureSchema` as part of test setup.)

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/db/postgres.go
git commit -m "feat(policy): add scenario_runs.policy_skipped_results column"
git push
```

---

### Task 3: Dispatch-time filtering + synthesis + empty-after-filter completion

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`dispatchOpts` struct at line 848, `RunScenario`'s request struct and its `dispatchOpts{}` construction, `dispatchRun`'s step-filtering section around line 1059)
- Test: `orchestrator/internal/api/run_scenario_integration_test.go` (existing file — extend with new tests matching its established fixture pattern)

**Interfaces:**
- Consumes: `scenario.PrivilegeExceeds` (Task 1), `models.SkipReasonPolicyPrivilege` (Task 1), `scenario_runs.policy_skipped_results` (Task 2), `scenario.Interpret(step Step, result ExecResult) models.SimulationResult` (already exists, `internal/scenario/interpreter.go`).
- Produces: `dispatchOpts.MaxPrivilege string`. `RunScenario` accepts `maxPrivilege` in its JSON request body.

**Why the synthetic `Step`/`ExecResult` shape:** `ScenarioStep` (the wire/runtime type `BuildSteps` returns) only carries `RequiresPriv` as a flattened `string`, not the richer `scenario.PrivSpec`. `Interpret`'s first argument is a `scenario.Step` (the YAML-declared type). Build a minimal one — `Step{TechniqueID: st.TechniqueID, Name: st.Name, Framework: st.Framework, RequiresPriv: PrivSpec{Minimum: st.RequiresPriv}}` — exactly the same simplification `SubmitScenarioResult`'s own `stepMap` overlay already does for dynamically-built ART/Caldera steps (`handlers.go:1609-1615`, confirmed: it only reconstructs `TechniqueID`/`Name`/`Framework` too).

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/run_scenario_integration_test.go` (same package `api`, same imports already present):

```go
func TestRunScenarioIntegration_MaxPrivilegeFiltersStep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "user-step", TechniqueID: "T1059", Framework: "custom", Command: "echo user",
				RequiresPriv: scenario.PrivSpec{Minimum: "user"}},
			{Name: "admin-step", TechniqueID: "T1548", Framework: "custom", Command: "echo admin",
				RequiresPriv: scenario.PrivSpec{Minimum: "admin"}},
		}
		sc, engine := minimalLiveScenario(t, "int-maxpriv-mixed", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-maxpriv-mixed"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true, "maxPrivilege": "user",
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		runID, _ := resp["runId"].(string)
		if runID == "" {
			t.Fatalf("resp = %+v, want a non-empty runId", resp)
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "user-step" {
			t.Fatalf("cmd.Steps = %+v, want exactly [user-step] (admin-step must be filtered)", cmd.Steps)
		}

		var skippedJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT policy_skipped_results FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&skippedJSON); err != nil {
			t.Fatalf("read policy_skipped_results: %v", err)
		}
		var skipped []models.SimulationResult
		if err := json.Unmarshal(skippedJSON, &skipped); err != nil {
			t.Fatalf("unmarshal policy_skipped_results: %v", err)
		}
		if len(skipped) != 1 {
			t.Fatalf("policy_skipped_results = %d entries, want 1", len(skipped))
		}
		if skipped[0].Result != models.ResultSkipped {
			t.Errorf("skipped[0].Result = %q, want %q", skipped[0].Result, models.ResultSkipped)
		}
		if skipped[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Errorf("skipped[0].SkipReason = %q, want %q", skipped[0].SkipReason, models.SkipReasonPolicyPrivilege)
		}
		if skipped[0].Technique.ID != "T1548" {
			t.Errorf("skipped[0].Technique.ID = %q, want T1548", skipped[0].Technique.ID)
		}
	})
}

func TestRunScenarioIntegration_MaxPrivilegeAllFilteredCompletesImmediately(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "admin-step", TechniqueID: "T1548", Framework: "custom", Command: "echo admin",
				RequiresPriv: scenario.PrivSpec{Minimum: "admin"}},
		}
		sc, engine := minimalLiveScenario(t, "int-maxpriv-all", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-maxpriv-all"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true, "maxPrivilege": "user",
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		runID, _ := resp["runId"].(string)
		if runID == "" {
			t.Fatalf("resp = %+v, want a non-empty runId", resp)
		}

		var status string
		var resultsJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT status, results FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&status, &resultsJSON); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if status != "completed" {
			t.Fatalf("status = %q, want completed (run should finish immediately, no agent round-trip)", status)
		}
		var results []models.SimulationResult
		_ = json.Unmarshal(resultsJSON, &results)
		if len(results) != 1 || results[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Fatalf("results = %+v, want exactly 1 policy-privilege skip", results)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRunScenarioIntegration_MaxPrivilege' -v`
Expected: FAIL — `maxPrivilege` isn't read from the request yet, so both tests dispatch unfiltered (first test: `cmd.Steps` has 2 entries, not 1; second test: the run dispatches to the agent instead of completing immediately, so `fake` never gets disconnected cleanly and/or `status` stays `'running'`).

- [ ] **Step 3: Add `MaxPrivilege` to `dispatchOpts`**

In `orchestrator/internal/api/handlers.go`, the current struct:

```go
type dispatchOpts struct {
	Mode         string // already-normalized: posture | telemetry | lab
	ConfirmLive  bool
	ConfirmLab   bool
	Reason       string
	Techniques   []string
	Abilities    []string
	Steps        []int
	Checks       []string
	CampaignID   string                // "" for ad-hoc single runs
	InitiatedBy  *string               // requesting user id (nil if unauthenticated)
	VariantDepth scenario.VariantDepth // "none"|"quick"|"standard"|"full"; "" == "none"
	RunLabel     string                // overrides sc.Name in scenario_runs.name when set
}
```

becomes:

```go
type dispatchOpts struct {
	Mode         string // already-normalized: posture | telemetry | lab
	ConfirmLive  bool
	ConfirmLab   bool
	Reason       string
	Techniques   []string
	Abilities    []string
	Steps        []int
	Checks       []string
	CampaignID   string                // "" for ad-hoc single runs
	InitiatedBy  *string               // requesting user id (nil if unauthenticated)
	VariantDepth scenario.VariantDepth // "none"|"quick"|"standard"|"full"; "" == "none"
	RunLabel     string                // overrides sc.Name in scenario_runs.name when set
	// MaxPrivilege is an execution-policy ceiling: "" (default, unconstrained) |
	// "user" | "admin" | "system". Steps whose RequiresPriv exceeds this tier are
	// filtered out before dispatch — see dispatchRun's policy filter.
	MaxPrivilege string
}
```

- [ ] **Step 4: Add `maxPrivilege` to `RunScenario`'s request struct and pass it through**

The current request struct in `RunScenario`:

```go
	var req struct {
		AgentID      string                `json:"agentId"`
		Mode         string                `json:"mode"`         // posture (default) | telemetry | lab
		ConfirmLive  bool                  `json:"confirmLive"`  // required ack for any live run (telemetry/lab)
		ConfirmLab   bool                  `json:"confirmLab"`   // second-stage approval, required for lab mode
		Reason       string                `json:"reason"`       // optional operator justification (audited)
		Techniques   []string              `json:"techniques"`   // optional ART technique subset
		Abilities    []string              `json:"abilities"`    // optional Caldera ability subset
		Steps        []int                 `json:"steps"`        // optional step subset — indices into scenario step list
		Checks       []string              `json:"checks"`       // optional posture-check subset (local_check scenarios)
		VariantDepth scenario.VariantDepth `json:"variantDepth"` // ""|"none"|"quick"|"standard"|"full"
		RunLabel     string                `json:"runLabel"`     // optional override for scenario_runs.name
	}
```

becomes:

```go
	var req struct {
		AgentID      string                `json:"agentId"`
		Mode         string                `json:"mode"`         // posture (default) | telemetry | lab
		ConfirmLive  bool                  `json:"confirmLive"`  // required ack for any live run (telemetry/lab)
		ConfirmLab   bool                  `json:"confirmLab"`   // second-stage approval, required for lab mode
		Reason       string                `json:"reason"`       // optional operator justification (audited)
		Techniques   []string              `json:"techniques"`   // optional ART technique subset
		Abilities    []string              `json:"abilities"`    // optional Caldera ability subset
		Steps        []int                 `json:"steps"`        // optional step subset — indices into scenario step list
		Checks       []string              `json:"checks"`       // optional posture-check subset (local_check scenarios)
		VariantDepth scenario.VariantDepth `json:"variantDepth"` // ""|"none"|"quick"|"standard"|"full"
		RunLabel     string                `json:"runLabel"`     // optional override for scenario_runs.name
		MaxPrivilege string                `json:"maxPrivilege"` // ""|"user"|"admin"|"system" — execution policy ceiling
	}
```

And the `dispatchOpts{}` construction:

```go
	runID, skip, err := h.dispatchRun(r.Context(), sc, req.AgentID, dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		InitiatedBy: initiatedBy, VariantDepth: req.VariantDepth, RunLabel: req.RunLabel,
	})
```

becomes:

```go
	runID, skip, err := h.dispatchRun(r.Context(), sc, req.AgentID, dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		InitiatedBy: initiatedBy, VariantDepth: req.VariantDepth, RunLabel: req.RunLabel,
		MaxPrivilege: req.MaxPrivilege,
	})
```

- [ ] **Step 5: Add the policy-skip synthesis helper**

Add this new function to `orchestrator/internal/api/handlers.go`, near `dispatchRun` (e.g. immediately before it):

```go
// synthesizePolicySkipResult builds the SimulationResult for a step that was
// never dispatched to the agent because its RequiresPriv exceeded the run's
// MaxPrivilege execution policy. Reuses the existing scenario.Interpret path
// (via a constructed "SKIP:" marker, the same convention every framework's
// interpreter already recognizes) so severity/threat-impact/remediation
// lookups are identical to any other skip — only SkipReason distinguishes it.
func synthesizePolicySkipResult(st scenario.ScenarioStep, maxPrivilege string) models.SimulationResult {
	step := scenario.Step{
		TechniqueID: st.TechniqueID,
		Name:        st.Name,
		Framework:   st.Framework,
		RequiresPriv: scenario.PrivSpec{Minimum: st.RequiresPriv},
	}
	result := scenario.ExecResult{
		TaskID: st.TaskID,
		Stdout: fmt.Sprintf("SKIP: requires %s privilege, execution policy caps at %s", st.RequiresPriv, maxPrivilege),
	}
	sim := scenario.Interpret(step, result)
	sim.SkipReason = models.SkipReasonPolicyPrivilege
	return sim
}
```

- [ ] **Step 6: Wire the filter into `dispatchRun`, right after the lab-only fidelity filter**

The current lab-only block in `dispatchRun`:

```go
	// Dynamically-built Caldera abilities carry their own fidelity tag. Payload-
	// bearing abilities (e.g. emu APT chains) are "lab-only" and must never fire
	// outside lab mode — drop them in posture/telemetry.
	if o.Mode != "lab" {
		kept := make([]scenario.ScenarioStep, 0, len(steps))
		for _, st := range steps {
			if st.Fidelity == "lab-only" {
				continue
			}
			kept = append(kept, st)
		}
		dropped := len(steps) - len(kept)
		steps = kept
		if dropped > 0 {
			log.Printf("[scenario] run %s: dropped %d lab-only step(s) for mode=%s", runID, dropped, o.Mode)
		}
		if len(steps) == 0 {
			_, _ = h.db.Exec(context.Background(),
				`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
			return "", "", fmt.Errorf("every step in this scenario is lab-only (ships real payloads) — run it in lab mode against an isolated range")
		}
	}
```

Add the new privilege-ceiling filter immediately after this block (still before the variant-expansion section):

```go
	// Execution-policy privilege ceiling: steps that require a higher tier than
	// MaxPrivilege are never dispatched. Each one gets a synthesized, scored-out
	// Skipped result instead of being attempted — mirrors the lab-only filter
	// above, but unlike it, filtering out EVERY step here is a legitimate outcome
	// ("nothing was executable under this policy"), not a hard failure.
	if o.MaxPrivilege != "" {
		kept := make([]scenario.ScenarioStep, 0, len(steps))
		var policySkipped []models.SimulationResult
		for _, st := range steps {
			if scenario.PrivilegeExceeds(st.RequiresPriv, o.MaxPrivilege) {
				policySkipped = append(policySkipped, synthesizePolicySkipResult(st, o.MaxPrivilege))
				continue
			}
			kept = append(kept, st)
		}
		steps = kept
		if len(policySkipped) > 0 {
			log.Printf("[scenario] run %s: %d step(s) exceeded MaxPrivilege=%s, skipped by policy",
				runID, len(policySkipped), o.MaxPrivilege)
			skippedJSON, _ := json.Marshal(policySkipped)
			if _, err := h.db.Exec(context.Background(),
				`UPDATE scenario_runs SET policy_skipped_results = $1 WHERE id = $2`, skippedJSON, runID,
			); err != nil {
				return "", "", fmt.Errorf("persist policy-skipped results: %w", err)
			}
		}
		if len(steps) == 0 {
			// Every step was excluded by policy — a legitimate, reportable
			// outcome, not a failure. Complete the run immediately using only
			// the synthesized results; there is nothing to dispatch, and
			// waiting for an agent submission that will never arrive would
			// hang the run.
			skippedJSON, _ := json.Marshal(policySkipped)
			_, err := h.db.Exec(context.Background(),
				`UPDATE scenario_runs SET status = 'completed', results = $1::jsonb, completed_at = NOW() WHERE id = $2`,
				skippedJSON, runID,
			)
			if err != nil {
				return "", "", fmt.Errorf("complete all-policy-skipped run: %w", err)
			}
			return runID, "", nil
		}
	}
```

- [ ] **Step 7: Run the new tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRunScenarioIntegration_MaxPrivilege' -v`
Expected: both PASS.

- [ ] **Step 8: Run the full existing dispatch/run test suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRunScenarioIntegration|TestClassifyAgentOS' -v`
Expected: all PASS, including the 5 pre-existing `TestRunScenarioIntegration_*` tests (regression check — confirms the lab-only filter, OS-mismatch, subset-selection, and busy/offline gating all still work unchanged when `MaxPrivilege` is empty).

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/run_scenario_integration_test.go
git commit -m "feat(policy): dispatch-time MaxPrivilege filtering with synthesized policy-skip results"
git push
```

---

### Task 4: Merge `policy_skipped_results` into the agent's submission

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`SubmitScenarioResult`)
- Test: `orchestrator/internal/api/submit_scenario_result_test.go` (existing file)

**Interfaces:**
- Consumes: `scenario_runs.policy_skipped_results` (Task 2, Task 3).
- Produces: `scenario_runs.results` now contains both the agent's real results and any policy-skipped ones, on every submission (idempotent across retries).

- [ ] **Step 1: Confirm the existing test file's fixture pattern**

`orchestrator/internal/api/submit_scenario_result_test.go` already has an existing test, `TestSubmitScenarioResult_ResultsInterpretedViaSteps`, that establishes the exact pattern this new test follows:

```go
func TestSubmitScenarioResult_ResultsInterpretedViaSteps(t *testing.T) {
	...
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"}}
		sc, engine := minimalLiveScenario(t, "sc-interp", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		seedRunRow(t, pool, "interp-run", sc.ID, "agent-interp", "running")

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "interp-run", ScenarioID: sc.ID, AgentID: "agent-interp",
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("T1059", "step-0"), ExitCode: 0, Stdout: "PASS: ok"}},
		})

		results := readRunResults(t, pool, "interp-run")
		...
	})
}
```

It relies on three helpers already defined in package `api`:
- `New(pool, ws.NewHub(), engine, "")` — the empty string 4th arg is the agent secret; every existing test in this file passes `""`, making MAC/auth verification a no-op, so there is no separate "signed request" helper to find.
- `seedRunRow(t *testing.T, pool *pgxpool.Pool, runID, scenarioID, agentID, status string)` (`internal/api/result_ingestion_helpers_test.go:72`) — seeds the `agents` row then inserts the `scenario_runs` row.
- `submitResultOK(t *testing.T, h *Handler, raw scenario.RawRunResult)` (`submit_scenario_result_test.go:19`) — builds the request body, calls `h.SubmitScenarioResult`, and asserts HTTP 200.
- `readRunResults(t *testing.T, pool *pgxpool.Pool, runID string) []models.SimulationResult` (`submit_scenario_result_test.go:29`) — reads and unmarshals `scenario_runs.results`.

- [ ] **Step 2: Write the failing test**

Add to `orchestrator/internal/api/submit_scenario_result_test.go`:

```go
func TestSubmitScenarioResult_MergesPolicySkippedResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "int-submit-merge")
		h := New(pool, ws.NewHub(), engine, "")
		runID := "run-merge-test"
		agentID := "agent-merge-test"
		seedRunRow(t, pool, runID, sc.ID, agentID, "running")

		policySkipped := []models.SimulationResult{
			{ID: "policy-skip-1", Result: models.ResultSkipped, SkipReason: models.SkipReasonPolicyPrivilege,
				Technique: models.AttackTechnique{ID: "T1548"}},
		}
		skippedJSON, _ := json.Marshal(policySkipped)
		if _, err := pool.Exec(context.Background(),
			`UPDATE scenario_runs SET policy_skipped_results = $1 WHERE id = $2`, skippedJSON, runID,
		); err != nil {
			t.Fatalf("seed policy_skipped_results: %v", err)
		}

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: sc.ID, AgentID: agentID,
			Results: []scenario.ExecResult{{TaskID: "real-1", Stdout: "the operation completed successfully", ExitCode: 0}},
		})

		results := readRunResults(t, pool, runID)
		if len(results) != 2 {
			t.Fatalf("results = %d entries, want 2 (1 real + 1 policy-skipped): %+v", len(results), results)
		}
		var sawPolicySkip bool
		for _, r := range results {
			if r.SkipReason == models.SkipReasonPolicyPrivilege {
				sawPolicySkip = true
			}
		}
		if !sawPolicySkip {
			t.Fatalf("results = %+v, missing the policy-skipped entry", results)
		}
	})
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitScenarioResult_MergesPolicySkippedResults -v`
Expected: FAIL — `results` has only 1 entry (the real one), not 2.

- [ ] **Step 4: Add the merge**

In `orchestrator/internal/api/handlers.go`, inside `SubmitScenarioResult`, find the block that computes `simResults` from `raw.Results` (the `else` branch of the `if len(raw.Checks) > 0` conditional):

```go
	} else {
		simResults = make([]models.SimulationResult, 0, len(raw.Results))
		for _, execResult := range raw.Results {
			step, found := stepMap[execResult.TaskID]
			if !found {
				step = scenario.Step{Framework: "custom"}
			}
			simResults = append(simResults, scenario.Interpret(step, execResult))
		}
	}
```

Add the merge immediately after this whole `if/else` block (still before `status := "completed"`):

```go
	// Merge in any steps the server itself excluded before dispatch under a
	// MaxPrivilege execution policy — persisted once at dispatch time into a
	// separate column specifically so this merge survives every retry of this
	// handler without needing to touch the agent's own REPLACE semantics above.
	var policySkippedJSON []byte
	if err := h.db.QueryRow(r.Context(),
		`SELECT policy_skipped_results FROM scenario_runs WHERE id = $1`, raw.RunID,
	).Scan(&policySkippedJSON); err == nil && len(policySkippedJSON) > 0 {
		var policySkipped []models.SimulationResult
		if json.Unmarshal(policySkippedJSON, &policySkipped) == nil {
			simResults = append(simResults, policySkipped...)
		}
	}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitScenarioResult_MergesPolicySkippedResults -v`
Expected: PASS.

- [ ] **Step 6: Run the full existing SubmitScenarioResult suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitScenarioResult -v`
Expected: all pre-existing tests in this file still PASS (regression check — confirms a run with an EMPTY `policy_skipped_results` — the default `'[]'` — behaves identically to before this change).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/submit_scenario_result_test.go
git commit -m "feat(policy): merge policy_skipped_results into scenario_runs.results on submission"
git push
```

---

### Task 5: Full verification

**Files:** none — verification only.

- [ ] **Step 1: Full build/vet/gofmt**

Run: `cd orchestrator && go build ./... && go vet ./... && gofmt -l internal/scenario/types.go internal/scenario/types_test.go internal/models/schema.go internal/db/postgres.go internal/api/handlers.go internal/api/run_scenario_integration_test.go internal/api/submit_scenario_result_test.go`
Expected: build/vet clean; `gofmt -l` prints nothing (or only CRLF-line-ending noise on files this Windows checkout hasn't normalized — confirmed cosmetic-only via `git cat-file` in prior sessions; do not treat that alone as a real formatting failure, see `project_docker_windows` memory).

- [ ] **Step 2: Full `internal/scenario`, `internal/models`, and `internal/api` suites**

Run:
```bash
cd orchestrator
go test ./internal/scenario/... -v
go test ./internal/models/... -v
go test ./internal/api/... 2>&1 | tail -20
```
Expected: `internal/scenario` and `internal/models` fully green (unit tests, fast). `internal/api` ends with `ok` — this package takes several minutes; if anything unrelated fails, re-run that specific test in isolation before treating it as a real regression (this session's `internal/auth`/`internal/connector` full-suite-only flakes were confirmed non-reproducible in isolation).

- [ ] **Step 3: Manual end-to-end confirmation (optional but recommended)**

Using the same dev-Postgres-container + `go run ./cmd/server` setup from earlier this session: start a live scenario run against a real connected agent (or the fake-agent pattern isn't available outside tests, so this step needs a real or simulated agent connection) with `maxPrivilege: "user"` in the `RunScenario` request body, and confirm via `psql` that `scenario_runs.policy_skipped_results` gets populated for any admin-tier steps, and that the final `results` column (read after the agent submits) contains both the real and synthesized entries. Skip this step if no agent is readily available — Task 3 and Task 4's integration tests already prove the mechanism end-to-end against a real Postgres and a real (fake) WebSocket agent connection.

- [ ] **Step 4: Report results to the user**

Summarize: test results, and note explicitly what's still open — report-template enhancement (the "Skipped by policy" breakdown in the existing Privilege Assessment section) is a deliberate, separate follow-up plan, and `MaxPrivilege` is not yet wired into the campaign launcher or adversary-template dispatch paths.
