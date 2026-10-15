# TCF Phase 6 — Automated Validation Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give TCF-originated content a real, evidence-backed EXECUTION-level validation step — dispatched to a factory-owned lab agent a customer target can never be substituted for, re-checked for safety immediately before it runs, recorded honestly (pass/fail/inconclusive, never a fabricated pass), and required before TCF-originated content can be published.

**Architecture:** Three small, surgical changes to existing code (`dispatchRun` ownership enforcement, a dispatch-time safety re-check, a publish-gate guard inside `Registry.Transition`), plus one new package (`internal/validationlab`) implementing a periodic scan→claim→dispatch→poll→resolve cycle against a single persistent, pre-registered lab agent. No new HTTP endpoints; no new UI.

**Tech Stack:** Go, PostgreSQL (pgx/v5), the existing `internal/contentregistry`, `internal/api` (dispatchRun), and `internal/scenario` packages.

**Spec:** `docs/superpowers/specs/2026-10-14-tcf-phase6-validation-lab-design.md`

## Global Constraints

- v1 uses exactly one persistent, pre-registered lab agent — no ephemeral provisioning (spec §2.1).
- EXECUTION-level validation only — no TELEMETRY/DETECTION in this plan (spec §1.4, §4).
- `RegisterLocalApproved` (`internal/contentregistry/intake.go:215-253`) and the operator "save" flow are never touched (spec §1.6, §2.5).
- `analyzeArtifact`, `safetyVerdict`, `combinatorialRisk`, and the Phase 5 tactic-pair catalog are reused unmodified — no changes to their logic (spec §2.3, §4).
- `combinatorialRisk` is **not** re-run at dispatch time (spec §2.3, §4) — only `analyzeArtifact`'s structural + per-step safety verdict.
- The new dispatch mode and execution kind are never exposed through any HTTP request-validation path — internal Go-level calls only.
- No retry backoff or attempt cap for repeatedly-failing validation in this plan (spec §4, explicit direction).
- Every `content_validations` write at EXECUTION level with `outcome='PASS'` must carry a real, non-null `run_id` — enforced by the existing DB CHECK (`content_registry_schema.go:145`); never write around it.

## Review Focus

- A content version dispatched for validation whose current technique set would now fail `analyzeArtifact`'s structural/per-step safety re-check — confirm refusal before dispatch, with a `content_safety_verdicts(classifier="dispatch-recheck")` row whose `detail` is traceable, and no `content_validations` row.
- A dispatch attempt against the factory-lab agent using one of the three *existing* customer-facing modes (`posture`/`telemetry`/`lab`) — confirm refusal, proving ownership enforcement works in both directions.
- A dispatch failure (agent offline/busy) that never produces a `run_id` — confirm the `content_validations` write with `run_id=NULL, outcome=ERROR` succeeds against the real database CHECK constraint, not a mocked store.
- A `VALIDATING` row whose dispatched run already completed before the orchestrator process restarts — confirm the next scan resolves it correctly using only durable state.
- `RegisterLocalApproved`'s existing behavior — confirm this plan's diff never touches `intake.go:215-253` and its regression test still passes.

---

### Task 1: Schema migration and new constants

**Files:**
- Modify: `internal/db/postgres.go:84` (agents table idempotent migrations)
- Modify: `internal/db/content_registry_schema.go:158-164` (scenario_runs execution_kind constraint)
- Modify: `internal/contentregistry/types.go:47-63` (Kind and Actor constants)
- Modify: `config/config.go` (new config fields)
- Test: `internal/db/content_registry_schema_test.go`

**Interfaces:**
- Produces: `contentregistry.KindFactoryValidation = "factory_validation"`, `contentregistry.ActorValidationLab = "validation:lab"` — both consumed by Task 2 (dispatchRun), Task 5/6 (validationlab orchestrator).
- Produces: `agents.is_factory_lab boolean` column — consumed by Task 2.
- Produces: `config.Config.ValidationLabAgentID string`, `config.Config.ValidationLabPollInterval time.Duration` — consumed by Task 7.

- [ ] **Step 1: Write the failing test for the new `execution_kind` value and `is_factory_lab` column**

Add to `internal/db/content_registry_schema_test.go`, right after `TestScenarioRuns_ContentKindRequiresVersion` (the existing test at line 214 already proves `'bogus'` is rejected and `'legacy'` is the default — this new test proves the new value is accepted):

```go
func TestScenarioRuns_FactoryValidationKindAccepted(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ('a9','h')`); err != nil {
			t.Fatalf("agent: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (scenario_id, agent_id, execution_kind) VALUES ('x','a9','factory_validation')`); err != nil {
			t.Fatalf("factory_validation kind must be accepted: %v", err)
		}
	})
}

func TestAgentsSchema_HasFactoryLabColumn(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ('a10','h')`); err != nil {
			t.Fatalf("agent: %v", err)
		}
		if _, err := pool.Exec(ctx, `UPDATE agents SET is_factory_lab = true WHERE agent_id = 'a10'`); err != nil {
			t.Fatalf("is_factory_lab column must exist and accept true: %v", err)
		}
		var got bool
		if err := pool.QueryRow(ctx, `SELECT is_factory_lab FROM agents WHERE agent_id = 'a10'`).Scan(&got); err != nil || !got {
			t.Fatalf("got is_factory_lab=%v err=%v, want true", got, err)
		}
		var defaultVal bool
		if err := pool.QueryRow(ctx,
			`INSERT INTO agents (agent_id, hostname) VALUES ('a11','h') RETURNING is_factory_lab`).Scan(&defaultVal); err != nil || defaultVal {
			t.Fatalf("default is_factory_lab: got %v err=%v, want false", defaultVal, err)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/... -run 'TestScenarioRuns_FactoryValidationKindAccepted|TestAgentsSchema_HasFactoryLabColumn' -v`
Expected: both FAIL — `TestScenarioRuns_FactoryValidationKindAccepted` fails because the CHECK constraint rejects `'factory_validation'`; `TestAgentsSchema_HasFactoryLabColumn` fails because `is_factory_lab` is an unknown column.

- [ ] **Step 3: Add the `is_factory_lab` column migration**

In `internal/db/postgres.go`, immediately after the existing agents migrations (after the line `ALTER TABLE agents ADD COLUMN IF NOT EXISTS protocol_version int NOT NULL DEFAULT 1` at line 84):

```go
		// TCF Phase 6: marks the single, persistent, factory-owned lab agent.
		// Customer-facing dispatch modes (posture/telemetry/lab) refuse this
		// agent; the new factory-validation mode requires it. See
		// docs/superpowers/specs/2026-10-14-tcf-phase6-validation-lab-design.md §2.2.
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS is_factory_lab boolean NOT NULL DEFAULT false`,
```

- [ ] **Step 4: Expand the `execution_kind` CHECK constraint**

In `internal/db/content_registry_schema.go`, replace the existing `scenario_runs_execution_kind_check` addition (lines 160-161):

```go
		addConstraint("scenario_runs", "scenario_runs_execution_kind_check",
			`CHECK (execution_kind IN ('content','remediation','technique_verification','variant','adhoc_adversary','legacy'))`),
```

with a drop-and-readd (an existing deployment already has the old constraint; `addConstraint`'s `IF NOT EXISTS` guard only helps on a fresh database, so the old definition must be dropped first for the new value to actually take effect on an upgrade):

```go
		// TCF Phase 6: 'factory_validation' added for validation-lab dispatches.
		// Dropped and re-added (not just addConstraint'd) because an existing
		// deployment already has this constraint under its old definition —
		// addConstraint's IF NOT EXISTS guard would otherwise never widen it.
		`ALTER TABLE scenario_runs DROP CONSTRAINT IF EXISTS scenario_runs_execution_kind_check`,
		addConstraint("scenario_runs", "scenario_runs_execution_kind_check",
			`CHECK (execution_kind IN ('content','remediation','technique_verification','variant','adhoc_adversary','legacy','factory_validation'))`),
```

Also add a partial unique index Task 6 depends on — the orchestrator writes an in-flight `NO_DATA` placeholder row at dispatch time and updates it in place once the run resolves (Task 6, Step 3's design note); that `UPDATE ... ON CONFLICT` requires a matching unique index, which does not exist yet:

```go
		// TCF Phase 6: validationlab writes an in-flight NO_DATA placeholder
		// at dispatch time and updates it in place on resolution (at most one
		// in-flight EXECUTION-level attempt per version at a time) -- the
		// ON CONFLICT target in recordExecutionOutcome needs this index to exist.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_content_validations_inflight
		   ON content_validations (content_version_id, level) WHERE outcome = 'NO_DATA'`,
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/db/... -run 'TestScenarioRuns_FactoryValidationKindAccepted|TestAgentsSchema_HasFactoryLabColumn' -v`
Expected: both PASS.

- [ ] **Step 6: Add the new Go constants**

In `internal/contentregistry/types.go`, add to the existing `execution_kind` const block (after `KindLegacy`, line 54):

```go
	// KindFactoryValidation: a validation-lab dispatch (TCF Phase 6). Never
	// carries content_version_id -- the orchestrator's own content_validations
	// row is the authoritative run<->version link, so these runs stay
	// structurally invisible to any feature (e.g. live threat coverage) that
	// counts customer-facing runs by that FK.
	KindFactoryValidation = "factory_validation"
```

And to the existing actor const block (after `ActorMigration`, line 61):

```go
	// ActorValidationLab: the system actor the validation orchestrator uses
	// for its own DRAFT<->VALIDATING<->VALIDATED/DRAFT transitions. Not a
	// "user:" prefix, so IsHumanActor treats it as a system actor.
	ActorValidationLab = "validation:lab"
```

- [ ] **Step 7: Add the config fields**

In `config/config.go`, add near `ThreatIntelPollHours` (line 103):

```go
	ValidationLabAgentID      string `json:"validation_lab_agent_id,omitempty"`      // "" disables the validation lab entirely
	ValidationLabPollMinutes  int    `json:"validation_lab_poll_minutes,omitempty"`   // default 5
```

And near the `ThreatIntelPollHours` env-var parse (around line 347):

```go
	if v := os.Getenv("VALIDATION_LAB_AGENT_ID"); v != "" {
		cfg.ValidationLabAgentID = v
	}
	if v := os.Getenv("VALIDATION_LAB_POLL_MINUTES"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.ValidationLabPollMinutes)
	}
```

- [ ] **Step 8: Run the full db package tests**

Run: `go test ./internal/db/...`
Expected: PASS (all tests, including the two new ones).

- [ ] **Step 9: Commit**

```bash
git add internal/db/postgres.go internal/db/content_registry_schema.go internal/db/content_registry_schema_test.go internal/contentregistry/types.go config/config.go
git commit -m "feat(tcf-phase6): schema migration and constants for the validation lab"
```

---

### Task 2: `dispatchRun` ownership enforcement

**Files:**
- Modify: `internal/api/handlers.go:1838-1920` (dispatchRun body)
- Test: `internal/api/dispatch_run_test.go` (create if it doesn't already cover dispatchRun directly — check first; if a `dispatchRun`-level test file already exists, add to it instead)

**Interfaces:**
- Consumes: `contentregistry.KindFactoryValidation` (Task 1).
- Produces: `dispatchRun` refuses `Mode: "factory-validation"` against a non-lab agent, and refuses `Mode: "posture"|"telemetry"|"lab"` against the lab agent — consumed directly by Task 6 (the orchestrator calls `dispatchRun` and must get a clean refusal, never a silent success, on a misconfigured agent).

- [ ] **Step 1: Check for an existing dispatchRun-level test file**

Run: `grep -rl "func.*dispatchRun" internal/api/*_test.go`

If a result names a file already testing `dispatchRun` directly (not through an HTTP handler), add the new tests there instead of creating a new file; otherwise create `internal/api/dispatch_run_ownership_test.go`.

- [ ] **Step 2: Write the failing tests**

```go
package api

import (
	"context"
	"testing"
)

func TestDispatchRun_FactoryValidationRequiresLabAgent(t *testing.T) {
	h, cleanup := newTestHandler(t) // use whatever existing helper constructs *Handler against a real test DB; see an existing dispatchRun-adjacent test for the exact helper name
	defer cleanup()
	ctx := context.Background()

	mustInsertAgent(t, h, "not-lab", false)
	sc := minimalTestScenario(t) // reuse whatever helper other dispatchRun tests use to build a *scenario.Scenario fixture

	_, skip, err := h.dispatchRun(ctx, sc, "not-lab", dispatchOpts{Mode: "factory-validation"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if skip == "" {
		t.Fatal("factory-validation dispatch against a non-lab agent must be refused, got no skip reason")
	}
}

func TestDispatchRun_CustomerModesRefuseLabAgent(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()
	ctx := context.Background()

	mustInsertAgent(t, h, "lab-agent", true)
	sc := minimalTestScenario(t)

	for _, mode := range []string{"posture", "telemetry", "lab"} {
		_, skip, err := h.dispatchRun(ctx, sc, "lab-agent", dispatchOpts{Mode: mode})
		if err != nil {
			t.Fatalf("mode %s: unexpected error: %v", mode, err)
		}
		if skip == "" {
			t.Fatalf("mode %s dispatched against the factory-lab agent must be refused, got no skip reason", mode)
		}
	}
}
```

Note: `newTestHandler`/`mustInsertAgent`/`minimalTestScenario` are placeholders for whatever this package's *actual* existing test helpers are named — before writing this step for real, grep `internal/api/*_test.go` for an existing test that calls `dispatchRun` directly (not via HTTP) and copy its exact setup pattern; do not invent new helper names if equivalent ones already exist.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/api/... -run 'TestDispatchRun_FactoryValidationRequiresLabAgent|TestDispatchRun_CustomerModesRefuseLabAgent' -v`
Expected: both FAIL — today `dispatchRun` has no ownership check at all, so both dispatches would proceed (empty skip reason) instead of being refused.

- [ ] **Step 4: Add the ownership gate inside `dispatchRun`**

In `internal/api/handlers.go`, immediately after the existing "Agent state gate" block (right after line 1873, before the "OS compatibility check" comment at line 1875):

```go
	// ── Factory-lab ownership gate (TCF Phase 6) ─────────────────────────────
	// A customer target may never be substituted for the factory-owned lab
	// agent, and the lab agent may never be dispatched to as if it were a
	// customer target -- enforced both directions, not just by convention.
	var isFactoryLab bool
	h.db.QueryRow(ctx,
		`SELECT is_factory_lab FROM agents WHERE agent_id = $1`, agentID,
	).Scan(&isFactoryLab)
	if o.Mode == "factory-validation" && !isFactoryLab {
		return "", "factory-validation dispatch requires the factory-owned lab agent", nil
	}
	if o.Mode != "factory-validation" && isFactoryLab {
		return "", "the factory-owned lab agent cannot be dispatched to in mode " + o.Mode, nil
	}
```

- [ ] **Step 5: Include `"factory-validation"` in the `live` classification**

In `internal/api/handlers.go`, update line 1862:

```go
	live := o.Mode == "telemetry" || o.Mode == "lab" || o.Mode == "factory-validation"
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/api/... -run 'TestDispatchRun_FactoryValidationRequiresLabAgent|TestDispatchRun_CustomerModesRefuseLabAgent' -v`
Expected: both PASS.

- [ ] **Step 7: Run the full api package tests (this touches a widely-shared function)**

Run: `go test ./internal/api/...`
Expected: PASS. If this hangs or takes 10+ minutes, it may be the pre-existing testcontainer resource issue noted in prior sessions — in that case re-run scoped to packages/tests actually touched: `go test ./internal/api/... -run 'DispatchRun|Scenario|Run'`.

- [ ] **Step 8: Commit**

```bash
git add internal/api/handlers.go internal/api/dispatch_run_ownership_test.go
git commit -m "feat(tcf-phase6): enforce factory-lab ownership in both directions at dispatch"
```

---

### Task 3: Dispatch-time safety re-check

**Files:**
- Create: `internal/contentregistry/dispatch_recheck.go`
- Test: `internal/contentregistry/dispatch_recheck_test.go`

**Interfaces:**
- Consumes: `Version.Artifact` ([]byte, Task-independent — already exists on `Version`, `store.go:17-30`), `analyzeArtifact` (`analyze.go:62`, unmodified).
- Produces: `func (r *Registry) DispatchSafetyRecheck(ctx context.Context, v Version) error` — consumed by Task 6 (the orchestrator calls this immediately before dispatch).

- [ ] **Step 1: Write the failing test**

```go
package contentregistry

import (
	"context"
	"encoding/json"
	"testing"
)

func TestDispatchSafetyRecheck_RefusesDestructiveVerdict(t *testing.T) {
	reg := newTestRegistry(t) // use whichever existing helper other contentregistry tests use to build a *Registry against a real test DB
	ctx := context.Background()

	v := Version{
		ID:        "v-recheck-1",
		ContentID: "c-recheck-1",
		Artifact:  destructiveTestArtifact(t), // reuse whatever fixture an existing safetyVerdict/analyzeArtifact test already uses for a destructive scenario
	}
	if err := reg.DispatchSafetyRecheck(ctx, v); err == nil {
		t.Fatal("a destructive verdict must refuse the dispatch")
	}

	var count int
	if err := reg.pool.QueryRow(ctx,
		`SELECT count(*) FROM content_safety_verdicts WHERE content_version_id = $1 AND classifier = 'dispatch-recheck'`,
		v.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("got %d dispatch-recheck rows, err=%v, want exactly 1", count, err)
	}

	var detail []byte
	if err := reg.pool.QueryRow(ctx,
		`SELECT detail FROM content_safety_verdicts WHERE content_version_id = $1 AND classifier = 'dispatch-recheck'`,
		v.ID).Scan(&detail); err != nil {
		t.Fatalf("read detail: %v", err)
	}
	var parsed any
	if err := json.Unmarshal(detail, &parsed); err != nil || len(detail) <= len("[]") {
		t.Fatalf("detail must be real, non-empty JSON, got %q", detail)
	}
}

func TestDispatchSafetyRecheck_PassesNonDestructive(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := context.Background()

	v := Version{
		ID:        "v-recheck-2",
		ContentID: "c-recheck-2",
		Artifact:  nonDestructiveTestArtifact(t), // reuse an existing non-destructive fixture
	}
	if err := reg.DispatchSafetyRecheck(ctx, v); err != nil {
		t.Fatalf("a non-destructive verdict must not be refused: %v", err)
	}
	var count int
	reg.pool.QueryRow(ctx,
		`SELECT count(*) FROM content_safety_verdicts WHERE content_version_id = $1 AND classifier = 'dispatch-recheck'`,
		v.ID).Scan(&count)
	if count != 0 {
		t.Fatalf("a passing re-check must not write a refusal row, got %d", count)
	}
}
```

Before writing this step for real: grep `internal/contentregistry/*_test.go` for the exact names of the existing destructive/non-destructive scenario-artifact fixtures and the registry-construction helper already used by Phase 4/5's own tests (e.g. in `compose_test.go` or `analyze_test.go`), and use those exact names rather than inventing new ones.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/contentregistry/... -run 'TestDispatchSafetyRecheck' -v`
Expected: both FAIL with "undefined: DispatchSafetyRecheck" (or similar compile error).

- [ ] **Step 3: Implement `DispatchSafetyRecheck`**

Create `internal/contentregistry/dispatch_recheck.go`:

```go
package contentregistry

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	dispatchRecheckClassifier = "dispatch-recheck"
	dispatchRecheckVersion    = "1"
)

// DispatchSafetyRecheck re-runs analyzeArtifact (unmodified -- the exact
// entry point Compose/RegisterGenerated already use) against a version's
// stored artifact, immediately before a validation-lab dispatch. It does
// NOT re-run combinatorialRisk: that check's input (loadedComponent) is
// Compose-time-only data not retained in reusable form on a persisted
// version (spec §2.3, §4). A refusal here writes an auditable
// content_safety_verdicts row with classifier "dispatch-recheck", distinct
// from and in addition to the original "execclass" row createVersion wrote.
func (r *Registry) DispatchSafetyRecheck(ctx context.Context, v Version) error {
	a, err := analyzeArtifact(v.Artifact)
	if err != nil {
		return fmt.Errorf("dispatch re-check: artifact unreadable: %w", err)
	}
	if a.safety.verdict != scenario.ClassDestructive {
		return nil
	}
	detail, _ := json.Marshal(a.safety.detail)
	_, err = r.pool.Exec(ctx,
		`INSERT INTO content_safety_verdicts (content_version_id, classifier, classifier_version, verdict, detail)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (content_version_id, classifier, classifier_version) DO UPDATE SET detail = EXCLUDED.detail, verdict = EXCLUDED.verdict, evaluated_at = NOW()`,
		v.ID, dispatchRecheckClassifier, dispatchRecheckVersion, a.safety.verdict, detail)
	if err != nil {
		return fmt.Errorf("dispatch re-check: write verdict row: %w", err)
	}
	return fmt.Errorf("dispatch re-check: %s", "current safety verdict is destructive")
}
```

Note: `ON CONFLICT ... DO UPDATE` handles a candidate being re-checked across multiple failed validation attempts (Global Constraints: no attempt cap in v1) without violating the `UNIQUE(content_version_id, classifier, classifier_version)` constraint on a second refusal for the same version.

Confirm the actual import path for `scenario.ClassDestructive` matches what `analyze.go` imports (it already imports `"github.com/audspect/bas/internal/scenario"` for this exact type — add the same import here).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/contentregistry/... -run 'TestDispatchSafetyRecheck' -v`
Expected: both PASS.

- [ ] **Step 5: Run the full contentregistry package tests**

Run: `go test ./internal/contentregistry/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/contentregistry/dispatch_recheck.go internal/contentregistry/dispatch_recheck_test.go
git commit -m "feat(tcf-phase6): dispatch-time safety re-check reusing analyzeArtifact"
```

---

### Task 4: Publication gate for TCF-originated content

**Files:**
- Modify: `internal/contentregistry/intake.go:285-318` (`Registry.Transition`)
- Test: `internal/contentregistry/lifecycle_test.go` (the existing file already testing `VALIDATING` transitions — add here, matching its style)

**Interfaces:**
- Consumes: `ActorGenerator`, `ActorComposer` (existing, `types.go:59-60`).
- Produces: `Registry.Transition` refuses `DRAFT→PUBLISHED_LOCAL` when the version's `created_by` is `ActorGenerator` or `ActorComposer` — no new exported function; this is a behavior change to an existing one, consumed by anyone (including the orchestrator, Task 6) who might call `Transition` with that combination.

- [ ] **Step 1: Write the failing tests**

Add to `internal/contentregistry/lifecycle_test.go`:

```go
func TestTransition_TCFOriginDraftCannotPublishDirectly(t *testing.T) {
	reg := newTestRegistry(t) // match the exact helper this file's existing tests already use
	ctx := context.Background()

	vid := mustCreateDraftVersion(t, reg, ActorGenerator) // reuse/adapt whatever helper this file's existing tests use to get a real DRAFT, OriginLocal version row

	if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "user:admin1", "trying to publish"); err == nil {
		t.Fatal("DRAFT->PUBLISHED_LOCAL must be refused for generator-created content")
	}
}

func TestTransition_TCFOriginComposedDraftCannotPublishDirectly(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := context.Background()

	vid := mustCreateDraftVersion(t, reg, ActorComposer)

	if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "user:admin1", "trying to publish"); err == nil {
		t.Fatal("DRAFT->PUBLISHED_LOCAL must be refused for composer-created content")
	}
}

func TestTransition_OperatorDraftCanStillPublishDirectly(t *testing.T) {
	// Regression guard: RegisterLocalApproved itself bypasses Transition
	// entirely (out of scope, intake.go:215-253), but this proves the new
	// guard is scoped to created_by, not to every DRAFT->PUBLISHED_LOCAL
	// call -- an intake-actor DRAFT (the shape any pre-existing or
	// hypothetical operator DRAFT would have) must still be publishable.
	reg := newTestRegistry(t)
	ctx := context.Background()

	vid := mustCreateDraftVersion(t, reg, ActorIntake)

	if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "user:admin1", "operator publish"); err != nil {
		t.Fatalf("intake-actor DRAFT->PUBLISHED_LOCAL must still succeed: %v", err)
	}
}

func TestTransition_ValidatedTCFOriginCanStillPublish(t *testing.T) {
	// VALIDATED->PUBLISHED_LOCAL already existed before this phase
	// (lifecycle.go:26) -- this proves the new guard does not accidentally
	// also block the legitimate post-validation path.
	reg := newTestRegistry(t)
	ctx := context.Background()

	vid := mustCreateDraftVersion(t, reg, ActorGenerator)
	if err := reg.Transition(ctx, vid, LifecycleValidating, ActorValidationLab, "scanned"); err != nil {
		t.Fatalf("DRAFT->VALIDATING: %v", err)
	}
	if err := reg.Transition(ctx, vid, LifecycleValidated, ActorValidationLab, "passed"); err != nil {
		t.Fatalf("VALIDATING->VALIDATED: %v", err)
	}
	if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "user:admin1", "publish after validation"); err != nil {
		t.Fatalf("VALIDATED->PUBLISHED_LOCAL must succeed: %v", err)
	}
}
```

Before writing this step for real: read `lifecycle_test.go` in full (it's referenced in the spec as already containing a `VALIDATING→DRAFT` system-actor test around line 58) and use its exact existing helper names for registry construction and draft-version creation — do not invent `newTestRegistry`/`mustCreateDraftVersion` if differently-named equivalents already exist there.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/contentregistry/... -run 'TestTransition_TCFOrigin|TestTransition_OperatorDraft|TestTransition_ValidatedTCFOrigin' -v`
Expected: `TestTransition_TCFOriginDraftCannotPublishDirectly` and `TestTransition_TCFOriginComposedDraftCannotPublishDirectly` FAIL (today's code allows the transition); `TestTransition_OperatorDraftCanStillPublishDirectly` and `TestTransition_ValidatedTCFOriginCanStillPublish` PASS already (they're regression guards for existing behavior, included now so a later step can't silently break them without turning this run red).

- [ ] **Step 3: Add the guard inside `Registry.Transition`**

In `internal/contentregistry/intake.go`, change the initial `SELECT` (lines 291-293) to also fetch `created_by`:

```go
	var origin, trust, lc, createdBy string
	err = tx.QueryRow(ctx, `SELECT origin, trust_level, lifecycle, created_by FROM content_versions WHERE id = $1 FOR UPDATE`,
		versionID).Scan(&origin, &trust, &lc, &createdBy)
```

Then, immediately after the existing `CheckTransition` call succeeds (after line 302, before `newTrust := TrustAfter(...)` at line 303):

```go
	// TCF Phase 6: TCF-originated content must pass validation before
	// publishing. VALIDATED->PUBLISHED_LOCAL (already legal, lifecycle.go:26)
	// is unaffected -- only this specific from/to pair is newly refused, and
	// only for content this phase's origin filter matches. RegisterLocalApproved
	// (intake.go:215-253) never calls Transition at all, so it is unreachable here.
	if to == LifecyclePublishedLocal && Lifecycle(lc) == LifecycleDraft &&
		(createdBy == ActorGenerator || createdBy == ActorComposer) {
		return &ErrIllegalTransition{From: Lifecycle(lc), To: to,
			Reason: "TCF-originated content must pass validation (VALIDATED) before publishing"}
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/contentregistry/... -run 'TestTransition_TCFOrigin|TestTransition_OperatorDraft|TestTransition_ValidatedTCFOrigin' -v`
Expected: all four PASS.

- [ ] **Step 5: Run the full contentregistry package tests (this touches the one shared transition path)**

Run: `go test ./internal/contentregistry/...`
Expected: PASS.

- [ ] **Step 6: Run the RegisterLocalApproved regression test explicitly**

Run: `go test ./internal/contentregistry/... -run 'RegisterLocalApproved' -v`
Expected: PASS, unchanged. If no test with this name exists yet, grep for whatever test already covers `RegisterLocalApproved`'s immediate-publish behavior and run that by its real name instead — this step exists to prove this plan's diff leaves it green, not to invent new coverage for it.

- [ ] **Step 7: Commit**

```bash
git add internal/contentregistry/intake.go internal/contentregistry/lifecycle_test.go
git commit -m "feat(tcf-phase6): require validation before publishing TCF-originated content"
```

---

### Task 5: `internal/validationlab` — selection, claim, and safety-recheck refusal

**Files:**
- Create: `internal/validationlab/orchestrator.go`
- Test: `internal/validationlab/orchestrator_test.go`

**Interfaces:**
- Consumes: `contentregistry.Registry.LoadVersion`, `.Transition`, `.DispatchSafetyRecheck` (Task 3), `ActorValidationLab`, `ActorGenerator`, `ActorComposer`, `LifecycleDraft`, `LifecycleValidating` (all existing or Task 3).
- Produces: `type Orchestrator struct{...}`, `func NewOrchestrator(pool *pgxpool.Pool, reg *contentregistry.Registry, labAgentID string, pollInterval time.Duration) *Orchestrator`, `func (o *Orchestrator) runOnce(ctx context.Context) error` (unexported, the one tick's worth of work — exported `Start`/`Stop` come in Task 6 once dispatch/poll/resolve exist, so this task's own test calls `runOnce` directly rather than waiting on a real ticker). `runOnce` here only performs selection, claim, and the safety re-check refusal path — it does not yet dispatch (Task 6 extends it).

- [ ] **Step 1: Write the failing tests**

Create `internal/validationlab/orchestrator_test.go`:

```go
package validationlab

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/contentregistry"
)

func TestRunOnce_SelectsOnlyTCFOriginatedDraft(t *testing.T) {
	reg, pool := newTestRegistry(t) // match whatever helper internal/contentregistry's own tests use, exported or re-derived locally for this package
	ctx := context.Background()

	generatorDraft := mustCreateDraftVersion(t, reg, contentregistry.ActorGenerator, nonDestructiveArtifact(t))
	operatorDraft := mustCreateDraftVersion(t, reg, contentregistry.ActorIntake, nonDestructiveArtifact(t))

	o := NewOrchestrator(pool, reg, "lab-agent-1", 0)
	if err := o.runOnce(ctx); err != nil {
		t.Fatalf("runOnce: %v", err)
	}

	assertLifecycle(t, reg, generatorDraft, contentregistry.LifecycleValidating)
	assertLifecycle(t, reg, operatorDraft, contentregistry.LifecycleDraft) // untouched
}

func TestRunOnce_SafetyRecheckRefusalReturnsToDraft(t *testing.T) {
	reg, pool := newTestRegistry(t)
	ctx := context.Background()

	destructiveDraft := mustCreateDraftVersion(t, reg, contentregistry.ActorGenerator, destructiveArtifact(t))

	o := NewOrchestrator(pool, reg, "lab-agent-1", 0)
	if err := o.runOnce(ctx); err != nil {
		t.Fatalf("runOnce: %v", err)
	}

	assertLifecycle(t, reg, destructiveDraft, contentregistry.LifecycleDraft)

	var validationCount int
	pool.QueryRow(ctx, `SELECT count(*) FROM content_validations WHERE content_version_id = $1`, destructiveDraft).Scan(&validationCount)
	if validationCount != 0 {
		t.Fatalf("a safety-recheck refusal must not write a content_validations row, got %d", validationCount)
	}
}

func TestRunOnce_ConcurrentClaimOnlyOneWins(t *testing.T) {
	reg, pool := newTestRegistry(t)
	ctx := context.Background()

	draft := mustCreateDraftVersion(t, reg, contentregistry.ActorGenerator, nonDestructiveArtifact(t))

	o1 := NewOrchestrator(pool, reg, "lab-agent-1", 0)
	o2 := NewOrchestrator(pool, reg, "lab-agent-1", 0)

	// Both race the same candidate; whichever actually commits the
	// DRAFT->VALIDATING transition inside runOnce wins, the other's claim
	// attempt fails CheckTransition (already VALIDATING, not DRAFT) and is
	// silently skipped -- proving no double-dispatch via the transition
	// itself, not a new lock.
	err1 := o1.runOnce(ctx)
	err2 := o2.runOnce(ctx)
	if err1 != nil || err2 != nil {
		t.Fatalf("runOnce errors: %v, %v", err1, err2)
	}
	assertLifecycle(t, reg, draft, contentregistry.LifecycleValidating)
}
```

Before writing this step for real: check whether `internal/contentregistry` already exports a test-helper package or whether its test helpers are internal to `package contentregistry_test`/`package contentregistry` — if they're unexported, this new package cannot reuse them directly, and this step must instead write its own minimal local equivalents (a real `*pgxpool.Pool` against the shared test DB, a real `*contentregistry.Registry`, and a way to insert a DRAFT version with a chosen `created_by` and artifact bytes) rather than importing something that doesn't exist. Grep `internal/contentregistry/*_test.go` for `func newTestRegistry` or equivalent and check its visibility before deciding.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/validationlab/... -v`
Expected: all three FAIL with compile errors (`NewOrchestrator`/`runOnce` undefined) — this package doesn't exist yet.

- [ ] **Step 3: Implement the orchestrator's selection, claim, and refusal path**

Create `internal/validationlab/orchestrator.go`:

```go
// Package validationlab drives TCF-originated DRAFT content through a
// factory-owned lab agent for EXECUTION-level validation. See
// docs/superpowers/specs/2026-10-14-tcf-phase6-validation-lab-design.md.
package validationlab

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
)

type Orchestrator struct {
	pool         *pgxpool.Pool
	reg          *contentregistry.Registry
	labAgentID   string
	pollInterval time.Duration
	stopCh       chan struct{}
}

func NewOrchestrator(pool *pgxpool.Pool, reg *contentregistry.Registry, labAgentID string, pollInterval time.Duration) *Orchestrator {
	return &Orchestrator{pool: pool, reg: reg, labAgentID: labAgentID, pollInterval: pollInterval, stopCh: make(chan struct{})}
}

// selectEligible returns DRAFT content_version ids whose created_by marks
// them as TCF-originated (spec §1.7) and that are not already mid-flight.
func (o *Orchestrator) selectEligible(ctx context.Context) ([]string, error) {
	rows, err := o.pool.Query(ctx,
		`SELECT id FROM content_versions
		  WHERE lifecycle = 'DRAFT' AND created_by IN ($1, $2)
		  ORDER BY created_at ASC`,
		contentregistry.ActorGenerator, contentregistry.ActorComposer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// runOnce performs one scan tick: claim each eligible candidate, re-check
// safety, and either refuse back to DRAFT or (Task 6) dispatch. Processes
// at most one candidate that reaches dispatch per tick -- v1's single lab
// agent can only run one validation at a time (scenario_runs' own
// idx_scenario_runs_agent_running unique index enforces this at the DB
// level regardless), so claiming many and dispatching one would just
// generate spurious "agent busy" errors for the rest.
func (o *Orchestrator) runOnce(ctx context.Context) error {
	ids, err := o.selectEligible(ctx)
	if err != nil {
		return err
	}
	dispatched := false
	for _, id := range ids {
		if err := o.reg.Transition(ctx, id, contentregistry.LifecycleValidating, contentregistry.ActorValidationLab, "claimed for validation"); err != nil {
			continue // already claimed by another tick/instance, or no longer DRAFT -- not an error, just skip
		}
		v, err := o.reg.LoadVersion(ctx, id)
		if err != nil {
			log.Printf("[validationlab] load claimed version %s: %v", id, err)
			_ = o.reg.Transition(ctx, id, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "load failed after claim")
			continue
		}
		if err := o.reg.DispatchSafetyRecheck(ctx, v); err != nil {
			log.Printf("[validationlab] %s failed dispatch safety re-check: %v", id, err)
			_ = o.reg.Transition(ctx, id, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "dispatch safety re-check refused")
			continue
		}
		if dispatched {
			// Already dispatched one this tick; leave this candidate claimed
			// in VALIDATING -- Task 6's dispatch/poll logic (and the crash-
			// recovery scan) will pick it up on a later tick.
			break
		}
		dispatched = true
		// Task 6 adds: dispatch via dispatchRun, poll, resolve.
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/validationlab/... -v`
Expected: all three PASS. (`TestRunOnce_ConcurrentClaimOnlyOneWins` passes because the second `runOnce` call's `Transition` attempt on the already-`VALIDATING` row fails `CheckTransition` and is silently skipped by the `continue`.)

- [ ] **Step 5: Commit**

```bash
git add internal/validationlab/orchestrator.go internal/validationlab/orchestrator_test.go
git commit -m "feat(tcf-phase6): validationlab selection, claim, and safety-recheck refusal"
```

---

### Task 6: `internal/validationlab` — dispatch, poll, resolve, and crash recovery

**Files:**
- Modify: `internal/validationlab/orchestrator.go` (extend `runOnce`'s dispatch path; add polling)
- Test: `internal/validationlab/orchestrator_test.go`

**Interfaces:**
- Consumes: `(*api.Handler).dispatchRun` — **this is the one real cross-package wrinkle in this plan**: `dispatchRun` is an unexported method on `*api.Handler` (`internal/api`), and `internal/validationlab` cannot call an unexported method on a type in another package. Resolve this at the start of this task (Step 1 below) before writing any other code — do not guess.
- Produces: `Orchestrator.Start()`, `Orchestrator.Stop()` — consumed by Task 7 (main.go wiring).

- [ ] **Step 1: Resolve the cross-package dispatch call**

`dispatchRun` is unexported (`internal/api/handlers.go:1838`), and `internal/validationlab` is a new, separate package — it cannot call `h.dispatchRun(...)` directly. Before writing Step 2, read `internal/api/handlers.go` around `dispatchRun`'s existing callers to confirm there is no already-exported wrapper, then add one: an exported method `(h *Handler) DispatchFactoryValidation(ctx context.Context, sc *scenario.Scenario, agentID string) (runID, skipReason string, err error)` in `internal/api/handlers.go`, directly beside `dispatchRun`, that does nothing but fix `Mode`/`Kind` and forward:

```go
// DispatchFactoryValidation is the one exported entry point into dispatchRun
// for internal/validationlab (TCF Phase 6) -- a separate package cannot call
// the unexported dispatchRun directly. Mode and Kind are fixed here, not
// caller-supplied, so a validationlab caller cannot accidentally dispatch in
// any other mode.
func (h *Handler) DispatchFactoryValidation(ctx context.Context, sc *scenario.Scenario, agentID string) (runID, skipReason string, err error) {
	return h.dispatchRun(ctx, sc, agentID, dispatchOpts{Mode: "factory-validation", Kind: contentregistry.KindFactoryValidation})
}
```

Then decide how `*Orchestrator` reaches a `*api.Handler` to call this. Grep `cmd/server/main.go` for how `*api.Handler` is constructed (it needs `h.db`, among other fields, to run the ownership-gate query added in Task 2) — if `*Handler` is constructed before the orchestrator in `main.go`'s boot sequence (likely, since `dispatchRun` already depends on it), pass the already-constructed `*api.Handler` into `NewOrchestrator` as a new parameter rather than constructing a second one. Confirm this by reading main.go's actual construction order in Task 7's Step 1.

**Signature change:** `NewOrchestrator` gains a new 3rd positional parameter, `d dispatcher`, between `reg` and `labAgentID` — `NewOrchestrator(pool *pgxpool.Pool, reg *contentregistry.Registry, d dispatcher, labAgentID string, pollInterval time.Duration) *Orchestrator`, where:

```go
type dispatcher interface {
	DispatchFactoryValidation(ctx context.Context, sc *scenario.Scenario, agentID string) (runID, skipReason string, err error)
}
```

`dispatcher` is an unexported interface type, but `NewOrchestrator` itself stays exported — Go callers outside the package (Task 7's `main.go`) can still pass any value structurally satisfying it (`*api.Handler`, once Task 7's `DispatchFactoryValidation` method exists) without needing to name the interface type at all. This is a constructor parameter, not a field set after construction — it must be a parameter precisely because `main.go` (a different package) cannot assign to an unexported field directly.

This changes Task 5's existing `NewOrchestrator` call sites. **Update all three of Task 5's test functions** (`TestRunOnce_SelectsOnlyTCFOriginatedDraft`, `TestRunOnce_SafetyRecheckRefusalReturnsToDraft`, `TestRunOnce_ConcurrentClaimOnlyOneWins`) to pass `nil` as the new 3rd argument — e.g. `NewOrchestrator(pool, reg, nil, "lab-agent-1", 0)` — since none of them reach the dispatch step this parameter serves.

- [ ] **Step 2: Write the failing tests**

Add to `internal/validationlab/orchestrator_test.go`:

```go
type fakeDispatcher struct {
	runID      string
	skipReason string
	err        error
}

func (f *fakeDispatcher) DispatchFactoryValidation(ctx context.Context, sc *scenario.Scenario, agentID string) (string, string, error) {
	return f.runID, f.skipReason, f.err
}

func TestRunOnce_SuccessfulRunTransitionsToValidated(t *testing.T) {
	reg, pool := newTestRegistry(t)
	ctx := context.Background()

	draft := mustCreateDraftVersion(t, reg, contentregistry.ActorGenerator, nonDestructiveArtifact(t))
	mustInsertAgent(t, pool, "lab-agent-1")
	runID := mustInsertScenarioRun(t, pool, "lab-agent-1", "completed") // a run that's already terminal, so the poll resolves on the first check

	o := NewOrchestrator(pool, reg, &fakeDispatcher{runID: runID}, "lab-agent-1", 0)
	if err := o.runOnce(ctx); err != nil {
		t.Fatalf("runOnce: %v", err)
	}

	assertLifecycle(t, reg, draft, contentregistry.LifecycleValidated)

	var outcome, gotRunID string
	if err := pool.QueryRow(ctx,
		`SELECT outcome, run_id FROM content_validations WHERE content_version_id = $1 AND level = 'EXECUTION'`,
		draft).Scan(&outcome, &gotRunID); err != nil {
		t.Fatalf("content_validations row: %v", err)
	}
	if outcome != "PASS" || gotRunID != runID {
		t.Fatalf("got outcome=%s run_id=%s, want PASS/%s", outcome, gotRunID, runID)
	}
}

func TestRunOnce_FailedRunReturnsToDraft(t *testing.T) {
	reg, pool := newTestRegistry(t)
	ctx := context.Background()

	draft := mustCreateDraftVersion(t, reg, contentregistry.ActorGenerator, nonDestructiveArtifact(t))
	mustInsertAgent(t, pool, "lab-agent-1")
	runID := mustInsertScenarioRun(t, pool, "lab-agent-1", "failed")

	o := NewOrchestrator(pool, reg, &fakeDispatcher{runID: runID}, "lab-agent-1", 0)
	if err := o.runOnce(ctx); err != nil {
		t.Fatalf("runOnce: %v", err)
	}

	assertLifecycle(t, reg, draft, contentregistry.LifecycleDraft)
	var outcome string
	pool.QueryRow(ctx, `SELECT outcome FROM content_validations WHERE content_version_id = $1 AND level = 'EXECUTION'`, draft).Scan(&outcome)
	if outcome != "FAIL" {
		t.Fatalf("got outcome=%s, want FAIL", outcome)
	}
}

func TestRunOnce_DispatchFailureRecordsErrorWithNullRunID(t *testing.T) {
	reg, pool := newTestRegistry(t)
	ctx := context.Background()

	draft := mustCreateDraftVersion(t, reg, contentregistry.ActorGenerator, nonDestructiveArtifact(t))

	o := NewOrchestrator(pool, reg, &fakeDispatcher{skipReason: "agent busy"}, "lab-agent-1", 0) // no run ever created

	if err := o.runOnce(ctx); err != nil {
		t.Fatalf("runOnce: %v", err)
	}

	assertLifecycle(t, reg, draft, contentregistry.LifecycleDraft)
	var outcome string
	var runID *string
	if err := pool.QueryRow(ctx,
		`SELECT outcome, run_id FROM content_validations WHERE content_version_id = $1 AND level = 'EXECUTION'`,
		draft).Scan(&outcome, &runID); err != nil {
		t.Fatalf("content_validations row: %v — a dispatch failure must still be honestly recorded against the real CHECK constraint", err)
	}
	if outcome != "ERROR" || runID != nil {
		t.Fatalf("got outcome=%s run_id=%v, want ERROR/nil", outcome, runID)
	}
}

func TestRunOnce_TimeoutReturnsToDraft(t *testing.T) {
	// A run that never leaves 'running' within the (shrunk, test-only)
	// timeout must resolve to an honest ERROR, never leaving the version
	// stuck in VALIDATING forever and never silently treated as a pass.
	reg, pool := newTestRegistry(t)
	ctx := context.Background()

	draft := mustCreateDraftVersion(t, reg, contentregistry.ActorGenerator, nonDestructiveArtifact(t))
	mustInsertAgent(t, pool, "lab-agent-1")
	runID := mustInsertScenarioRun(t, pool, "lab-agent-1", "running") // never completes

	o := NewOrchestrator(pool, reg, &fakeDispatcher{runID: runID}, "lab-agent-1", 0)
	o.timeout = 50 * time.Millisecond
	o.pollEvery = 10 * time.Millisecond
	if err := o.runOnce(ctx); err != nil {
		t.Fatalf("runOnce: %v", err)
	}

	assertLifecycle(t, reg, draft, contentregistry.LifecycleDraft)
	var outcome string
	pool.QueryRow(ctx, `SELECT outcome FROM content_validations WHERE content_version_id = $1 AND level = 'EXECUTION'`, draft).Scan(&outcome)
	if outcome != "ERROR" {
		t.Fatalf("got outcome=%s, want ERROR", outcome)
	}
}

func TestResolveOrphaned_RecoversAfterSimulatedRestart(t *testing.T) {
	// Simulates a crash: a version is already VALIDATING with a real,
	// already-completed run_id, but no Orchestrator instance in this test
	// ever called runOnce for it -- proving resolution reads only durable
	// state (content_versions.lifecycle + scenario_runs), never in-memory
	// tracking of what this process personally dispatched.
	reg, pool := newTestRegistry(t)
	ctx := context.Background()

	draft := mustCreateDraftVersion(t, reg, contentregistry.ActorGenerator, nonDestructiveArtifact(t))
	if err := reg.Transition(ctx, draft, contentregistry.LifecycleValidating, contentregistry.ActorValidationLab, "claimed"); err != nil {
		t.Fatalf("setup transition: %v", err)
	}
	mustInsertAgent(t, pool, "lab-agent-1")
	runID := mustInsertScenarioRun(t, pool, "lab-agent-1", "completed")
	mustRecordRunIDForVersion(t, pool, draft, runID) // whatever this task's own bookkeeping needs to associate the orphaned VALIDATING row with its already-dispatched run_id -- see Step 3's design note

	o := NewOrchestrator(pool, reg, nil, "lab-agent-1", 0) // resolveOrphaned never dispatches, so no fake dispatcher is needed here
	if err := o.resolveOrphaned(ctx); err != nil {
		t.Fatalf("resolveOrphaned: %v", err)
	}
	assertLifecycle(t, reg, draft, contentregistry.LifecycleValidated)
}
```

- [ ] **Step 3: Design note — how a `VALIDATING` row remembers its dispatched `run_id` across a restart**

Before implementing, resolve one real design question the tests above assume an answer to: `content_versions` has no `run_id` column, so once a run is dispatched, something durable must record which `run_id` belongs to which `VALIDATING` version, or `resolveOrphaned` has nothing to poll. Two options, pick the first unless it proves unworkable while implementing:

1. Write a `content_validations` row **immediately at dispatch time** with `outcome='NO_DATA'` (a legal, non-`'PASS'` outcome, so `run_id` can be real and the row still passes the CHECK constraint) as a placeholder, then `UPDATE` that same row's `outcome`/`detail` in place once the run resolves. `resolveOrphaned`'s query becomes: every `content_versions` row in `VALIDATING` that has a `content_validations` row with `outcome='NO_DATA'` and a non-null `run_id` — join to `scenario_runs` on that `run_id` to check for completion.
2. A new, small dedicated table (e.g. `validation_lab_runs(content_version_id, run_id, dispatched_at)`) if option 1 turns out to make the PASS/FAIL resolution logic awkward (updating a row whose outcome is also how the test asserts success is sensitive to ordering bugs).

Implement option 1 first — it reuses the existing table rather than adding a new one, and `NO_DATA` is already a legal `content_validations.outcome` value (`content_registry_schema.go:136-137`) that exists for exactly this "inconclusive, not yet known" case.

- [ ] **Step 4: Run tests to verify they fail**

Run: `go test ./internal/validationlab/... -v`
Expected: the five new tests FAIL — `dispatcher`/`timeout`/`pollEvery` fields and the 3rd `NewOrchestrator` parameter undefined, `resolveOrphaned` undefined, `mustInsertScenarioRun`/`mustRecordRunIDForVersion` undefined (write these two small test helpers alongside the tests in this same step, inserting directly into `scenario_runs`/`content_validations` with plain SQL). Also expect Task 5's three existing tests to now fail to *compile* until their `NewOrchestrator` calls are updated with the new `nil` 3rd argument (this step's own instructions, above) — fix those in this same step, not a later one.

- [ ] **Step 5: Implement dispatch, poll/resolve, and `resolveOrphaned`**

Extend `internal/validationlab/orchestrator.go`. Add the `dispatcher` field and interface:

```go
type dispatcher interface {
	DispatchFactoryValidation(ctx context.Context, sc *scenario.Scenario, agentID string) (runID, skipReason string, err error)
}
```

Add `dispatcher dispatcher` to the `Orchestrator` struct, set from `NewOrchestrator`'s new 3rd parameter (Task 6 Step 1). Also add two fields for the poll/timeout loop (Step 5 below needs these to be overridable so `TestRunOnce_TimeoutReturnsToDraft`, below, doesn't have to wait 10 real minutes):

```go
	timeout      time.Duration
	pollEvery    time.Duration
```

`NewOrchestrator` sets sensible defaults when unset; tests construct an `*Orchestrator` via `NewOrchestrator` as normal and then shrink these two fields directly before calling `runOnce` (same package, so the lowercase fields are reachable from the test file). Replace Task 5's `NewOrchestrator` with:

```go
func NewOrchestrator(pool *pgxpool.Pool, reg *contentregistry.Registry, d dispatcher, labAgentID string, pollInterval time.Duration) *Orchestrator {
	return &Orchestrator{
		pool: pool, reg: reg, dispatcher: d, labAgentID: labAgentID, pollInterval: pollInterval,
		stopCh: make(chan struct{}), timeout: 10 * time.Minute, pollEvery: 5 * time.Second,
	}
}
```

Replace the `// Task 6 adds:` comment inside `runOnce`'s loop body with:

```go
		sc, err := v.Parse()
		if err != nil {
			log.Printf("[validationlab] %s failed to parse for dispatch: %v", id, err)
			o.recordExecutionOutcome(ctx, id, "", "ERROR", map[string]any{"error": err.Error()})
			_ = o.reg.Transition(ctx, id, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "parse failed")
			continue
		}
		runID, skipReason, err := o.dispatcher.DispatchFactoryValidation(ctx, sc, o.labAgentID)
		if err != nil || runID == "" {
			reason := skipReason
			if err != nil {
				reason = err.Error()
			}
			o.recordExecutionOutcome(ctx, id, "", "ERROR", map[string]any{"dispatch_failure": reason})
			_ = o.reg.Transition(ctx, id, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "dispatch failed: "+reason)
			continue
		}
		o.recordExecutionOutcome(ctx, id, runID, "NO_DATA", map[string]any{"status": "dispatched"})
		o.pollAndResolve(ctx, id, runID)
```

Add the supporting methods:

```go
// recordExecutionOutcome writes (or updates, keyed by content_version_id +
// level, see Step 3) the one EXECUTION-level content_validations row for a
// validation attempt. outcome='NO_DATA' with a non-null run_id is the
// in-flight placeholder; a later call with the real PASS/FAIL/ERROR updates
// it in place.
func (o *Orchestrator) recordExecutionOutcome(ctx context.Context, versionID, runID, outcome string, detail map[string]any) {
	d, _ := json.Marshal(detail)
	var runIDArg any
	if runID != "" {
		runIDArg = runID
	}
	_, err := o.pool.Exec(ctx,
		`INSERT INTO content_validations (content_version_id, level, outcome, run_id, validator, validator_version, detail)
		 VALUES ($1, 'EXECUTION', $2, $3, 'validationlab', '1', $4)
		 ON CONFLICT (content_version_id, level) WHERE outcome = 'NO_DATA'
		 DO UPDATE SET outcome = EXCLUDED.outcome, run_id = EXCLUDED.run_id, detail = EXCLUDED.detail`,
		versionID, outcome, runIDArg, d)
	if err != nil {
		log.Printf("[validationlab] record outcome for %s: %v", versionID, err)
	}
}

// pollAndResolve waits (bounded) for a just-dispatched run to complete, then
// resolves the version. Shares its resolution logic with resolveOrphaned so
// a crash between dispatch and completion is handled identically to a live
// wait, not as a special case.
func (o *Orchestrator) pollAndResolve(ctx context.Context, versionID, runID string) {
	deadline := time.Now().Add(o.timeout)
	for time.Now().Before(deadline) {
		if o.resolveIfComplete(ctx, versionID, runID) {
			return
		}
		time.Sleep(o.pollEvery)
	}
	o.recordExecutionOutcome(ctx, versionID, runID, "ERROR", map[string]any{"error": "validation run timed out"})
	_ = o.reg.Transition(ctx, versionID, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "validation timed out")
}

// resolveIfComplete checks one run's current status and, if terminal,
// records the outcome and transitions the version. Returns true once
// resolved (terminal or already resolved), false if still running.
func (o *Orchestrator) resolveIfComplete(ctx context.Context, versionID, runID string) bool {
	var status string
	if err := o.pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = $1`, runID).Scan(&status); err != nil {
		log.Printf("[validationlab] read run %s status: %v", runID, err)
		return false
	}
	switch status {
	case "running":
		return false
	case "completed":
		o.recordExecutionOutcome(ctx, versionID, runID, "PASS", map[string]any{"run_id": runID, "status": status})
		_ = o.reg.Transition(ctx, versionID, contentregistry.LifecycleValidated, contentregistry.ActorValidationLab, "validation passed")
	default: // failed, partial
		o.recordExecutionOutcome(ctx, versionID, runID, "FAIL", map[string]any{"run_id": runID, "status": status})
		_ = o.reg.Transition(ctx, versionID, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "validation failed")
	}
	return true
}

// resolveOrphaned scans every VALIDATING version with an in-flight
// content_validations row and resolves it from durable state alone --
// recovers correctly whether this process dispatched it, a now-dead
// process dispatched it, or it has already completed and simply hasn't
// been resolved yet.
func (o *Orchestrator) resolveOrphaned(ctx context.Context) error {
	rows, err := o.pool.Query(ctx,
		`SELECT cv.id, v.run_id FROM content_versions cv
		   JOIN content_validations v ON v.content_version_id = cv.id AND v.level = 'EXECUTION' AND v.outcome = 'NO_DATA'
		  WHERE cv.lifecycle = 'VALIDATING' AND v.run_id IS NOT NULL`)
	if err != nil {
		return err
	}
	type pending struct{ versionID, runID string }
	var work []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.versionID, &p.runID); err != nil {
			rows.Close()
			return err
		}
		work = append(work, p)
	}
	rows.Close()
	for _, p := range work {
		o.resolveIfComplete(ctx, p.versionID, p.runID)
	}
	return nil
}
```

Add imports (`encoding/json`, `github.com/audspect/bas/internal/scenario`) as needed.

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/validationlab/... -v`
Expected: all tests (this task's new ones plus Task 5's) PASS.

- [ ] **Step 7: Add `Start`/`Stop`, mirroring `internal/connector.Scheduler`'s shape**

```go
func (o *Orchestrator) Start() {
	go o.run()
	log.Printf("[validationlab] started (poll interval: %s)", o.pollInterval)
}

func (o *Orchestrator) Stop() {
	close(o.stopCh)
}

func (o *Orchestrator) run() {
	ticker := time.NewTicker(o.pollInterval)
	defer ticker.Stop()
	ctx := context.Background()
	_ = o.resolveOrphaned(ctx) // recover anything left mid-flight by a previous process, before scanning for new work
	for {
		select {
		case <-o.stopCh:
			return
		case <-ticker.C:
			if err := o.runOnce(ctx); err != nil {
				log.Printf("[validationlab] runOnce: %v", err)
			}
			_ = o.resolveOrphaned(ctx)
		}
	}
}
```

- [ ] **Step 8: Run the full validationlab package tests**

Run: `go test ./internal/validationlab/...`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/validationlab/orchestrator.go internal/validationlab/orchestrator_test.go internal/api/handlers.go
git commit -m "feat(tcf-phase6): validationlab dispatch, poll, resolve, and crash recovery"
```

---

### Task 7: Wire into `main.go`

**Files:**
- Modify: `cmd/server/main.go`

**Interfaces:**
- Consumes: `config.Config.ValidationLabAgentID`, `.ValidationLabPollMinutes` (Task 1); `validationlab.NewOrchestrator`, `.Start()` (Task 5/6); the already-constructed `*api.Handler` (Task 6, Step 1's resolution).

- [ ] **Step 1: Read main.go's actual construction order**

Run: `grep -n "handler :=\|api.NewHandler\|connector.NewScheduler\|scheduler.Start" cmd/server/main.go`

Confirm where `*api.Handler` is constructed relative to where `connector.NewScheduler(...).Start()` is called (line ~570-585 per earlier grounding) — the validation lab orchestrator must be constructed *after* the handler, using that same handler instance, consistent with Task 6 Step 1's design.

- [ ] **Step 2: Construct and start the orchestrator, gated on config**

In `cmd/server/main.go`, after the `*api.Handler` is constructed and after the connector scheduler's `.Start()` call, add:

```go
	if cfg.ValidationLabAgentID != "" {
		pollMinutes := cfg.ValidationLabPollMinutes
		if pollMinutes <= 0 {
			pollMinutes = 5
		}
		validationOrchestrator := validationlab.NewOrchestrator(
			pool, contentRegistry, handler, cfg.ValidationLabAgentID, time.Duration(pollMinutes)*time.Minute,
		)
		validationOrchestrator.Start()
		log.Printf("[validationlab] enabled, lab agent %s, poll every %dm", cfg.ValidationLabAgentID, pollMinutes)
	} else {
		log.Println("[validationlab] disabled (VALIDATION_LAB_AGENT_ID not set)")
	}
```

Adjust the exact variable names (`pool`, `contentRegistry`, `handler`) to match whatever main.go actually calls them — confirmed by Step 1's grep, not guessed here. If `NewOrchestrator`'s signature from Task 6 Step 1 took the handler as a typed `dispatcher` interface parameter rather than a bare `*api.Handler`, pass `handler` as-is (Go satisfies the interface implicitly) — do not add an unnecessary explicit conversion.

- [ ] **Step 3: Add the import**

```go
	"github.com/audspect/bas/internal/validationlab"
```

- [ ] **Step 4: Build**

Run: `go build ./...`
Expected: clean build.

- [ ] **Step 5: Run the full orchestrator test suite**

Run: `go test ./... -timeout 40m -p 2`
Expected: PASS. If `internal/api`'s full suite shows the pre-existing testcontainer connection-refused cascade under concurrent load (a known, previously-documented issue unrelated to this plan), re-run just the affected tests in isolation to confirm they pass cleanly alone, and note this explicitly rather than silently re-running until green.

- [ ] **Step 6: Commit**

```bash
git add cmd/server/main.go
git commit -m "feat(tcf-phase6): wire the validation lab orchestrator into main.go"
```
