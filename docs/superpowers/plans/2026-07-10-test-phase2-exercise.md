# Test Generation Phase 2 — `exercise` Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add high-confidence regression tests for `orchestrator/internal/exercise` (DAG executor state machine, evidence hash chain, store, plan validation, variable resolution) and the pure-logic units of `internal/exercise/tracker`.

**Architecture:** Characterization testing of working code — tests encode the code's *actual* behavior; no product-code changes except one approved harness edit (Task 1). White-box (in-package) tests so executor tests drive the unexported `advance()` tick directly with synchronous fake handlers. One Postgres container per package via `TestMain` + `testutil.MustSharedTestDB`; `RunWithPool` truncate-isolation; `-short` skip guard on every DB test; pure-logic tests carry no guard.

**Tech Stack:** Go, `testing`, `testcontainers-go` (via `internal/testutil`), `pgx/v5`, `net/http/httptest`.

**Spec:** `docs/superpowers/specs/2026-07-10-test-phase2-exercise-design.md`

## Global Constraints

- **Characterization phase — tests must PASS on first run.** The production code already works. Each "run the test" step expects PASS. If a test FAILS, the test's understanding of the code is wrong: re-read the source and fix the *test*, never the product code. (The one exception is Task 1, which edits the harness.)
- **No product-code changes** except Task 1's `testutil` edit. Do not touch any `internal/exercise/*.go` non-test file.
- **Every DB-backed test** begins with `if testing.Short() { t.Skip("skipping container-backed test in -short mode") }`. Pure-logic tests (validator, variables, registry, tracker) have **no** `-short` guard.
- **`RunWithPool` everywhere for DB tests** — the `Store` wraps `*pgxpool.Pool`, so `RunInTx` (which yields a `pgx.Tx`) is unusable.
- **Package for exercise tests:** `package exercise` (white-box). **Package for tracker tests:** `package tracker`.
- **Commit after every task; `git push` immediately after every commit** (standing rule). Commit trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- **Working dir for all `go` commands:** `orchestrator/` — i.e. `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator` first (Bash tool cwd can reset between calls).
- **Docker Desktop must be running** for DB tasks (Tasks 1, 6, 7, 8). If a test panics with "rootless Docker is not supported on Windows / daemon not running", start Docker Desktop and retry.
- **`gofmt` will warn** `LF will be replaced by CRLF` on commit — that is the known `core.autocrlf=true` artifact, not an error.

---

### Task 1: Add `EnsureExerciseSchema` to the shared test harness

**Files:**
- Modify: `orchestrator/internal/testutil/testdb.go` (the `newTestDB` function, after the `EnsureContentSchema` block at lines 65-69)

**Interfaces:**
- Consumes: `db.EnsureExerciseSchema(ctx context.Context, pool *pgxpool.Pool) error` (already exists in `internal/db/exercise_schema.go`).
- Produces: the shared `testutil.TestDB.Pool` now has the `exercise_*` tables. Tasks 6–8 rely on this.

- [ ] **Step 1: Add the schema call**

In `orchestrator/internal/testutil/testdb.go`, immediately after the existing `EnsureContentSchema` error block (the one ending `return nil, fmt.Errorf("testutil: EnsureContentSchema: %w", err)` / `}`), insert:

```go
	if err := db.EnsureExerciseSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: EnsureExerciseSchema: %w", err)
	}
```

Also update the doc comment on `newTestDB` (line ~27) from `db.EnsureSchema + db.EnsureContentSchema, and returns a ready harness.` to `db.EnsureSchema + db.EnsureContentSchema + db.EnsureExerciseSchema, and returns a ready harness.`

- [ ] **Step 2: Verify the harness still builds and its own tests pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./internal/testutil/... && go test ./internal/testutil/... -run TestNewTestDB_SchemaApplied -v`
Expected: build clean; `TestNewTestDB_SchemaApplied` PASS (the container now applies all three schemas without error).

- [ ] **Step 3: Verify a smoke query against an exercise table**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/testutil/... -run TestNewTestDB_SchemaApplied -count=1`
Expected: `ok`. (The schema application would have errored inside `newTestDB` if any `exercise_*` DDL were malformed.)

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/testutil/testdb.go
git commit -m "test(testutil): apply EnsureExerciseSchema in shared harness

The canonical test DB now carries the full production schema (base +
content + exercise), so exercise store/executor tests (Phase 2) and future
api tests (Phase 3) get the exercise_* tables. Only cross-package table
dependency of the exercise store, scenario_runs, is already in EnsureSchema.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push
```

---

### Task 2: `validator_test.go` — plan validation (pure, no DB)

**Files:**
- Create: `orchestrator/internal/exercise/validator_test.go`

**Interfaces:**
- Consumes: `ValidatePlan(p *Plan) ValidationErrors` (returns `[]string`; empty ⇒ valid), `Plan`, `PlanStep`, `StepConfig`, `VarDef` (all in `internal/exercise`).

- [ ] **Step 1: Write the test file**

`orchestrator/internal/exercise/validator_test.go`:
```go
package exercise

import (
	"strings"
	"testing"
)

// hasErrContaining reports whether any error string contains sub.
func hasErrContaining(errs ValidationErrors, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

func step(id string, deps ...string) PlanStep {
	return PlanStep{ID: id, Type: StepTypeNotify, DependsOn: deps}
}

func TestValidatePlan_ValidLinearAndDiamond(t *testing.T) {
	linear := &Plan{Steps: []PlanStep{step("a"), step("b", "a"), step("c", "b")}}
	if errs := ValidatePlan(linear); len(errs) != 0 {
		t.Fatalf("valid linear plan reported errors: %v", errs)
	}
	diamond := &Plan{Steps: []PlanStep{
		step("a"), step("b", "a"), step("c", "a"), step("d", "b", "c"),
	}}
	if errs := ValidatePlan(diamond); len(errs) != 0 {
		t.Fatalf("valid diamond plan reported errors: %v", errs)
	}
}

func TestValidatePlan_IDErrorsShortCircuit(t *testing.T) {
	missing := &Plan{Steps: []PlanStep{{ID: ""}, step("b")}}
	if errs := ValidatePlan(missing); !hasErrContaining(errs, "missing an id") {
		t.Fatalf("expected missing-id error, got %v", errs)
	}
	dup := &Plan{Steps: []PlanStep{step("a"), step("a")}}
	errs := ValidatePlan(dup)
	if !hasErrContaining(errs, `duplicate step id "a"`) {
		t.Fatalf("expected duplicate-id error, got %v", errs)
	}
}

func TestValidatePlan_UnknownDependency(t *testing.T) {
	p := &Plan{Steps: []PlanStep{step("a"), step("b", "nope")}}
	if errs := ValidatePlan(p); !hasErrContaining(errs, `depends_on unknown step "nope"`) {
		t.Fatalf("expected unknown-dependency error, got %v", errs)
	}
}

func TestValidatePlan_CycleDetection(t *testing.T) {
	selfLoop := &Plan{Steps: []PlanStep{step("a", "a")}}
	if errs := ValidatePlan(selfLoop); !hasErrContaining(errs, "circular dependency") {
		t.Fatalf("expected cycle error for self-loop, got %v", errs)
	}
	twoNode := &Plan{Steps: []PlanStep{step("a", "b"), step("b", "a")}}
	if errs := ValidatePlan(twoNode); !hasErrContaining(errs, "circular dependency") {
		t.Fatalf("expected cycle error for 2-node cycle, got %v", errs)
	}
}

func TestValidatePlan_ConditionSyntaxMatrix(t *testing.T) {
	cases := []struct {
		name    string
		cond    string
		wantErr bool
	}{
		{"empty", "", false},
		{"always", "always", false},
		{"true", "true", false},
		{"false", "false", false},
		{"never", "never", false},
		{"valid predicate", "step:a:clicked", false},
		{"wrong arity", "step:a", true},
		{"non-step prefix", "foo:a:clicked", true},
		{"empty step id", "step::clicked", true},
		{"unknown step", "step:zzz:clicked", true},
		{"unknown predicate", "step:a:exploded", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Plan{Steps: []PlanStep{step("a"), {ID: "b", Type: StepTypeNotify, Condition: tc.cond}}}
			errs := ValidatePlan(p)
			got := hasErrContaining(errs, "invalid condition")
			if got != tc.wantErr {
				t.Fatalf("cond %q: got invalid-condition=%v want %v (errs=%v)", tc.cond, got, tc.wantErr, errs)
			}
		})
	}
}

func TestValidatePlan_TimeoutAndDuration(t *testing.T) {
	neg := &Plan{Steps: []PlanStep{{ID: "a", Type: StepTypeWait, TimeoutSecs: -1}}}
	if errs := ValidatePlan(neg); !hasErrContaining(errs, "negative timeout_secs") {
		t.Fatalf("expected negative-timeout error, got %v", errs)
	}
	badDur := &Plan{Steps: []PlanStep{{ID: "a", Type: StepTypeWait, Config: StepConfig{WaitDuration: "notaduration"}}}}
	if errs := ValidatePlan(badDur); !hasErrContaining(errs, "invalid wait_duration") {
		t.Fatalf("expected bad-duration error, got %v", errs)
	}
	varDur := &Plan{Steps: []PlanStep{{ID: "a", Type: StepTypeWait, Config: StepConfig{WaitDuration: "${Wait}"}}}}
	if errs := ValidatePlan(varDur); hasErrContaining(errs, "invalid wait_duration") {
		t.Fatalf("${...} wait_duration must be skipped, got %v", errs)
	}
}

func TestValidatePlan_VariableReferences(t *testing.T) {
	// Undeclared ref flagged only when the plan declares variables.
	undeclared := &Plan{
		Variables: []VarDef{{Name: "Known", Type: VarTypeString}},
		Steps: []PlanStep{{ID: "a", Type: StepTypeNotify,
			Config: StepConfig{NotifyMsg: "hi ${Unknown}"}}},
	}
	if errs := ValidatePlan(undeclared); !hasErrContaining(errs, "undeclared variable ${Unknown}") {
		t.Fatalf("expected undeclared-variable error, got %v", errs)
	}
	// System variables are always allowed.
	sysVar := &Plan{
		Variables: []VarDef{{Name: "Known", Type: VarTypeString}},
		Steps: []PlanStep{{ID: "a", Type: StepTypeNotify,
			Config: StepConfig{NotifyMsg: "run ${ExecutionID} at ${Timestamp} by ${CurrentUser}"}}},
	}
	if errs := ValidatePlan(sysVar); hasErrContaining(errs, "undeclared variable") {
		t.Fatalf("system variables must not be flagged, got %v", errs)
	}
	// Duplicate variable name flagged.
	dupVar := &Plan{
		Variables: []VarDef{{Name: "X", Type: VarTypeString}, {Name: "X", Type: VarTypeString}},
		Steps:     []PlanStep{step("a")},
	}
	if errs := ValidatePlan(dupVar); !hasErrContaining(errs, `duplicate variable name "X"`) {
		t.Fatalf("expected duplicate-variable error, got %v", errs)
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/exercise/... -run TestValidatePlan -v`
Expected: all `TestValidatePlan_*` subtests PASS. (No Docker needed — pure functions.)

- [ ] **Step 3: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/exercise/validator_test.go
git commit -m "test(exercise): add plan validator tests (DAG, cycles, conditions, variables)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push
```

---

### Task 3: `variables_test.go` — variable resolution (pure, no DB)

**Files:**
- Create: `orchestrator/internal/exercise/variables_test.go`

**Interfaces:**
- Consumes: `NewResolver(defs []VarDef, provided map[string]string, execID, actor string) *Resolver`; `(*Resolver).Sub(string) string`; `(*Resolver).Set(name, value string)`; `(*Resolver).ResolveStepConfig(StepConfig) (StepConfig, error)`; `ValidateVars(defs []VarDef, provided map[string]string) error`; `ExtractVarRefs(*PlanStep) []string`.

- [ ] **Step 1: Write the test file**

`orchestrator/internal/exercise/variables_test.go`:
```go
package exercise

import (
	"strings"
	"testing"
)

func TestNewResolver_PrecedenceAndSystemVars(t *testing.T) {
	defs := []VarDef{
		{Name: "Greeting", Type: VarTypeString, Default: "hello"},
		{Name: "Runtime", Type: VarTypeRuntime},
	}
	r := NewResolver(defs, map[string]string{"Greeting": "override"}, "exec-1", "alice")

	if got := r.Sub("${ExecutionID}"); got != "exec-1" {
		t.Fatalf("ExecutionID = %q, want exec-1", got)
	}
	if got := r.Sub("${CurrentUser}"); got != "alice" {
		t.Fatalf("CurrentUser = %q, want alice", got)
	}
	if got := r.Sub("${Timestamp}"); got == "${Timestamp}" || got == "" {
		t.Fatalf("Timestamp should be populated, got %q", got)
	}
	if got := r.Sub("${Greeting}"); got != "override" {
		t.Fatalf("operator value must win over default: got %q", got)
	}
	// Runtime var is not pre-populated → reference left literal.
	if got := r.Sub("${Runtime}"); got != "${Runtime}" {
		t.Fatalf("runtime var must be unset until Set: got %q", got)
	}
	// Set injects a runtime value visible to later Sub.
	r.Set("Runtime", "generated")
	if got := r.Sub("${Runtime}"); got != "generated" {
		t.Fatalf("after Set, Runtime = %q, want generated", got)
	}
}

func TestNewResolver_SecretFromEnv(t *testing.T) {
	t.Setenv("BAS_TEST_SECRET", "s3cr3t")
	defs := []VarDef{{Name: "ApiKey", Type: VarTypeSecret, SecretEnv: "BAS_TEST_SECRET"}}
	r := NewResolver(defs, nil, "exec-1", "alice")
	if got := r.Sub("${ApiKey}"); got != "s3cr3t" {
		t.Fatalf("secret = %q, want s3cr3t", got)
	}
}

func TestSub_UnknownRefLeftLiteral(t *testing.T) {
	r := NewResolver(nil, nil, "e", "u")
	if got := r.Sub("a ${Nope} b"); got != "a ${Nope} b" {
		t.Fatalf("unknown ref must be left literal, got %q", got)
	}
}

func TestResolveStepConfig_SubstitutesAndEscapes(t *testing.T) {
	r := NewResolver(nil, map[string]string{
		"Subj":    "Q3 Review",
		"Tricky":  `he said "hi"` + "\n" + `path\to`,
	}, "e", "u")
	in := StepConfig{Email: &EmailConfig{
		Subject:  "${Subj}",
		BodyHTML: "value=${Tricky}",
	}}
	out, err := r.ResolveStepConfig(in)
	if err != nil {
		t.Fatalf("ResolveStepConfig: %v", err)
	}
	if out.Email == nil {
		t.Fatal("email config lost during resolution")
	}
	if out.Email.Subject != "Q3 Review" {
		t.Fatalf("Subject = %q, want Q3 Review", out.Email.Subject)
	}
	// Quote/backslash/newline value must survive intact (JSON-safe substitution).
	if out.Email.BodyHTML != `value=he said "hi"`+"\n"+`path\to` {
		t.Fatalf("Tricky value mangled: %q", out.Email.BodyHTML)
	}
}

func TestValidateVars(t *testing.T) {
	defs := []VarDef{
		{Name: "Req", Type: VarTypeString, Required: true},
		{Name: "Opt", Type: VarTypeString},
		{Name: "Sec", Type: VarTypeSecret, Required: true, SecretEnv: "X"},
		{Name: "Run", Type: VarTypeRuntime, Required: true},
		{Name: "Def", Type: VarTypeString, Required: true, Default: "d"},
	}
	// Missing Req only (Sec/Run skipped, Def satisfied by default).
	if err := ValidateVars(defs, nil); err == nil || !strings.Contains(err.Error(), "Req") {
		t.Fatalf("expected missing Req, got %v", err)
	}
	if err := ValidateVars(defs, map[string]string{"Req": "x"}); err != nil {
		t.Fatalf("all requirements met, got %v", err)
	}
}

func TestExtractVarRefs_UniqueAndEmpty(t *testing.T) {
	ps := &PlanStep{Config: StepConfig{Email: &EmailConfig{
		Subject:  "${A} ${B}",
		BodyHTML: "${A} again",
	}}}
	refs := ExtractVarRefs(ps)
	if len(refs) != 2 {
		t.Fatalf("expected 2 unique refs, got %v", refs)
	}
	seen := map[string]bool{}
	for _, r := range refs {
		seen[r] = true
	}
	if !seen["A"] || !seen["B"] {
		t.Fatalf("expected refs A and B, got %v", refs)
	}
	none := &PlanStep{Config: StepConfig{NotifyMsg: "no refs here"}}
	if refs := ExtractVarRefs(none); len(refs) != 0 {
		t.Fatalf("expected no refs, got %v", refs)
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/exercise/... -run 'TestNewResolver|TestSub_|TestResolveStepConfig|TestValidateVars|TestExtractVarRefs' -v`
Expected: all PASS.

- [ ] **Step 3: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/exercise/variables_test.go
git commit -m "test(exercise): add variable resolver tests (precedence, secrets, JSON-safe substitution)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push
```

---

### Task 4: `registry_test.go` — registry, triggers, scheduler, helpers (pure/concurrency, no DB)

**Files:**
- Create: `orchestrator/internal/exercise/registry_test.go`

**Interfaces:**
- Consumes: `NewRegistry()`, `(*Registry).Register(StepType, StepHandler)`, `.Dispatch(ctx, *Execution, *PlanStep, *StepExecution) error`, `.Has(StepType) bool`; `StepHandlerFunc`; `NewTriggerRegistry()`, `.Register(StepType, TriggerFn)`, `.Has`, `.Check(ctx, *Execution, *PlanStep, *StepExecution) (bool, map[string]any, error)`; `NewPollScheduler(time.Duration)`, `.Start(func(context.Context))`, `.Stop()`; `mergeMaps(a, b map[string]any) map[string]any`; `mintHookToken() (string, error)`; package var `cryptoRandRead`.

- [ ] **Step 1: Write the test file**

`orchestrator/internal/exercise/registry_test.go`:
```go
package exercise

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRegistry_DispatchAndHas(t *testing.T) {
	r := NewRegistry()
	if r.Has(StepTypeNotify) {
		t.Fatal("empty registry should not Has notify")
	}
	var called bool
	r.Register(StepTypeNotify, StepHandlerFunc(func(_ context.Context, _ *Execution, _ *PlanStep, _ *StepExecution) error {
		called = true
		return nil
	}))
	if !r.Has(StepTypeNotify) {
		t.Fatal("Has should be true after Register")
	}
	if err := r.Dispatch(context.Background(), &Execution{}, &PlanStep{Type: StepTypeNotify}, &StepExecution{}); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !called {
		t.Fatal("handler was not invoked")
	}
}

func TestRegistry_UnknownTypeError(t *testing.T) {
	r := NewRegistry()
	err := r.Dispatch(context.Background(), &Execution{}, &PlanStep{Type: StepType("mystery")}, &StepExecution{})
	if err == nil {
		t.Fatal("expected error for unknown step type")
	}
}

func TestRegistry_RegisterOverwrites(t *testing.T) {
	r := NewRegistry()
	r.Register(StepTypeNotify, StepHandlerFunc(func(context.Context, *Execution, *PlanStep, *StepExecution) error {
		return errors.New("first")
	}))
	r.Register(StepTypeNotify, StepHandlerFunc(func(context.Context, *Execution, *PlanStep, *StepExecution) error {
		return nil
	}))
	if err := r.Dispatch(context.Background(), &Execution{}, &PlanStep{Type: StepTypeNotify}, &StepExecution{}); err != nil {
		t.Fatalf("second registration should win: %v", err)
	}
}

func TestTriggerRegistry_CheckWithAndWithout(t *testing.T) {
	tr := NewTriggerRegistry()
	// No trigger registered → (false, nil, nil).
	ok, payload, err := tr.Check(context.Background(), &Execution{}, &PlanStep{Type: StepTypeWaitForWebhook}, &StepExecution{})
	if ok || payload != nil || err != nil {
		t.Fatalf("unregistered Check = (%v,%v,%v), want (false,nil,nil)", ok, payload, err)
	}
	tr.Register(StepTypeWaitForWebhook, func(context.Context, *Execution, *PlanStep, *StepExecution) (bool, map[string]any, error) {
		return true, map[string]any{"hit": 1}, nil
	})
	if !tr.Has(StepTypeWaitForWebhook) {
		t.Fatal("Has should be true after Register")
	}
	ok, payload, err = tr.Check(context.Background(), &Execution{}, &PlanStep{Type: StepTypeWaitForWebhook}, &StepExecution{})
	if !ok || payload["hit"] != 1 || err != nil {
		t.Fatalf("registered Check = (%v,%v,%v), want (true,{hit:1},nil)", ok, payload, err)
	}
}

func TestPollScheduler_TicksAndStopIdempotent(t *testing.T) {
	s := NewPollScheduler(5 * time.Millisecond)
	fired := make(chan struct{}, 1)
	var once sync.Once
	s.Start(func(context.Context) {
		once.Do(func() { close(fired) })
	})
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler tick did not fire within 2s")
	}
	s.Stop()
	s.Stop() // must not panic (exercises the select-default branch)
}

func TestMergeMaps(t *testing.T) {
	a := map[string]any{"x": 1, "y": 2}
	b := map[string]any{"y": 99, "z": 3}
	out := mergeMaps(a, b)
	if out["x"] != 1 || out["y"] != 99 || out["z"] != 3 {
		t.Fatalf("mergeMaps = %v, want {x:1,y:99,z:3}", out)
	}
	if a["y"] != 2 {
		t.Fatal("mergeMaps must not mutate input a")
	}
}

func TestMintHookToken(t *testing.T) {
	tok, err := mintHookToken()
	if err != nil {
		t.Fatalf("mintHookToken: %v", err)
	}
	if len(tok) != 32 {
		t.Fatalf("token length = %d, want 32 hex chars", len(tok))
	}
	// Error path: stub cryptoRandRead to fail.
	orig := cryptoRandRead
	t.Cleanup(func() { cryptoRandRead = orig })
	cryptoRandRead = func([]byte) (int, error) { return 0, errors.New("boom") }
	if _, err := mintHookToken(); err == nil {
		t.Fatal("expected error when cryptoRandRead fails")
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/exercise/... -run 'TestRegistry|TestTriggerRegistry|TestPollScheduler|TestMergeMaps|TestMintHookToken' -v`
Expected: all PASS.

- [ ] **Step 3: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/exercise/registry_test.go
git commit -m "test(exercise): add registry, trigger, scheduler, and helper tests

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push
```

---

### Task 5: `tracker/tracker_test.go` — token minting + link rewriting (pure, no DB)

**Files:**
- Create: `orchestrator/internal/exercise/tracker/tracker_test.go`

**Interfaces:**
- Consumes: `MintToken(ctx, store TokenStore, execID, stepExecID, targetID, tokenType string, payload map[string]any) (string, error)`; `GenerateLinks(ctx, store TokenStore, execID, stepExecID, bodyHTML string, cfg LinkConfig) (string, error)`; `TokenStore` interface (`InsertTrackToken`, `GetTrackToken`, `RecordTokenUse`); `LinkConfig`, `TrackToken`.

- [ ] **Step 1: Write the test file**

`orchestrator/internal/exercise/tracker/tracker_test.go`:
```go
package tracker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeTokenStore is an in-memory TokenStore for pure tracker tests.
type fakeTokenStore struct {
	inserted []insertedToken
	failOn   bool
}

type insertedToken struct {
	token, execID, stepExecID, targetID, tokenType string
	payload                                         map[string]any
}

func (f *fakeTokenStore) InsertTrackToken(_ context.Context, token, execID, stepExecID, targetID, tokenType string, payload map[string]any) error {
	if f.failOn {
		return errors.New("insert failed")
	}
	f.inserted = append(f.inserted, insertedToken{token, execID, stepExecID, targetID, tokenType, payload})
	return nil
}
func (f *fakeTokenStore) GetTrackToken(context.Context, string) (*TrackToken, error) { return nil, nil }
func (f *fakeTokenStore) RecordTokenUse(context.Context, string) error               { return nil }

func TestMintToken_ShapeAndStore(t *testing.T) {
	fs := &fakeTokenStore{}
	tok, err := MintToken(context.Background(), fs, "e1", "se1", "t1", "click", map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if len(tok) != 32 {
		t.Fatalf("token length = %d, want 32 hex", len(tok))
	}
	if len(fs.inserted) != 1 {
		t.Fatalf("expected 1 stored token, got %d", len(fs.inserted))
	}
	got := fs.inserted[0]
	if got.token != tok || got.execID != "e1" || got.tokenType != "click" {
		t.Fatalf("stored token mismatch: %+v", got)
	}
}

func TestMintToken_StoreErrorPropagates(t *testing.T) {
	fs := &fakeTokenStore{failOn: true}
	if _, err := MintToken(context.Background(), fs, "e", "s", "t", "open", nil); err == nil {
		t.Fatal("expected store error to propagate")
	}
}

func TestGenerateLinks_EmptyBaseURLUnchanged(t *testing.T) {
	fs := &fakeTokenStore{}
	body := `<a href="https://evil.test">click</a>`
	out, err := GenerateLinks(context.Background(), fs, "e", "s", body, LinkConfig{TrackClicks: true})
	if err != nil {
		t.Fatalf("GenerateLinks: %v", err)
	}
	if out != body {
		t.Fatalf("empty BaseURL must return body unchanged, got %q", out)
	}
}

func TestGenerateLinks_RewritesAbsoluteHrefsOnly(t *testing.T) {
	fs := &fakeTokenStore{}
	body := `<a href="https://evil.test/page">x</a> <a href="/relative">y</a> <a href="mailto:a@b.c">z</a>`
	out, err := GenerateLinks(context.Background(), fs, "e", "s", body, LinkConfig{
		TrackClicks: true, BaseURL: "https://bas.internal/",
	})
	if err != nil {
		t.Fatalf("GenerateLinks: %v", err)
	}
	if !strings.Contains(out, "https://bas.internal/x/click/") {
		t.Fatalf("absolute href not rewritten to redirect: %q", out)
	}
	if !strings.Contains(out, `href="/relative"`) {
		t.Fatalf("relative href must be left alone: %q", out)
	}
	if !strings.Contains(out, `href="mailto:a@b.c"`) {
		t.Fatalf("mailto href must be left alone: %q", out)
	}
	// Trailing slash on BaseURL is trimmed (no double slash before /x/click).
	if strings.Contains(out, "internal//x/click") {
		t.Fatalf("BaseURL trailing slash not trimmed: %q", out)
	}
}

func TestGenerateLinks_InjectsPixelBeforeBody(t *testing.T) {
	fs := &fakeTokenStore{}
	withBody := `<html><body>hi</body></html>`
	out, err := GenerateLinks(context.Background(), fs, "e", "s", withBody, LinkConfig{
		TrackOpens: true, BaseURL: "https://bas.internal",
	})
	if err != nil {
		t.Fatalf("GenerateLinks: %v", err)
	}
	if !strings.Contains(out, "/x/open/") || !strings.Contains(out, `width="1"`) {
		t.Fatalf("open pixel not injected: %q", out)
	}
	if strings.Index(out, "/x/open/") > strings.Index(out, "</body>") {
		t.Fatalf("pixel must appear before </body>: %q", out)
	}
	// No </body> → pixel appended at end.
	noBody := `plain text`
	out2, _ := GenerateLinks(context.Background(), fs, "e", "s", noBody, LinkConfig{TrackOpens: true, BaseURL: "https://bas.internal"})
	if !strings.HasPrefix(out2, "plain text") || !strings.Contains(out2, "/x/open/") {
		t.Fatalf("pixel not appended when no </body>: %q", out2)
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/exercise/tracker/... -v`
Expected: all PASS.

- [ ] **Step 3: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/exercise/tracker/tracker_test.go
git commit -m "test(exercise/tracker): add token minting and link-rewriting tests

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push
```

---

### Task 6: `store_test.go` — store CRUD + TestMain (DB)

**Files:**
- Create: `orchestrator/internal/exercise/store_test.go`

**Interfaces:**
- Consumes: `testutil.MustSharedTestDB`, `(*TestDB).RunWithPool`; `NewStore(*pgxpool.Pool) *Store`; all `Store` methods listed in the spec §5.5.
- Produces: package-level `var sharedDB *testutil.TestDB` and `func TestMain(*testing.M)` — reused by Tasks 7 and 8.

- [ ] **Step 1: Write the test file**

`orchestrator/internal/exercise/store_test.go`:
```go
package exercise

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestPlan_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		p := &Plan{Name: "Phish Drill", Description: "q3",
			Steps:     []PlanStep{{ID: "a", Type: StepTypeNotify}},
			Variables: []VarDef{{Name: "X", Type: VarTypeString}}}
		if err := store.CreatePlan(ctx, p); err != nil {
			t.Fatalf("CreatePlan: %v", err)
		}
		if p.ID == "" || p.CreatedAt.IsZero() {
			t.Fatal("CreatePlan must set ID and CreatedAt")
		}

		got, err := store.GetPlan(ctx, p.ID)
		if err != nil {
			t.Fatalf("GetPlan: %v", err)
		}
		if got.Name != "Phish Drill" || len(got.Steps) != 1 || got.Steps[0].ID != "a" || len(got.Variables) != 1 {
			t.Fatalf("GetPlan round-trip mismatch: %+v", got)
		}

		p.Name = "Renamed"
		if err := store.UpdatePlan(ctx, p); err != nil {
			t.Fatalf("UpdatePlan: %v", err)
		}
		got, _ = store.GetPlan(ctx, p.ID)
		if got.Name != "Renamed" {
			t.Fatalf("UpdatePlan not applied: %q", got.Name)
		}

		list, err := store.ListPlans(ctx)
		if err != nil || len(list) != 1 {
			t.Fatalf("ListPlans = %v (err %v), want 1", list, err)
		}

		if err := store.DeletePlan(ctx, p.ID); err != nil {
			t.Fatalf("DeletePlan: %v", err)
		}
		if _, err := store.GetPlan(ctx, p.ID); err == nil {
			t.Fatal("GetPlan after delete should error")
		}
	})
}

func TestExecution_LifecycleAndStatusTimestamps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		p := &Plan{Name: "P", Steps: []PlanStep{{ID: "a", Type: StepTypeNotify}}}
		if err := store.CreatePlan(ctx, p); err != nil {
			t.Fatalf("CreatePlan: %v", err)
		}
		ex := &Execution{PlanID: p.ID, Name: "Run", Status: ExecDraft,
			InitiatedBy: "alice", Targets: []Target{{ID: "t1", Name: "Bob", Email: "b@x.io"}},
			Variables: map[string]string{"K": "V"}}
		if err := store.CreateExecution(ctx, ex); err != nil {
			t.Fatalf("CreateExecution: %v", err)
		}
		if ex.ID == "" {
			t.Fatal("CreateExecution must set ID")
		}

		got, err := store.GetExecution(ctx, ex.ID)
		if err != nil {
			t.Fatalf("GetExecution: %v", err)
		}
		if len(got.Targets) != 1 || got.Targets[0].Email != "b@x.io" || got.Variables["K"] != "V" {
			t.Fatalf("execution JSON round-trip mismatch: %+v", got)
		}
		if got.PlanVersion != 1 {
			t.Fatalf("PlanVersion default = %d, want 1", got.PlanVersion)
		}

		if err := store.UpdateExecutionStatus(ctx, ex.ID, ExecRunning); err != nil {
			t.Fatalf("UpdateExecutionStatus running: %v", err)
		}
		got, _ = store.GetExecution(ctx, ex.ID)
		if got.Status != ExecRunning || got.StartedAt == nil {
			t.Fatalf("running status must set started_at: %+v", got)
		}

		if err := store.UpdateExecutionStatus(ctx, ex.ID, ExecCompleted); err != nil {
			t.Fatalf("UpdateExecutionStatus completed: %v", err)
		}
		got, _ = store.GetExecution(ctx, ex.ID)
		if got.Status != ExecCompleted || got.CompletedAt == nil {
			t.Fatalf("completed status must set completed_at: %+v", got)
		}
	})
}

func TestListRunningExecutions_OnlyRunningAndPaused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		p := &Plan{Name: "P", Steps: []PlanStep{{ID: "a", Type: StepTypeNotify}}}
		_ = store.CreatePlan(ctx, p)

		mk := func(status ExecStatus) {
			ex := &Execution{PlanID: p.ID, Name: string(status), Status: status}
			if err := store.CreateExecution(ctx, ex); err != nil {
				t.Fatalf("CreateExecution: %v", err)
			}
		}
		mk(ExecRunning)
		mk(ExecPaused)
		mk(ExecDraft)
		mk(ExecCompleted)

		running, err := store.ListRunningExecutions(ctx)
		if err != nil {
			t.Fatalf("ListRunningExecutions: %v", err)
		}
		if len(running) != 2 {
			t.Fatalf("expected 2 running/paused, got %d", len(running))
		}
	})
}

func TestTemplate_UpsertAndSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		tpl := &Template{ID: "tpl-1", Name: "Phishing", Version: 1, Category: "phishing",
			Steps: []PlanStep{{ID: "a", Type: StepTypeSendEmail}}}
		if err := store.UpsertTemplate(ctx, tpl); err != nil {
			t.Fatalf("UpsertTemplate insert: %v", err)
		}
		tpl.Name = "Phishing v2"
		if err := store.UpsertTemplate(ctx, tpl); err != nil {
			t.Fatalf("UpsertTemplate update: %v", err)
		}
		got, err := store.GetTemplate(ctx, "tpl-1")
		if err != nil || got.Name != "Phishing v2" {
			t.Fatalf("GetTemplate = %+v (err %v)", got, err)
		}

		// SeedBuiltinTemplates is idempotent.
		if err := store.SeedBuiltinTemplates(ctx); err != nil {
			t.Fatalf("SeedBuiltinTemplates 1: %v", err)
		}
		if err := store.SeedBuiltinTemplates(ctx); err != nil {
			t.Fatalf("SeedBuiltinTemplates 2 (idempotent): %v", err)
		}
		list, err := store.ListTemplates(ctx)
		if err != nil || len(list) == 0 {
			t.Fatalf("ListTemplates = %v (err %v)", list, err)
		}
	})
}

func TestStepExecution_UpsertStatusResult(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		execID := "ex-se"

		se := &StepExecution{ExecutionID: execID, StepID: "a", StepType: StepTypeNotify, Status: StepPending}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution: %v", err)
		}
		if se.ID == "" {
			t.Fatal("UpsertStepExecution must set ID")
		}
		if err := store.SetStepStatus(ctx, execID, "a", StepRunning, ""); err != nil {
			t.Fatalf("SetStepStatus running: %v", err)
		}
		if err := store.SetStepResult(ctx, execID, "a", map[string]any{"ok": true}); err != nil {
			t.Fatalf("SetStepResult: %v", err)
		}
		if err := store.SetStepStatus(ctx, execID, "a", StepCompleted, ""); err != nil {
			t.Fatalf("SetStepStatus completed: %v", err)
		}

		list, err := store.ListStepExecutions(ctx, execID)
		if err != nil || len(list) != 1 {
			t.Fatalf("ListStepExecutions = %v (err %v)", list, err)
		}
		if list[0].Status != StepCompleted || list[0].Result["ok"] != true {
			t.Fatalf("step exec state mismatch: %+v", list[0])
		}
		if list[0].StartedAt == nil || list[0].CompletedAt == nil {
			t.Fatalf("running then completed must set both timestamps: %+v", list[0])
		}

		byStep, err := store.GetStepExecByStepID(ctx, execID, "a")
		if err != nil || byStep.ID != se.ID {
			t.Fatalf("GetStepExecByStepID = %+v (err %v)", byStep, err)
		}
	})
}

func TestEvents_RecordAndList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		if err := store.RecordEvent(ctx, "ex-ev", "a", "started", "system", map[string]any{"n": 1}); err != nil {
			t.Fatalf("RecordEvent: %v", err)
		}
		events, err := store.ListEvents(ctx, "ex-ev")
		if err != nil || len(events) != 1 {
			t.Fatalf("ListEvents = %v (err %v)", events, err)
		}
		if events[0]["event_type"] != "started" || events[0]["actor"] != "system" {
			t.Fatalf("event shape mismatch: %+v", events[0])
		}
	})
}

func TestTrackToken_Lifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		if err := store.InsertTrackToken(ctx, "tok1", "ex-t", "se1", "target1", "click", map[string]any{"x": "y"}); err != nil {
			t.Fatalf("InsertTrackToken: %v", err)
		}
		got, err := store.GetTrackToken(ctx, "tok1")
		if err != nil || got.TokenType != "click" || got.Payload["x"] != "y" {
			t.Fatalf("GetTrackToken = %+v (err %v)", got, err)
		}
		if err := store.RecordTokenUse(ctx, "tok1"); err != nil {
			t.Fatalf("RecordTokenUse: %v", err)
		}
		got, _ = store.GetTrackToken(ctx, "tok1")
		if got.UsedCount != 1 || got.UsedAt == nil {
			t.Fatalf("RecordTokenUse must increment count and set used_at: %+v", got)
		}
	})
}

func TestEvidenceCounting_TypesAndDuration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := "ex-count"

		appendEv := func(evType string) {
			if _, err := chain.Append(ctx, execID, "se1", evType, "system", "test", map[string]any{"t": evType}); err != nil {
				t.Fatalf("Append %s: %v", evType, err)
			}
		}
		appendEv("email_sent")
		appendEv("email_sent")
		appendEv("link_clicked")
		appendEv("edr_detected")

		counts, err := store.CountEvidenceByType(ctx, execID)
		if err != nil {
			t.Fatalf("CountEvidenceByType: %v", err)
		}
		if counts["email_sent"] != 2 || counts["link_clicked"] != 1 {
			t.Fatalf("CountEvidenceByType = %v", counts)
		}

		// CountEvidenceForExec with explicit types.
		n, err := store.CountEvidenceForExec(ctx, execID, []string{"edr_detected"})
		if err != nil || n != 1 {
			t.Fatalf("CountEvidenceForExec explicit = %d (err %v), want 1", n, err)
		}
		// Empty types defaults to edr_detected+siem_alerted.
		n, err = store.CountEvidenceForExec(ctx, execID, nil)
		if err != nil || n != 1 {
			t.Fatalf("CountEvidenceForExec default = %d (err %v), want 1", n, err)
		}

		// hasEvidenceType by step_execution_id.
		has, err := store.hasEvidenceType(ctx, "se1", "link_clicked")
		if err != nil || !has {
			t.Fatalf("hasEvidenceType link_clicked = %v (err %v)", has, err)
		}
		has, _ = store.hasEvidenceType(ctx, "se1", "never")
		if has {
			t.Fatal("hasEvidenceType for absent type should be false")
		}

		// SumDurationByType: from email_sent to edr_detected (>= 0 seconds, no error).
		if _, err := store.SumDurationByType(ctx, execID, "email_sent", "edr_detected"); err != nil {
			t.Fatalf("SumDurationByType: %v", err)
		}
	})
}

func TestWebhookCall_And_BASRunStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		if err := store.InsertWebhookCall(ctx, "hooktok", "ex-w", "se1", []byte(`{"a":1}`)); err != nil {
			t.Fatalf("InsertWebhookCall: %v", err)
		}
		n, err := store.WebhookCallCount(ctx, "hooktok")
		if err != nil || n != 1 {
			t.Fatalf("WebhookCallCount = %d (err %v), want 1", n, err)
		}

		// BASRunStatus not-found → ("", nil).
		status, err := store.BASRunStatus(ctx, "no-such-run")
		if err != nil || status != "" {
			t.Fatalf("BASRunStatus missing = (%q,%v), want (\"\",nil)", status, err)
		}
		// Seed agent + scenario_run (FK: scenario_runs.agent_id → agents.agent_id).
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-x')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		var runID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO scenario_runs (scenario_id, agent_id, status) VALUES ('s1','agent-x','completed') RETURNING id`,
		).Scan(&runID); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}
		status, err = store.BASRunStatus(ctx, runID)
		if err != nil || status != "completed" {
			t.Fatalf("BASRunStatus found = (%q,%v), want (completed,nil)", status, err)
		}
	})
}

func TestStore_ClosedPool_ErrorsNotPanic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, sharedDB.Pool.Config().ConnString())
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	pool.Close()
	store := NewStore(pool)

	if _, err := store.ListPlans(ctx); err == nil {
		t.Error("ListPlans: want error on closed pool")
	}
	if _, err := store.GetExecution(ctx, "x"); err == nil {
		t.Error("GetExecution: want error on closed pool")
	}
	if _, err := store.ListRunningExecutions(ctx); err == nil {
		t.Error("ListRunningExecutions: want error on closed pool")
	}
	if _, err := store.ListStepExecutions(ctx, "x"); err == nil {
		t.Error("ListStepExecutions: want error on closed pool")
	}
	if _, err := store.CountEvidenceByType(ctx, "x"); err == nil {
		t.Error("CountEvidenceByType: want error on closed pool")
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/exercise/... -run 'TestPlan_CRUD|TestExecution_|TestListRunning|TestTemplate_|TestStepExecution_|TestEvents_|TestTrackToken_|TestEvidenceCounting_|TestWebhookCall_|TestStore_ClosedPool' -v 2>&1 | tail -40`
Expected: all listed tests PASS (requires Docker). The other package tests (validator/variables/registry) also run under this TestMain and pass.

- [ ] **Step 3: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/exercise/store_test.go
git commit -m "test(exercise): add store tests + TestMain (plans, executions, templates, steps, evidence counts, tokens)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push
```

---

### Task 7: `evidence_test.go` — hash chain integrity + tamper detection (DB)

**Files:**
- Create: `orchestrator/internal/exercise/evidence_test.go`

**Interfaces:**
- Consumes: `sharedDB` (Task 6); `NewEvidenceChain(*Store) *EvidenceChain`; `(*EvidenceChain).Append(ctx, execID, stepExecID, evType, actor, source string, payload map[string]any) (*Evidence, error)`; `.Verify(ctx, execID) error`; `.Record(...)`; `(*Store).ListEvidence`.

- [ ] **Step 1: Write the test file**

`orchestrator/internal/exercise/evidence_test.go`:
```go
package exercise

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEvidenceChain_AppendBuildsHashChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := "ex-chain"

		var prevHash string
		for i := 1; i <= 3; i++ {
			payload := map[string]any{"i": i}
			ev, err := chain.Append(ctx, execID, "se1", "email_sent", "system", "test", payload)
			if err != nil {
				t.Fatalf("Append %d: %v", i, err)
			}
			if ev.Seq != int64(i) {
				t.Fatalf("record %d seq = %d, want %d", i, ev.Seq, i)
			}
			if ev.PrevHash != prevHash {
				t.Fatalf("record %d prev_hash = %q, want %q", i, ev.PrevHash, prevHash)
			}
			// Recompute the chained hash the same way evidence.go does.
			pb, _ := json.Marshal(payload)
			ph := sha256.Sum256(pb)
			payHash := hex.EncodeToString(ph[:])
			combined := sha256.Sum256([]byte(payHash + prevHash))
			want := hex.EncodeToString(combined[:])
			if ev.SHA256 != want {
				t.Fatalf("record %d sha256 = %q, want %q", i, ev.SHA256, want)
			}
			prevHash = ev.SHA256
		}
	})
}

func TestEvidenceChain_VerifyIntactAndTampered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := "ex-verify"

		for i := 1; i <= 3; i++ {
			if _, err := chain.Append(ctx, execID, "se1", "email_sent", "system", "test", map[string]any{"i": i}); err != nil {
				t.Fatalf("Append %d: %v", i, err)
			}
		}
		if err := chain.Verify(ctx, execID); err != nil {
			t.Fatalf("intact chain should verify, got %v", err)
		}

		// Tamper: mutate the payload of the seq-2 record directly in the DB.
		if _, err := pool.Exec(ctx,
			`UPDATE exercise_evidence SET payload_json = $1 WHERE execution_id=$2 AND seq=2`,
			[]byte(`{"i":999}`), execID); err != nil {
			t.Fatalf("tamper update: %v", err)
		}
		err := chain.Verify(ctx, execID)
		if err == nil {
			t.Fatal("tampered chain must fail Verify")
		}
		if !strings.Contains(err.Error(), "seq 2") {
			t.Fatalf("Verify error should name the tampered seq, got %v", err)
		}
	})
}

func TestEvidenceChain_RecordAdapter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		chain := NewEvidenceChain(NewStore(pool))
		if err := chain.Record(context.Background(), "ex-rec", "se1", "link_clicked", "target", "tracker", map[string]any{"ok": true}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	})
}
```

- [ ] **Step 2: Run the tests**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/exercise/... -run 'TestEvidenceChain_' -v 2>&1 | tail -20`
Expected: all three `TestEvidenceChain_*` PASS.

- [ ] **Step 3: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/exercise/evidence_test.go
git commit -m "test(exercise): add evidence hash-chain tests (append chain, verify, tamper detection)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push
```

---

### Task 8: `executor_test.go` — state machine, conditions, timeouts, lifecycle, score (DB + fake handlers)

**Files:**
- Create: `orchestrator/internal/exercise/executor_test.go`

**Interfaces:**
- Consumes: `sharedDB` (Task 6); `NewExecutor(store *Store, evidence *EvidenceChain, registry *Registry, scheduler Scheduler, dispatch AgentDispatchFn) *Executor`; `NewRegistry`, `NewEvidenceChain`, `NewPollScheduler`, `NewTriggerRegistry`, `NewStore`; `(*Executor).LaunchExecution`, `.advance` (unexported, white-box), `.evalCondition` (unexported), `.computeScore` (unexported), `.ApproveStep`, `.AbortExecution`, `.WithTriggers`, `.RegisterBuiltins`; `(*Registry).Register`; `StepHandlerFunc`.

- [ ] **Step 1: Write the test file**

`orchestrator/internal/exercise/executor_test.go`:
```go
package exercise

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// newTestExecutor wires an Executor with real store/evidence but no scheduler
// loop (we call advance directly) and a completing fake handler for one step type.
func newTestExecutor(pool *pgxpool.Pool) (*Executor, *Store) {
	store := NewStore(pool)
	ev := NewEvidenceChain(store)
	reg := NewRegistry()
	e := NewExecutor(store, ev, reg, NewPollScheduler(time.Hour), nil)
	return e, store
}

// completeHandler marks the step Completed synchronously so advance() can make
// deterministic progress without goroutines.
func completeHandler(store *Store) StepHandlerFunc {
	return func(ctx context.Context, ex *Execution, ps *PlanStep, _ *StepExecution) error {
		return store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepCompleted, "")
	}
}

func seedRunningExecution(t *testing.T, store *Store, e *Executor, steps []PlanStep) *Execution {
	t.Helper()
	ctx := context.Background()
	p := &Plan{Name: "P", Steps: steps}
	if err := store.CreatePlan(ctx, p); err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	ex := &Execution{PlanID: p.ID, Name: "R", Status: ExecDraft}
	if err := store.CreateExecution(ctx, ex); err != nil {
		t.Fatalf("CreateExecution: %v", err)
	}
	if err := e.LaunchExecution(ctx, ex.ID); err != nil {
		t.Fatalf("LaunchExecution: %v", err)
	}
	got, _ := store.GetExecution(ctx, ex.ID)
	return got
}

func TestLaunchExecution_SeedsStepsAndRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "a", Type: StepTypeNotify}, {ID: "b", Type: StepTypeNotify, DependsOn: []string{"a"}}})
		if ex.Status != ExecRunning {
			t.Fatalf("status = %q, want running", ex.Status)
		}
		steps, _ := store.ListStepExecutions(context.Background(), ex.ID)
		if len(steps) != 2 {
			t.Fatalf("expected 2 seeded step execs, got %d", len(steps))
		}
		// A non-draft/scheduled execution is a no-op relaunch.
		if err := e.LaunchExecution(context.Background(), ex.ID); err != nil {
			t.Fatalf("relaunch should be a no-op, got %v", err)
		}
	})
}

func TestAdvance_DependencyOrderingAndCompletion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.registry.Register(StepTypeNotify, completeHandler(store))
		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "a", Type: StepTypeNotify},
			{ID: "b", Type: StepTypeNotify, DependsOn: []string{"a"}},
		})
		ctx := context.Background()

		// Tick 1: only "a" is ready; the completing handler marks it done.
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance 1: %v", err)
		}
		bStep, _ := store.GetStepExecByStepID(ctx, ex.ID, "b")
		if bStep != nil && bStep.Status == StepCompleted {
			t.Fatal("b must not complete before a is done")
		}
		// Tick 2: "a" done → "b" dispatched and completed.
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance 2: %v", err)
		}
		// Tick 3: all done → execution Completed.
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance 3: %v", err)
		}
		got, _ := store.GetExecution(ctx, ex.ID)
		if got.Status != ExecCompleted {
			t.Fatalf("execution status = %q, want completed", got.Status)
		}
	})
}

func TestAdvance_ConditionFalseSkips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.registry.Register(StepTypeNotify, completeHandler(store))
		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "a", Type: StepTypeNotify},
			{ID: "b", Type: StepTypeNotify, DependsOn: []string{"a"}, Condition: "never"},
		})
		ctx := context.Background()
		_ = e.advance(ctx, ex) // a completes
		_ = e.advance(ctx, ex) // b evaluated: condition false → skipped
		bStep, _ := store.GetStepExecByStepID(ctx, ex.ID, "b")
		if bStep == nil || bStep.Status != StepSkipped {
			t.Fatalf("b status = %v, want skipped", bStep)
		}
	})
}

func TestEvalCondition_PredicateMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := "ex-cond"

		// Build a real step exec so hasEvidenceType has an id to match.
		se := &StepExecution{ExecutionID: execID, StepID: "s1", StepType: StepTypeSendEmail, Status: StepCompleted}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution: %v", err)
		}
		if _, err := chain.Append(ctx, execID, se.ID, "link_clicked", "target", "tracker", map[string]any{}); err != nil {
			t.Fatalf("append link_clicked: %v", err)
		}
		byID := map[string]*StepExecution{"s1": se}

		// literals
		if !e.evalCondition(ctx, "", execID, byID) || !e.evalCondition(ctx, "always", execID, byID) || !e.evalCondition(ctx, "true", execID, byID) {
			t.Fatal("empty/always/true must be true")
		}
		if e.evalCondition(ctx, "false", execID, byID) || e.evalCondition(ctx, "never", execID, byID) {
			t.Fatal("false/never must be false")
		}
		// evidence-based
		if !e.evalCondition(ctx, "step:s1:clicked", execID, byID) {
			t.Fatal("clicked should be true (link_clicked evidence present)")
		}
		if e.evalCondition(ctx, "step:s1:not_clicked", execID, byID) {
			t.Fatal("not_clicked should be false")
		}
		if e.evalCondition(ctx, "step:s1:reported", execID, byID) {
			t.Fatal("reported should be false (no phishing_reported evidence)")
		}
		// status-based
		if !e.evalCondition(ctx, "step:s1:succeeded", execID, byID) {
			t.Fatal("succeeded should be true for a completed no-error step")
		}
		if e.evalCondition(ctx, "step:s1:failed", execID, byID) {
			t.Fatal("failed should be false for a completed step")
		}
		// timed_out via result
		se.Result = map[string]any{"timed_out": true}
		if !e.evalCondition(ctx, "step:s1:timeout", execID, byID) {
			t.Fatal("timeout should be true when result.timed_out is true")
		}
		if e.evalCondition(ctx, "step:s1:no_timeout", execID, byID) {
			t.Fatal("no_timeout should be false when timed_out is true")
		}
		// unknown predicate/format → defaults to true (fail-open per code)
		if !e.evalCondition(ctx, "step:s1:mystery", execID, byID) {
			t.Fatal("unknown predicate should default to true")
		}
		if !e.evalCondition(ctx, "garbage", execID, byID) {
			t.Fatal("unknown format should default to true")
		}
	})
}

func TestAdvance_WaitTimeoutCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "w", Type: StepTypeWait}})

		// Put the wait step into StepWaiting with a deadline in the past.
		past := time.Now().Add(-time.Minute)
		se := &StepExecution{ExecutionID: ex.ID, StepID: "w", StepType: StepTypeWait, Status: StepWaiting, ScheduledAt: &past}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution waiting: %v", err)
		}
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "w")
		if got.Status != StepCompleted {
			t.Fatalf("timed-out wait step status = %q, want completed", got.Status)
		}
	})
}

func TestAdvance_TriggerFires(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()

		tr := NewTriggerRegistry()
		tr.Register(StepTypeWaitForWebhook, func(context.Context, *Execution, *PlanStep, *StepExecution) (bool, map[string]any, error) {
			return true, map[string]any{"fired": true}, nil
		})
		e.WithTriggers(tr)

		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "h", Type: StepTypeWaitForWebhook}})
		se := &StepExecution{ExecutionID: ex.ID, StepID: "h", StepType: StepTypeWaitForWebhook, Status: StepWaiting}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution waiting: %v", err)
		}
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "h")
		if got.Status != StepCompleted || got.Result["fired"] != true {
			t.Fatalf("triggered step = %+v, want completed with fired=true", got)
		}
	})
}

func TestApproveStep_Completes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "ap", Type: StepTypeApproval}})
		if err := e.ApproveStep(ctx, ex.ID, "ap", "manager"); err != nil {
			t.Fatalf("ApproveStep: %v", err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "ap")
		if got.Status != StepCompleted || got.Result["approver"] != "manager" {
			t.Fatalf("approved step = %+v, want completed with approver=manager", got)
		}
	})
}

func TestAbortExecution_CancelsPendingAndWaiting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ctx := context.Background()
		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "p", Type: StepTypeNotify},
			{ID: "w", Type: StepTypeWait},
		})
		// Mark "w" waiting; leave "p" pending.
		wse := &StepExecution{ExecutionID: ex.ID, StepID: "w", StepType: StepTypeWait, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, wse)

		if err := e.AbortExecution(ctx, ex.ID); err != nil {
			t.Fatalf("AbortExecution: %v", err)
		}
		got, _ := store.GetExecution(ctx, ex.ID)
		if got.Status != ExecAborted {
			t.Fatalf("execution status = %q, want aborted", got.Status)
		}
		steps, _ := store.ListStepExecutions(ctx, ex.ID)
		for _, s := range steps {
			if s.Status != StepCancelled {
				t.Fatalf("step %s status = %q, want cancelled", s.StepID, s.Status)
			}
		}
	})
}

func TestComputeScore_HumanAndOverall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		chain := NewEvidenceChain(store)
		ctx := context.Background()
		execID := "ex-score"
		for _, ty := range []string{"email_sent", "email_sent", "link_clicked"} {
			if _, err := chain.Append(ctx, execID, "se1", ty, "system", "test", map[string]any{}); err != nil {
				t.Fatalf("append %s: %v", ty, err)
			}
		}
		score := e.computeScore(ctx, &Execution{ID: execID})
		if score.Human.Sent != 2 || score.Human.Clicked != 1 {
			t.Fatalf("human score = %+v, want Sent=2 Clicked=1", score.Human)
		}
		if score.Human.ClickRate != 0.5 {
			t.Fatalf("click rate = %v, want 0.5", score.Human.ClickRate)
		}
		// No edr/siem evidence → detBonus 0 → Overall = (1-0.5)*60 = 30.
		if score.Overall != 30 {
			t.Fatalf("overall = %v, want 30", score.Overall)
		}
	})
}

func TestBuiltinHandlers_SynchronousGuards(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.RegisterBuiltins(nil) // nil SMTP injector
		ctx := context.Background()

		// send_email with nil SMTP → Failed (synchronous guard).
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "em", Type: StepTypeSendEmail, Config: StepConfig{Email: &EmailConfig{}}}})
		se, _ := store.GetStepExecByStepID(ctx, ex.ID, "em")
		emStep := ex2step(store, ex, "em")
		if err := e.registry.Dispatch(ctx, ex, &emStep, se); err != nil {
			t.Fatalf("dispatch send_email: %v", err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "em")
		if got.Status != StepFailed {
			t.Fatalf("send_email with nil SMTP status = %q, want failed", got.Status)
		}

		// agent_task with nil config → Failed.
		ex2 := seedRunningExecution(t, store, e, []PlanStep{{ID: "at", Type: StepTypeAgentTask}})
		se2, _ := store.GetStepExecByStepID(ctx, ex2.ID, "at")
		atStep := ex2step(store, ex2, "at")
		_ = e.registry.Dispatch(ctx, ex2, &atStep, se2)
		got2, _ := store.GetStepExecByStepID(ctx, ex2.ID, "at")
		if got2.Status != StepFailed {
			t.Fatalf("agent_task with nil config status = %q, want failed", got2.Status)
		}

		// notify → Completed (log-only stub).
		ex3 := seedRunningExecution(t, store, e, []PlanStep{{ID: "no", Type: StepTypeNotify, Config: StepConfig{NotifyMsg: "hi"}}})
		se3, _ := store.GetStepExecByStepID(ctx, ex3.ID, "no")
		noStep := ex2step(store, ex3, "no")
		_ = e.registry.Dispatch(ctx, ex3, &noStep, se3)
		got3, _ := store.GetStepExecByStepID(ctx, ex3.ID, "no")
		if got3.Status != StepCompleted {
			t.Fatalf("notify status = %q, want completed", got3.Status)
		}
	})
}

// ex2step fetches the PlanStep for a given step id from the execution's plan.
func ex2step(store *Store, ex *Execution, stepID string) PlanStep {
	plan, _ := store.GetPlan(context.Background(), ex.PlanID)
	for _, ps := range plan.Steps {
		if ps.ID == stepID {
			return ps
		}
	}
	return PlanStep{ID: stepID}
}
```

- [ ] **Step 2: Run the tests**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/exercise/... -run 'TestLaunchExecution|TestAdvance_|TestEvalCondition_|TestApproveStep|TestAbortExecution|TestComputeScore|TestBuiltinHandlers_' -v 2>&1 | tail -50`
Expected: all listed executor tests PASS. If any FAIL, re-read the corresponding source in `executor.go` — the test's understanding is wrong, not the code.

- [ ] **Step 3: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/exercise/executor_test.go
git commit -m "test(exercise): add executor state-machine tests (dispatch, conditions, timeouts, triggers, score, lifecycle)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push
```

---

### Task 9: `webhook_test.go` + coverage & full-module verification

**Files:**
- Create: `orchestrator/internal/exercise/webhook_test.go`

**Interfaces:**
- Consumes: `fireWebhook(ctx context.Context, method, url string, headers map[string]string, body string) error`; `net/http/httptest`.

- [ ] **Step 1: Write the webhook test file**

`orchestrator/internal/exercise/webhook_test.go`:
```go
package exercise

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFireWebhook_SuccessAndDefaults(t *testing.T) {
	var gotMethod, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := fireWebhook(context.Background(), "", srv.URL, nil, `{"a":1}`); err != nil {
		t.Fatalf("fireWebhook: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("default method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Fatalf("default content-type = %q, want application/json", gotContentType)
	}
}

func TestFireWebhook_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := fireWebhook(context.Background(), "POST", srv.URL, nil, ""); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestFireWebhook_BadURL(t *testing.T) {
	if err := fireWebhook(context.Background(), "GET", "http://%zz", nil, ""); err == nil {
		t.Fatal("expected request-construction error for malformed URL")
	}
}
```

- [ ] **Step 2: Run the webhook tests**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/exercise/... -run TestFireWebhook -v`
Expected: all three PASS (no Docker — httptest is in-process).

- [ ] **Step 3: Check coverage on both packages**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/exercise/... ./internal/exercise/tracker/... -cover 2>&1 | grep -E '^(ok|FAIL)'`
Expected: both report `ok` with coverage. The `exercise` package should land in the high-80s to low-90s (see spec §7 — `smtp.go`'s network path and the two async `go func()` handler bodies cap it); `tracker` reports its pure-subset percentage. If `exercise` is **below ~85%**, inspect uncovered lines with `go test ./internal/exercise/... -coverprofile=cover.out && go tool cover -func=cover.out | grep -v '100.0%'` and add targeted tests for any *reachable* logic that was missed — do not add tests for the `smtp.go` network path or the async handler goroutine bodies.

- [ ] **Step 4: Run the full module suite (no regressions from the Task 1 harness change)**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./... 2>&1 | grep -E '^(FAIL|ok  .*exercise|ok  .*testutil)'`
Expected: no `FAIL` lines; `exercise`, `exercise/tracker`, and `testutil` all `ok`. (A transient container-startup failure right after a Docker restart can occur — see Phase 1 note; re-run once to confirm.)

- [ ] **Step 5: Verify `-short` runs without Docker**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/exercise/... ./internal/exercise/tracker/... -short 2>&1 | grep -E '^(ok|FAIL)'`
Expected: both `ok` (pure tests run, DB tests skip, no container started).

- [ ] **Step 6: Lint gates**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -l internal/exercise; echo "gofmt done"; go vet ./... && staticcheck ./... && go build ./...`
Expected: `gofmt -l internal/exercise` prints nothing; `vet`, `staticcheck`, `build` all clean.

- [ ] **Step 7: Commit and push**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/exercise/webhook_test.go
git commit -m "test(exercise): add fireWebhook tests; Phase 2 coverage verified

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push
```

- [ ] **Step 8: Update memory**

Update `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\project_test_generation_phase0.md` with a Phase 2 DONE section (commits, final `exercise`/`tracker` coverage numbers, the harness change, and any coverage-ceiling notes), and refresh its `description` + the `MEMORY.md` index line to mention Phase 2. Note Phase 3 (`api`) is next.

---

## Notes for the implementer

- **White-box access:** these tests are `package exercise`, so unexported identifiers (`advance`, `evalCondition`, `computeScore`, `hasEvidenceType`, `stepExecIDForStep`, `mergeMaps`, `mintHookToken`, `cryptoRandRead`, `fireWebhook`) are directly callable. Do not add exported shims.
- **Truncation isolation:** `RunWithPool` truncates every public table after each test, so hard-coded ids (`"ex-chain"`, `"agent-x"`, etc.) never collide across tests.
- **No goroutine assertions:** never assert on the result of `handleSendEmail`/`handleAgentTask`'s `go func()` — only their synchronous guard branches (Task 8's `TestBuiltinHandlers_SynchronousGuards`) and the state machine via synchronous fake handlers.
- **Determinism:** timeout tests set `ScheduledAt`/`StartedAt` in the past and call `advance` once; the scheduler test waits on a channel, never a sleep.
