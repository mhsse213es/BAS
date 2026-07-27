# BAS → Exercise Detection Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Exercise Engine's `wait_for_detection` step actually observe real BAS-triggered detections instead of silently timing out, by bridging `internal/verification.Store`'s (now, thanks to Phase A0, populated) automatic verdicts into the exercise's own evidence chain.

**Architecture:** Three layers — `verification.Store.CurrentApprovedForRun` (persistence, new method), `ResolveDetectionEvidence` (pure translation, new file), `Executor.bridgeVerifiedDetections`/rewritten `triggerWaitForDetection` (orchestration) — wired together via a new `WaitForDetectionConfig.ExecutionStepID` field that names which upstream `agent_task` step's BAS run to watch. Two already-shipped built-in templates (`builtin-ransomware-response`, `builtin-soc-drill`) are fixed to actually set it.

**Tech Stack:** Go, PostgreSQL (`pgxpool`), the existing `internal/testutil` Docker-testcontainer test harness.

## Global Constraints

- **Depends on Phase A0** (`docs/superpowers/plans/2026-07-27-automatic-verdict-persistence.md`), already DONE and pushed (`b209b70`..`b2e7617`). `verification.Record.RuleIDs` and the `rule_ids` column already exist — this plan consumes them, does not add them.
- `ExecutionStepID` empty must be byte-for-byte identical to today's behavior (`builtin-bec`'s `wait_detection` step is the regression guard — it must never be touched).
- `Executor.verification` nil must behave identically to `ExecutionStepID` empty (nil-safe — no existing test/call site is required to wire `WithVerification`).
- A permanent misconfiguration (bad `ExecutionStepID`, or a referenced step that produced no `bas_run_id`) must fail the step visibly via `SetStepStatus(..., StepFailed, ...)` — never silently retry forever, and never a bare returned error (which `triggers.Check`'s caller only logs).
- The dedup key is `(StepExecutionID, expectation_id)` — never re-append evidence for an expectation this step execution has already recorded, across ticks.
- Every extraction/refactor must leave existing `internal/exercise` and `internal/verification` test suites passing unmodified.
- Docker Desktop must be running for every `internal/verification`/`internal/exercise` test (Postgres testcontainer via `internal/testutil`). Check `docker info` before running these suites.

---

### Task 1: `verification.Store.CurrentApprovedForRun`

**Files:**
- Modify: `orchestrator/internal/verification/store.go` (new method, sibling to `CurrentForRun` at line 166)
- Test: `orchestrator/internal/verification/store_test.go`

**Interfaces:**
- Consumes: `recordCols`, `scanRecord`, `StateApproved` (all pre-existing, same file).
- Produces: `(*Store).CurrentApprovedForRun(ctx context.Context, runID string) ([]Record, error)`. Consumed by Task 4's `Executor.VerificationReader` interface.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/verification/store_test.go`:

```go
func TestCurrentApprovedForRun_OnlyApprovedRegardlessOfResult(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		if _, err := store.Attest(ctx, AttestInput{
			RunID: "run-approved-1", ExpectationID: "exp-approved-detected",
			Result: ResultDetected, WorkflowState: StateApproved, VerifiedBy: "analyst",
		}); err != nil {
			t.Fatalf("seed approved/detected: %v", err)
		}
		if _, err := store.Attest(ctx, AttestInput{
			RunID: "run-approved-1", ExpectationID: "exp-approved-notdetected",
			Result: ResultNotDetected, WorkflowState: StateApproved, VerifiedBy: "analyst",
		}); err != nil {
			t.Fatalf("seed approved/notdetected: %v", err)
		}
		if _, err := store.Attest(ctx, AttestInput{
			RunID: "run-approved-1", ExpectationID: "exp-pending",
			Result: ResultDetected, WorkflowState: StatePending, VerifiedBy: "analyst",
		}); err != nil {
			t.Fatalf("seed pending: %v", err)
		}

		got, err := store.CurrentApprovedForRun(ctx, "run-approved-1")
		if err != nil {
			t.Fatalf("CurrentApprovedForRun: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("len(got) = %d, want 2 (both Approved rows, regardless of Result; Pending excluded)", len(got))
		}
		byExp := map[string]Record{}
		for _, r := range got {
			byExp[r.ExpectationID] = r
		}
		if _, ok := byExp["exp-approved-detected"]; !ok {
			t.Error("missing exp-approved-detected")
		}
		if _, ok := byExp["exp-approved-notdetected"]; !ok {
			t.Error("missing exp-approved-notdetected")
		}
		if _, ok := byExp["exp-pending"]; ok {
			t.Error("exp-pending (WorkflowState=Pending) must be excluded")
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `orchestrator/`): `go test ./internal/verification/... -run TestCurrentApprovedForRun_OnlyApprovedRegardlessOfResult -v`
Expected: FAIL — `store.CurrentApprovedForRun undefined (type *Store has no field or method CurrentApprovedForRun)`

- [ ] **Step 3: Implement `CurrentApprovedForRun`**

In `orchestrator/internal/verification/store.go`, immediately after `CurrentForRun`'s closing `}` (the function ending at line 182), add:

```go
// CurrentApprovedForRun returns the active, Approved attestation for every
// expectation in a run, as a slice (not a map — callers decide how to key
// or group; a map would bake in "one record per expectation" as an
// assumption this method should not own). Unlike CurrentForRun (all
// workflow states, used by reporting's manual/API overlay), this
// pre-filters to Approved so callers never repeat that filter.
func (s *Store) CurrentApprovedForRun(ctx context.Context, runID string) ([]Record, error) {
	rows, err := s.db.Query(ctx, `SELECT `+recordCols+`
		FROM verification_history WHERE run_id=$1 AND active AND workflow_state=$2`,
		runID, StateApproved)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/verification/... -run TestCurrentApprovedForRun_OnlyApprovedRegardlessOfResult -v`
Expected: PASS

- [ ] **Step 5: Run the full verification suite to confirm no regression**

Run: `go test ./internal/verification/... -v -count=1`
Expected: 100% PASS

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/verification/store.go orchestrator/internal/verification/store_test.go
git commit -m "feat(verification): CurrentApprovedForRun — Approved-only, slice-returning read"
```

---

### Task 2: `WaitForDetectionConfig.ExecutionStepID`

**Files:**
- Modify: `orchestrator/internal/exercise/types.go:149-156` (`WaitForDetectionConfig`)

**Interfaces:**
- Produces: `WaitForDetectionConfig.ExecutionStepID string`. Consumed by Task 4's `triggerWaitForDetection`/`bridgeVerifiedDetections` and Task 5's template fixes.

This is a single-field addition with no new behavior on its own (nothing reads it until Task 4) — no dedicated test; it's exercised end-to-end by Task 4's integration tests. Per the plan's own Task Right-Sizing guidance, this stays a small step folded directly into the change rather than its own commit-worthy deliverable — but is still tracked as its own task here because Task 4 depends on the field existing before it can compile.

- [ ] **Step 1: Add the field**

In `orchestrator/internal/exercise/types.go`, `WaitForDetectionConfig` currently:

```go
type WaitForDetectionConfig struct {
	// DetectionTypes restricts which evidence types count as a "detection".
	// Defaults to ["edr_detected", "siem_alerted"] when empty.
	DetectionTypes []string `json:"detection_types,omitempty"`
	// MinCount is the minimum number of matching evidence records required.
	// Defaults to 1.
	MinCount int `json:"min_count,omitempty"`
}
```

Add `ExecutionStepID`:

```go
type WaitForDetectionConfig struct {
	// DetectionTypes restricts which evidence types count as a "detection".
	// Defaults to ["edr_detected", "siem_alerted"] when empty.
	DetectionTypes []string `json:"detection_types,omitempty"`
	// MinCount is the minimum number of matching evidence records required.
	// Defaults to 1.
	MinCount int `json:"min_count,omitempty"`

	// ExecutionStepID is the step ID (in the same plan) whose result holds
	// bas_run_id — the BAS run this detection step validates. Named
	// ExecutionStepID rather than AgentTaskStepID (unlike
	// WaitForAgentConfig's field) because the producer of that run ID may
	// not always be an agent_task step in the future; this field answers
	// "which step produced the verification records I consume," not "was
	// it specifically an agent task." Empty preserves today's exact
	// behavior: external/webhook/manual evidence only, no BAS-run lookup —
	// this is the correct (unchanged) setting for detection sources that
	// aren't BAS runs at all, e.g. builtin-bec's phishing-report flow.
	ExecutionStepID string `json:"execution_step_id,omitempty"`
}
```

- [ ] **Step 2: Confirm the package still builds**

Run: `go build ./internal/exercise/...`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/exercise/types.go
git commit -m "feat(exercise): add WaitForDetectionConfig.ExecutionStepID"
```

---

### Task 3: `ResolveDetectionEvidence` — the pure translation bridge

**Files:**
- Create: `orchestrator/internal/exercise/detectionbridge.go`
- Test: `orchestrator/internal/exercise/detectionbridge_test.go`

**Interfaces:**
- Consumes: `verification.Record{ExpectationID, RunID, TechniqueID, Domain, Provider, Result, RuleIDs}` (pre-existing, extended by Phase A0).
- Produces: `PendingEvidence{EvidenceType string, Payload map[string]any}`, `ResolveDetectionEvidence(records []verification.Record, alreadyRecorded map[string]bool) []PendingEvidence`. Consumed by Task 4's `bridgeVerifiedDetections`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/exercise/detectionbridge_test.go`:

```go
package exercise

import (
	"testing"

	"github.com/audspect/bas/internal/verification"
)

func TestResolveDetectionEvidence_DomainMapping(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		want   string
	}{
		{"endpoint maps to edr_detected", "endpoint", "edr_detected"},
		{"siem maps to siem_alerted", "siem", "siem_alerted"},
		{"identity maps to security_control_detected", "identity", "security_control_detected"},
		{"network maps to security_control_detected", "network", "security_control_detected"},
		{"cloud maps to security_control_detected", "cloud", "security_control_detected"},
		{"email maps to security_control_detected", "email", "security_control_detected"},
		{"dlp maps to security_control_detected", "dlp", "security_control_detected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			records := []verification.Record{{ExpectationID: "e1", Domain: tc.domain, Result: verification.ResultDetected}}
			got := ResolveDetectionEvidence(records, nil)
			if len(got) != 1 {
				t.Fatalf("len(got) = %d, want 1", len(got))
			}
			if got[0].EvidenceType != tc.want {
				t.Errorf("EvidenceType = %q, want %q", got[0].EvidenceType, tc.want)
			}
		})
	}
}

func TestResolveDetectionEvidence_NotDetectedProducesNoEvidence(t *testing.T) {
	records := []verification.Record{
		{ExpectationID: "e1", Domain: "endpoint", Result: verification.ResultNotDetected},
		{ExpectationID: "e2", Domain: "endpoint", Result: verification.ResultNotApplicable},
	}
	got := ResolveDetectionEvidence(records, nil)
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
}

func TestResolveDetectionEvidence_SkipsAlreadyRecorded(t *testing.T) {
	records := []verification.Record{
		{ExpectationID: "e1", Domain: "endpoint", Result: verification.ResultDetected},
		{ExpectationID: "e2", Domain: "endpoint", Result: verification.ResultDetected},
	}
	got := ResolveDetectionEvidence(records, map[string]bool{"e1": true})
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if id, _ := got[0].Payload["expectation_id"].(string); id != "e2" {
		t.Errorf("expectation_id = %q, want e2", id)
	}
}

func TestResolveDetectionEvidence_PayloadCarriesMetadata(t *testing.T) {
	records := []verification.Record{{
		ExpectationID: "e1", RunID: "run-1", TechniqueID: "T1055", Domain: "dlp",
		Provider: "trellix_dlp", Result: verification.ResultDetected,
		RuleIDs: []string{"AUDRULE-000042"},
	}}
	got := ResolveDetectionEvidence(records, nil)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	p := got[0].Payload
	if p["expectation_id"] != "e1" || p["run_id"] != "run-1" || p["technique_id"] != "T1055" ||
		p["control_domain"] != "dlp" || p["provider"] != "trellix_dlp" {
		t.Errorf("Payload = %+v, missing expected metadata", p)
	}
	ruleIDs, _ := p["rule_ids"].([]string)
	if len(ruleIDs) != 1 || ruleIDs[0] != "AUDRULE-000042" {
		t.Errorf("Payload[rule_ids] = %v, want [AUDRULE-000042]", p["rule_ids"])
	}
}

func TestResolveDetectionEvidence_EmptyRuleIDsDoesNotPanic(t *testing.T) {
	records := []verification.Record{{ExpectationID: "e1", Domain: "endpoint", Result: verification.ResultDetected}}
	got := ResolveDetectionEvidence(records, nil)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	_ = got[0].Payload["rule_ids"] // must not panic reading a nil []string
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/exercise/... -run TestResolveDetectionEvidence -v`
Expected: FAIL — `undefined: ResolveDetectionEvidence`

- [ ] **Step 3: Implement `detectionbridge.go`**

Create `orchestrator/internal/exercise/detectionbridge.go`:

```go
package exercise

import "github.com/audspect/bas/internal/verification"

// PendingEvidence is one exercise evidence row ResolveDetectionEvidence
// determined should be written. The Executor is responsible for the actual
// (stateful, hash-chained) write via EvidenceChain.Append.
type PendingEvidence struct {
	EvidenceType string
	Payload      map[string]any
}

// ResolveDetectionEvidence translates newly-approved verification records
// into exercise evidence. records is everything currently approved for the
// run (from verification.Store.CurrentApprovedForRun); alreadyRecorded is
// the set of expectation IDs this step execution has already emitted
// evidence for — dedup is an exercise concern (what counts as "already
// handled" for this step), not a verification-store concern, so it lives
// here, not in Store. Records with Result != "Detected" produce no
// evidence — this is translation, not gating; a NotDetected or
// NotApplicable record simply isn't evidence of anything happening yet.
func ResolveDetectionEvidence(records []verification.Record, alreadyRecorded map[string]bool) []PendingEvidence {
	var out []PendingEvidence
	for _, r := range records {
		if r.Result != "Detected" || alreadyRecorded[r.ExpectationID] {
			continue
		}
		evType := "security_control_detected"
		switch r.Domain {
		case "endpoint":
			evType = "edr_detected"
		case "siem":
			evType = "siem_alerted"
		}
		out = append(out, PendingEvidence{
			EvidenceType: evType,
			Payload: map[string]any{
				"expectation_id": r.ExpectationID,
				"run_id":         r.RunID,
				"technique_id":   r.TechniqueID,
				"control_domain": r.Domain,
				"provider":       r.Provider,
				"rule_ids":       r.RuleIDs,
			},
		})
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/exercise/... -run TestResolveDetectionEvidence -v`
Expected: PASS (all 5 test functions, including the 7 domain-mapping subtests)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/exercise/detectionbridge.go orchestrator/internal/exercise/detectionbridge_test.go
git commit -m "feat(exercise): ResolveDetectionEvidence — pure verification-to-evidence translation"
```

---

### Task 4: `Executor` orchestration — `bridgeVerifiedDetections` + rewritten `triggerWaitForDetection`

**Files:**
- Modify: `orchestrator/internal/exercise/executor.go` (imports, `Executor` struct, new `WithVerification` setter, new `VerificationReader` interface, rewritten `triggerWaitForDetection`, new `bridgeVerifiedDetections`)
- Test: `orchestrator/internal/exercise/executor_test.go`

**Interfaces:**
- Consumes: `verification.Record` (pre-existing), `ResolveDetectionEvidence`/`PendingEvidence` (Task 3), `WaitForDetectionConfig.ExecutionStepID` (Task 2), `Store.GetPlan`, `Store.GetStepExecByStepID`, `Store.SetStepStatus`, `Store.ListEvidence`, `Store.CountEvidenceForExec`, `EvidenceChain.Append` (all pre-existing).
- Produces: `Executor.VerificationReader` interface, `(*Executor).WithVerification(v VerificationReader) *Executor`. Consumed by Task 5's `main.go` wiring.

- [ ] **Step 1: Write the failing happy-path test**

Add to `orchestrator/internal/exercise/executor_test.go`:

```go
type fakeVerificationReader struct {
	records []verification.Record
	err     error
}

func (f fakeVerificationReader) CurrentApprovedForRun(context.Context, string) ([]verification.Record, error) {
	return f.records, f.err
}

func TestBridgeVerifiedDetections_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.WithVerification(fakeVerificationReader{records: []verification.Record{
			{ExpectationID: "exp-1", RunID: "run-1", Domain: "endpoint", Result: verification.ResultDetected},
		}})
		ctx := context.Background()

		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "sim", Type: StepTypeNotify},
			{ID: "wait_detect", Type: StepTypeWaitForDetection, DependsOn: []string{"sim"},
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "sim"}}},
		})
		// "sim" step completed and produced a bas_run_id.
		simSE := &StepExecution{ExecutionID: ex.ID, StepID: "sim", StepType: StepTypeNotify,
			Status: StepCompleted, Result: map[string]any{"bas_run_id": "run-1"}}
		if err := store.UpsertStepExecution(ctx, simSE); err != nil {
			t.Fatalf("UpsertStepExecution sim: %v", err)
		}
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		if err := store.UpsertStepExecution(ctx, waitSE); err != nil {
			t.Fatalf("UpsertStepExecution wait_detect: %v", err)
		}

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepCompleted {
			t.Fatalf("wait_detect status = %q, want completed", got.Status)
		}

		evs, err := store.ListEvidence(ctx, ex.ID)
		if err != nil {
			t.Fatalf("ListEvidence: %v", err)
		}
		found := false
		for _, ev := range evs {
			if ev.EvidenceType == "edr_detected" {
				found = true
				if ev.Payload["expectation_id"] != "exp-1" {
					t.Errorf("evidence payload expectation_id = %v, want exp-1", ev.Payload["expectation_id"])
				}
			}
		}
		if !found {
			t.Fatal("no edr_detected evidence was appended")
		}
	})
}
```

Check `orchestrator/internal/exercise/executor_test.go`'s existing imports — it already imports `"github.com/audspect/bas/internal/scenario"` and `"github.com/jackc/pgx/v5/pgxpool"`; add `"github.com/audspect/bas/internal/verification"` to that import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/exercise/... -run TestBridgeVerifiedDetections_HappyPath -v`
Expected: FAIL — `e.WithVerification undefined (type *Executor has no field or method WithVerification)`

- [ ] **Step 3: Add `fmt` and `verification` imports, the `VerificationReader` interface, and the `Executor.verification` field**

In `orchestrator/internal/exercise/executor.go`, the import block currently:

```go
import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"log"
	"strings"
	"time"
)
```

Add `fmt` and the verification package:

```go
import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/audspect/bas/internal/verification"
)
```

`Executor` currently:

```go
type Executor struct {
	store     *Store
	evidence  *EvidenceChain
	registry  *Registry
	triggers  *TriggerRegistry
	scheduler Scheduler
	dispatch  AgentDispatchFn
}
```

Add `verification`:

```go
type Executor struct {
	store        *Store
	evidence     *EvidenceChain
	registry     *Registry
	triggers     *TriggerRegistry
	scheduler    Scheduler
	dispatch     AgentDispatchFn
	verification VerificationReader
}

// VerificationReader is the narrow read interface the detection bridge
// needs from internal/verification.Store — kept narrow so internal/exercise
// does not take a hard dependency on the whole verification package
// surface. *verification.Store satisfies it.
type VerificationReader interface {
	CurrentApprovedForRun(ctx context.Context, runID string) ([]verification.Record, error)
}
```

Immediately after the existing `WithTriggers` method (`orchestrator/internal/exercise/executor.go`, currently ending at its closing `}`), add the new setter, matching that exact precedent:

```go
// WithTriggers replaces the trigger registry (useful in tests).
func (e *Executor) WithTriggers(t *TriggerRegistry) *Executor {
	e.triggers = t
	return e
}

// WithVerification wires the verification-store reader the detection bridge
// uses. Nil-safe: a wait_for_detection step with ExecutionStepID set but no
// verification reader configured behaves as if ExecutionStepID were empty.
func (e *Executor) WithVerification(v VerificationReader) *Executor {
	e.verification = v
	return e
}
```

- [ ] **Step 4: Run test to verify it still fails (compiles further now)**

Run: `go test ./internal/exercise/... -run TestBridgeVerifiedDetections_HappyPath -v`
Expected: FAIL — this time on `undefined: bridgeVerifiedDetections` or the trigger simply not firing (since `triggerWaitForDetection` hasn't been rewritten yet), not a compile error about `WithVerification`

- [ ] **Step 5: Rewrite `triggerWaitForDetection` and add `bridgeVerifiedDetections`**

`triggerWaitForDetection` currently:

```go
func (e *Executor) triggerWaitForDetection(ctx context.Context, ex *Execution, ps *PlanStep, _ *StepExecution) (bool, map[string]any, error) {
	cfg := ps.Config.WaitForDetection
	var types []string
	minCount := 1
	if cfg != nil {
		types = cfg.DetectionTypes
		if cfg.MinCount > 0 {
			minCount = cfg.MinCount
		}
	}
	n, err := e.store.CountEvidenceForExec(ctx, ex.ID, types)
	if err != nil {
		return false, nil, err
	}
	if n >= minCount {
		return true, map[string]any{"detection_count": n}, nil
	}
	return false, nil, nil
}
```

Replace with (note the third parameter, previously unused `_`, is now named `se` — it's needed by the new bridge call):

```go
func (e *Executor) triggerWaitForDetection(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) (bool, map[string]any, error) {
	cfg := ps.Config.WaitForDetection
	if cfg != nil && cfg.ExecutionStepID != "" && e.verification != nil {
		if err := e.bridgeVerifiedDetections(ctx, ex, ps, se, cfg.ExecutionStepID); err != nil {
			return false, nil, err
		}
	}

	var types []string
	minCount := 1
	if cfg != nil {
		types = cfg.DetectionTypes
		if cfg.MinCount > 0 {
			minCount = cfg.MinCount
		}
	}
	n, err := e.store.CountEvidenceForExec(ctx, ex.ID, types)
	if err != nil {
		return false, nil, err
	}
	if n >= minCount {
		return true, map[string]any{"detection_count": n}, nil
	}
	return false, nil, nil
}

// bridgeVerifiedDetections resolves executionStepID's BAS run, reads its
// approved verification records, translates them into exercise evidence via
// ResolveDetectionEvidence, and appends any new evidence. A permanent
// misconfiguration (bad executionStepID, or a completed step with no
// bas_run_id) fails the step visibly via SetStepStatus rather than
// returning a bare error — triggers.Check's caller only log.Printf's a
// returned error and retries forever, which would leave the step silently
// stuck. A run that simply hasn't produced results yet is not an error.
func (e *Executor) bridgeVerifiedDetections(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution, executionStepID string) error {
	plan, err := e.store.GetPlan(ctx, ex.PlanID)
	if err != nil {
		return err
	}
	found := false
	for _, s := range plan.Steps {
		if s.ID == executionStepID {
			found = true
			break
		}
	}
	if !found {
		return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed,
			fmt.Sprintf("wait_for_detection: execution_step_id %q does not reference a valid plan step", executionStepID))
	}

	srcSE, err := e.store.GetStepExecByStepID(ctx, ex.ID, executionStepID)
	if err != nil {
		// Referenced step is valid but hasn't started/produced a
		// StepExecution row yet — not an error, just not ready.
		return nil
	}
	if srcSE.Status != StepCompleted {
		return nil // still running — not an error, just not ready.
	}
	runID, _ := srcSE.Result["bas_run_id"].(string)
	if runID == "" {
		return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed,
			fmt.Sprintf("wait_for_detection: execution step %q completed but produced no bas_run_id", executionStepID))
	}

	records, err := e.verification.CurrentApprovedForRun(ctx, runID)
	if err != nil {
		return err
	}
	existing, err := e.store.ListEvidence(ctx, ex.ID)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, ev := range existing {
		if ev.StepExecutionID != se.ID {
			continue
		}
		if id, _ := ev.Payload["expectation_id"].(string); id != "" {
			seen[id] = true
		}
	}
	for _, p := range ResolveDetectionEvidence(records, seen) {
		if _, err := e.evidence.Append(ctx, ex.ID, se.ID, p.EvidenceType, "system", "verification_bridge", p.Payload); err != nil {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 6: Run the happy-path test to verify it passes**

Run: `go test ./internal/exercise/... -run TestBridgeVerifiedDetections_HappyPath -v`
Expected: PASS

- [ ] **Step 7: Write and pass the remaining edge-case tests**

Add to `orchestrator/internal/exercise/executor_test.go`:

```go
func TestBridgeVerifiedDetections_NotDetectedKeepsWaiting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.WithVerification(fakeVerificationReader{records: []verification.Record{
			{ExpectationID: "exp-1", RunID: "run-1", Domain: "endpoint", Result: verification.ResultNotDetected},
		}})
		ctx := context.Background()

		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "sim", Type: StepTypeNotify},
			{ID: "wait_detect", Type: StepTypeWaitForDetection, DependsOn: []string{"sim"},
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "sim"}}},
		})
		simSE := &StepExecution{ExecutionID: ex.ID, StepID: "sim", StepType: StepTypeNotify,
			Status: StepCompleted, Result: map[string]any{"bas_run_id": "run-1"}}
		_ = store.UpsertStepExecution(ctx, simSE)
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepWaiting {
			t.Fatalf("wait_detect status = %q, want still waiting (NotDetected produces no evidence)", got.Status)
		}
	})
}

func TestBridgeVerifiedDetections_MissingPlanStepFailsVisibly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.WithVerification(fakeVerificationReader{})
		ctx := context.Background()

		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "wait_detect", Type: StepTypeWaitForDetection,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "typo-does-not-exist"}}},
		})
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepFailed {
			t.Fatalf("wait_detect status = %q, want failed", got.Status)
		}
		if !strings.Contains(got.Error, "typo-does-not-exist") {
			t.Errorf("error = %q, want it to mention the bad execution_step_id", got.Error)
		}
	})
}

func TestBridgeVerifiedDetections_CompletedStepNoRunIDFailsVisibly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.WithVerification(fakeVerificationReader{})
		ctx := context.Background()

		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "approve", Type: StepTypeApproval},
			{ID: "wait_detect", Type: StepTypeWaitForDetection, DependsOn: []string{"approve"},
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "approve"}}},
		})
		// "approve" completed but is not an agent_task — no bas_run_id in its Result.
		approveSE := &StepExecution{ExecutionID: ex.ID, StepID: "approve", StepType: StepTypeApproval,
			Status: StepCompleted, Result: map[string]any{"approver": "manager"}}
		_ = store.UpsertStepExecution(ctx, approveSE)
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepFailed {
			t.Fatalf("wait_detect status = %q, want failed", got.Status)
		}
	})
}

func TestBridgeVerifiedDetections_EmptyExecutionStepIDUnchangedBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.WithVerification(fakeVerificationReader{records: []verification.Record{
			{ExpectationID: "exp-1", RunID: "run-1", Domain: "endpoint", Result: verification.ResultDetected},
		}})
		ctx := context.Background()

		// ExecutionStepID deliberately unset (builtin-bec's regression shape).
		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "wait_detect", Type: StepTypeWaitForDetection,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{}}},
		})
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepWaiting {
			t.Fatalf("wait_detect status = %q, want still waiting (no bridge, no external evidence posted)", got.Status)
		}
		evs, _ := store.ListEvidence(ctx, ex.ID)
		if len(evs) != 0 {
			t.Fatalf("evidence count = %d, want 0 — bridge must not run when ExecutionStepID is empty", len(evs))
		}
	})
}

func TestBridgeVerifiedDetections_NilVerificationReaderUnchangedBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool) // no WithVerification call
		ctx := context.Background()

		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "sim", Type: StepTypeNotify},
			{ID: "wait_detect", Type: StepTypeWaitForDetection, DependsOn: []string{"sim"},
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "sim"}}},
		})
		simSE := &StepExecution{ExecutionID: ex.ID, StepID: "sim", StepType: StepTypeNotify,
			Status: StepCompleted, Result: map[string]any{"bas_run_id": "run-1"}}
		_ = store.UpsertStepExecution(ctx, simSE)
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepWaiting {
			t.Fatalf("wait_detect status = %q, want still waiting — nil verification reader must not panic or fire", got.Status)
		}
	})
}

func TestBridgeVerifiedDetections_NoDuplicateEvidenceAcrossTicks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		reader := &mutableVerificationReader{records: []verification.Record{
			{ExpectationID: "exp-1", RunID: "run-1", Domain: "endpoint", Result: verification.ResultDetected},
		}}
		e.WithVerification(reader)
		ctx := context.Background()

		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "sim", Type: StepTypeNotify},
			{ID: "wait_detect", Type: StepTypeWaitForDetection, DependsOn: []string{"sim"},
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "sim", MinCount: 2}}},
		})
		simSE := &StepExecution{ExecutionID: ex.ID, StepID: "sim", StepType: StepTypeNotify,
			Status: StepCompleted, Result: map[string]any{"bas_run_id": "run-1"}}
		_ = store.UpsertStepExecution(ctx, simSE)
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil { // tick 1: exp-1 detected
			t.Fatalf("advance 1: %v", err)
		}
		// tick 2: exp-1 unchanged (must not duplicate), exp-2 newly detected.
		reader.records = append(reader.records, verification.Record{
			ExpectationID: "exp-2", RunID: "run-1", Domain: "endpoint", Result: verification.ResultDetected,
		})
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance 2: %v", err)
		}

		evs, err := store.ListEvidence(ctx, ex.ID)
		if err != nil {
			t.Fatalf("ListEvidence: %v", err)
		}
		bridged := 0
		seen := map[string]bool{}
		for _, ev := range evs {
			if ev.EvidenceType != "edr_detected" {
				continue
			}
			bridged++
			if id, _ := ev.Payload["expectation_id"].(string); id != "" {
				if seen[id] {
					t.Fatalf("duplicate evidence for expectation_id %q", id)
				}
				seen[id] = true
			}
		}
		if bridged != 2 {
			t.Fatalf("bridged evidence count = %d, want 2 (one per expectation, no duplicates)", bridged)
		}
	})
}

type mutableVerificationReader struct {
	records []verification.Record
}

func (m *mutableVerificationReader) CurrentApprovedForRun(context.Context, string) ([]verification.Record, error) {
	return m.records, nil
}

func TestBridgeVerifiedDetections_ReferencedStepNotYetCompletedKeepsWaiting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.WithVerification(fakeVerificationReader{})
		ctx := context.Background()

		// "sim" is a real plan step but has not been dispatched/completed yet
		// (still StepPending, as seedRunningExecution leaves an un-started
		// dependency) — this must be treated as "not ready", not an error.
		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "sim", Type: StepTypeNotify},
			{ID: "wait_detect", Type: StepTypeWaitForDetection, DependsOn: []string{"sim"},
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{ExecutionStepID: "sim"}}},
		})
		// wait_detect is forced into StepWaiting directly (bypassing the
		// normal DependsOn gate) purely to exercise the trigger in
		// isolation; "sim" is deliberately left at its seeded StepPending
		// status with no Result.
		waitSE := &StepExecution{ExecutionID: ex.ID, StepID: "wait_detect", StepType: StepTypeWaitForDetection, Status: StepWaiting}
		_ = store.UpsertStepExecution(ctx, waitSE)

		e.RegisterBuiltinTriggers()
		if err := e.advance(ctx, ex); err != nil {
			t.Fatalf("advance: %v", err)
		}

		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "wait_detect")
		if got.Status != StepWaiting {
			t.Fatalf("wait_detect status = %q, want still waiting (referenced step not completed yet is not an error)", got.Status)
		}
	})
}
```

`orchestrator/internal/exercise/executor_test.go`'s import block does not currently include `"strings"` (needed by `TestBridgeVerifiedDetections_MissingPlanStepFailsVisibly`'s `strings.Contains`) — add it.

- [ ] **Step 8: Run all the new tests**

Run: `go test ./internal/exercise/... -run 'TestBridgeVerifiedDetections' -v`
Expected: all 8 PASS

- [ ] **Step 9: Run the full exercise package suite to confirm no regression**

Run: `go test ./internal/exercise/... -v -count=1`
Expected: 100% PASS, including all pre-existing tests unmodified

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/exercise/executor.go orchestrator/internal/exercise/executor_test.go
git commit -m "feat(exercise): bridgeVerifiedDetections — wait_for_detection now observes real BAS verdicts"
```

---

### Task 5: Fix existing templates + wire `main.go`

**Files:**
- Modify: `orchestrator/internal/exercise/templates.go:144-151` (`builtin-ransomware-response`'s `wait_edr`), `:247-254` (`builtin-soc-drill`'s `wait_detect`)
- Modify: `orchestrator/cmd/server/main.go` (add `.WithVerification(verificationStore)` to the existing `exExecutor` construction)
- Create: `orchestrator/internal/exercise/templates_test.go` (confirmed not to exist yet in this codebase)

**Interfaces:**
- Consumes: `WaitForDetectionConfig.ExecutionStepID` (Task 2), `(*Executor).WithVerification` (Task 4), the existing `verificationStore := verification.NewStore(pool)` (`main.go:188`, from Phase A0's wiring).

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/exercise/templates_test.go`:

```go
func TestBuiltinTemplates_DetectionBridgeWiring(t *testing.T) {
	findStep := func(steps []PlanStep, id string) *PlanStep {
		for i := range steps {
			if steps[i].ID == id {
				return &steps[i]
			}
		}
		return nil
	}
	findTemplate := func(id string) *Template {
		for i := range BuiltinTemplates {
			if BuiltinTemplates[i].ID == id {
				return &BuiltinTemplates[i]
			}
		}
		return nil
	}

	ransomware := findTemplate("builtin-ransomware-response")
	if ransomware == nil {
		t.Fatal("builtin-ransomware-response template not found")
	}
	waitEDR := findStep(ransomware.Steps, "wait_edr")
	if waitEDR == nil || waitEDR.Config.WaitForDetection == nil || waitEDR.Config.WaitForDetection.ExecutionStepID != "sim" {
		t.Errorf("builtin-ransomware-response wait_edr.ExecutionStepID = %+v, want \"sim\"", waitEDR)
	}

	socDrill := findTemplate("builtin-soc-drill")
	if socDrill == nil {
		t.Fatal("builtin-soc-drill template not found")
	}
	waitDetect := findStep(socDrill.Steps, "wait_detect")
	if waitDetect == nil || waitDetect.Config.WaitForDetection == nil || waitDetect.Config.WaitForDetection.ExecutionStepID != "drill_sim" {
		t.Errorf("builtin-soc-drill wait_detect.ExecutionStepID = %+v, want \"drill_sim\"", waitDetect)
	}

	bec := findTemplate("builtin-bec")
	if bec == nil {
		t.Fatal("builtin-bec template not found")
	}
	waitDetection := findStep(bec.Steps, "wait_detection")
	if waitDetection == nil || waitDetection.Config.WaitForDetection == nil {
		t.Fatal("builtin-bec wait_detection step or its WaitForDetection config is missing")
	}
	if waitDetection.Config.WaitForDetection.ExecutionStepID != "" {
		t.Errorf("builtin-bec wait_detection.ExecutionStepID = %q, want empty (not a BAS-run-triggered detection)",
			waitDetection.Config.WaitForDetection.ExecutionStepID)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/exercise/... -run TestBuiltinTemplates_DetectionBridgeWiring -v`
Expected: FAIL — `wait_edr.ExecutionStepID = ..., want "sim"` (empty today)

- [ ] **Step 3: Fix `builtin-ransomware-response`'s `wait_edr` step**

In `orchestrator/internal/exercise/templates.go`, currently:

```go
			{
				ID: "wait_edr", Type: StepTypeWaitForDetection, Label: "Wait for EDR/SIEM detection",
				DependsOn: []string{"wait_sim"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes: []string{"edr_detected", "siem_alerted"},
				}},
			},
```

Add `ExecutionStepID: "sim"` (the `agent_task` step's ID earlier in this same template):

```go
			{
				ID: "wait_edr", Type: StepTypeWaitForDetection, Label: "Wait for EDR/SIEM detection",
				DependsOn: []string{"wait_sim"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes: []string{"edr_detected", "siem_alerted"},
					ExecutionStepID: "sim",
				}},
			},
```

- [ ] **Step 4: Fix `builtin-soc-drill`'s `wait_detect` step**

Currently:

```go
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC detection",
				DependsOn: []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes: []string{"edr_detected", "siem_alerted"},
				}},
			},
```

Add `ExecutionStepID: "drill_sim"`:

```go
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC detection",
				DependsOn: []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes: []string{"edr_detected", "siem_alerted"},
					ExecutionStepID: "drill_sim",
				}},
			},
```

Leave `builtin-bec`'s `wait_detection` step completely untouched — its `WaitForDetectionConfig` already exists with `DetectionTypes` set and no `ExecutionStepID`, and must stay that way.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/exercise/... -run TestBuiltinTemplates_DetectionBridgeWiring -v`
Expected: PASS

- [ ] **Step 6: Wire `main.go`**

In `orchestrator/cmd/server/main.go`, currently (around line 325, after Phase A0's wiring shifted line numbers — locate by content, not line number):

```go
	exExecutor := exercise.NewExecutor(exStore, exChain, exRegistry, exScheduler, nil)
	exExecutor.RegisterBuiltins(smtpInj, smsInj, slackInj, teamsInj)
	exExecutor.RegisterBuiltinTriggers()
```

Add `.WithVerification(verificationStore)` as its own line immediately after construction (`verificationStore` is already in scope — constructed at `main.go:188` by Phase A0's prerequisite work, well before this point):

```go
	exExecutor := exercise.NewExecutor(exStore, exChain, exRegistry, exScheduler, nil)
	exExecutor.WithVerification(verificationStore)
	exExecutor.RegisterBuiltins(smtpInj, smsInj, slackInj, teamsInj)
	exExecutor.RegisterBuiltinTriggers()
```

- [ ] **Step 7: Verify it compiles**

Run: `go build ./...`
Expected: no errors

- [ ] **Step 8: Run the full affected-package test suite**

Run: `go test ./internal/exercise/... ./internal/verification/... -v -count=1`
Expected: 100% PASS

- [ ] **Step 9: Run `go vet`**

Run: `go vet ./...`
Expected: no output

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/exercise/templates.go orchestrator/internal/exercise/templates_test.go orchestrator/cmd/server/main.go
git commit -m "feat(exercise): wire ExecutionStepID into builtin templates + main.go — detection bridge live"
```
