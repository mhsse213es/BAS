# DCSync Lab-Runtime — Phase A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (execution already decided: native/inline). Steps use `- [ ]` checkboxes.

**Goal:** Build the pure-Go controlled lab-runtime contract (`internal/adlabrt`) and the `adgate` "verified controlled lab" provenance origin, with the full lifecycle, fail-closed semantics, run-bound provenance, and lab-local evidence — all exercised against an in-process fake substrate. No real VM, no real DC, no attack commands.

**Architecture:** `adlabrt.Runtime.Validate` orchestrates provision → verify-isolation → mint run-bound provenance → `adgate.Decide` (requires BOTH verified-lab env **and** action authorization) → execute → collect evidence → guaranteed teardown. Infrastructure is reached only through a narrow `Substrate` interface; Phase A uses a configurable fake, Phase B (deferred) adds the real disposable-VM adapter.

**Tech Stack:** Go; `internal/adgate`, `internal/adprimitive`, `internal/scenario`, stdlib `context`/`time`/`fmt`.

**Spec:** `docs/superpowers/specs/2026-10-09-dcsync-lab-runtime-design.md`

## Global Constraints

- Pure Go, in-process. No real provisioning, no hypervisor/credentials, no network calls.
- `adgate` change is additive: a new allowable provenance origin; existing `SyntheticProvenance` allow and `LiveADProvenance`/zero-value deny behavior MUST remain unchanged (adrehearse + existing gate tests stay green).
- The gate decision requires **both** a verified-controlled-lab env provenance **and** `Authorization.Authorized` — verified isolation alone never allows (critical requirement).
- Provenance for a verified lab is minted **only** after isolation is verified, is **run+target bound**, and is unforgeable by struct literal (unexported origin pattern).
- Teardown runs on every path (success, error, panic) exactly once; teardown error is surfaced in the `Result`, never swallowed.
- Fail closed: provision-failed, isolation-unverified, gate-denied, execution-errored, evidence-inconclusive, and not-validated are each a distinct non-success `Status`.
- `dispatchRun`, run modes, and `adlab` planning semantics are untouched. No E2 per-gap content.
- Module import paths are `github.com/audspect/bas/internal/<pkg>`. Package test command from `orchestrator/`: `go test ./internal/adgate/... ./internal/adlabrt/...`.

## Review Focus

- Verified-lab env with **no** authorization must DENY (both-inputs) — Task 1, `TestDecide_VerifiedLabRequiresAuthorization`.
- `LiveADProvenance` and zero-value `Provenance{}` must still DENY after the change (no regression) — Task 1, `TestDecide_LiveAndUnknownStillDeny`.
- Provenance run-binding: a provenance minted for run/target A must not report bound to B — Task 1, `TestVerifiedLabProvenance_BoundToRunAndTarget`.
- Isolation unverified/uncertain must mint NO provenance and NOT execute — Task 2, `TestValidate_IsolationUnverifiedBlocksAndMintsNoProvenance`.
- Teardown must run exactly once even on a panic during execute — Task 2, `TestValidate_TeardownRunsOnPanic`.
- Evidence inconclusive and postcondition-not-observed are distinct fail-closed outcomes, not success — Task 2, `TestValidate_EvidenceInconclusive` + `TestValidate_NegativeControlNotValidated`.

---

### Task 1: `adgate` — verified-controlled-lab provenance origin

**Files:**
- Modify: `orchestrator/internal/adgate/gate.go`
- Test: `orchestrator/internal/adgate/verifiedlab_test.go` (new)

**Interfaces:**
- Consumes: existing `Request`, `Decision`, `Authorization`, `scenario.ExecutionClass`.
- Produces:
  - `func VerifiedControlledLabProvenance(runID, targetID string) Provenance`
  - `func (p Provenance) BoundTo(runID, targetID string) bool`
  - new const `ReasonAllowedControlledLabAuthorized Reason = "allowed_controlled_lab_authorized"`
  - `Decide` now allows a verified-lab env (still subject to class/auth rules).

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/adgate/verifiedlab_test.go`:

```go
package adgate

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestDecide_VerifiedLabAuthorizedAllows(t *testing.T) {
	d := Decide(Request{
		Class: scenario.ClassPotentiallyDestructive,
		Env:   VerifiedControlledLabProvenance("run-1", "target-1"),
		Auth:  Authorization{Authorized: true},
	})
	if !d.Allowed || d.Reason != ReasonAllowedControlledLabAuthorized {
		t.Fatalf("verified-lab + authorized must allow with lab reason, got %+v", d)
	}
}

func TestDecide_VerifiedLabRequiresAuthorization(t *testing.T) {
	d := Decide(Request{
		Class: scenario.ClassPotentiallyDestructive,
		Env:   VerifiedControlledLabProvenance("run-1", "target-1"),
		Auth:  Authorization{Authorized: false},
	})
	if d.Allowed || d.Reason != ReasonDeniedMissingAuth {
		t.Fatalf("verified isolation alone must NOT allow; needs auth, got %+v", d)
	}
}

func TestDecide_LiveAndUnknownStillDeny(t *testing.T) {
	for _, env := range []Provenance{LiveADProvenance(), {}} {
		d := Decide(Request{Class: scenario.ClassPotentiallyDestructive, Env: env, Auth: Authorization{Authorized: true}})
		if d.Allowed || d.Reason != ReasonDeniedNotSynthetic {
			t.Fatalf("live/unknown env must still deny not-synthetic, got %+v", d)
		}
	}
}

func TestDecide_VerifiedLabDestructiveNeedsApproval(t *testing.T) {
	base := Request{Class: scenario.ClassDestructive, Env: VerifiedControlledLabProvenance("r", "t"), Auth: Authorization{Authorized: true}}
	if d := Decide(base); d.Allowed || d.Reason != ReasonDeniedDestructiveNotApproved {
		t.Fatalf("destructive verified-lab without approval must deny, got %+v", d)
	}
	base.Auth.DestructiveApproved = true
	if d := Decide(base); !d.Allowed {
		t.Fatalf("destructive verified-lab WITH approval must allow, got %+v", d)
	}
}

func TestVerifiedLabProvenance_BoundToRunAndTarget(t *testing.T) {
	p := VerifiedControlledLabProvenance("run-A", "target-A")
	if !p.BoundTo("run-A", "target-A") {
		t.Fatal("provenance must report bound to its own run+target")
	}
	if p.BoundTo("run-B", "target-B") || p.BoundTo("run-A", "target-B") || p.BoundTo("run-B", "target-A") {
		t.Fatal("provenance must NOT report bound to a different run/target")
	}
	if SyntheticProvenance().BoundTo("run-A", "target-A") {
		t.Fatal("non-lab provenance must never report bound")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/adgate/... -run 'VerifiedLab|LiveAndUnknown' -v`
Expected: FAIL — `undefined: VerifiedControlledLabProvenance`, `undefined: ReasonAllowedControlledLabAuthorized`, `p.BoundTo undefined`.

- [ ] **Step 3: Implement the minimal change in `gate.go`**

Add the kind, fields, constructor, predicate, reason, and the Decide branch:

```go
// in the provenanceKind const block, add after provLiveAD:
	provVerifiedLab
```

Change the `Provenance` struct and add the constructor + predicate:

```go
// Provenance records where an environment came from ... (existing doc)
type Provenance struct {
	kind     provenanceKind
	runID    string // set only for provVerifiedLab: run-binding
	targetID string // set only for provVerifiedLab: target-binding
}

// VerifiedControlledLabProvenance marks a real environment the lab-runtime has
// provisioned AND independently verified as isolated. It is minted only by the
// lab-runtime, after verification, and is bound to a specific run and target.
func VerifiedControlledLabProvenance(runID, targetID string) Provenance {
	return Provenance{kind: provVerifiedLab, runID: runID, targetID: targetID}
}

// BoundTo reports whether this is a verified-controlled-lab provenance minted
// for exactly this run and target. Non-lab provenance is never bound.
func (p Provenance) BoundTo(runID, targetID string) bool {
	return p.kind == provVerifiedLab && p.runID == runID && p.targetID == targetID
}
```

Add the reason const:

```go
	ReasonAllowedControlledLabAuthorized Reason = "allowed_controlled_lab_authorized"
```

Change `Decide` so an allowed env is synthetic OR verified-lab, preserving rule order and returning the matching allow reason:

```go
func Decide(req Request) Decision {
	if req.Env.kind != provSynthetic && req.Env.kind != provVerifiedLab {
		return deny(ReasonDeniedNotSynthetic)
	}
	if !knownClass(req.Class) {
		return deny(ReasonDeniedUnknownClass)
	}
	if !req.Auth.Authorized {
		return deny(ReasonDeniedMissingAuth)
	}
	if req.Class == scenario.ClassDestructive && !req.Auth.DestructiveApproved {
		return deny(ReasonDeniedDestructiveNotApproved)
	}
	if req.Env.kind == provVerifiedLab {
		return Decision{Allowed: true, Reason: ReasonAllowedControlledLabAuthorized}
	}
	return Decision{Allowed: true, Reason: ReasonAllowedSyntheticAuthorized}
}
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `go test ./internal/adgate/... -run 'VerifiedLab|LiveAndUnknown' -v`
Expected: PASS.

- [ ] **Step 5: Run the full adgate + adrehearse suites (no regression)**

Run: `go test ./internal/adgate/... ./internal/adrehearse/...`
Expected: PASS (existing synthetic-allow and live/unknown-deny behavior unchanged).

- [ ] **Step 6: gofmt + commit**

```bash
gofmt -w internal/adgate/gate.go internal/adgate/verifiedlab_test.go
git add orchestrator/internal/adgate/gate.go orchestrator/internal/adgate/verifiedlab_test.go
git commit -m "feat(adgate): add verified-controlled-lab provenance origin"
```

---

### Task 2: `internal/adlabrt` — Runtime lifecycle + fake substrate + evidence

**Files:**
- Create: `orchestrator/internal/adlabrt/runtime.go`
- Test: `orchestrator/internal/adlabrt/runtime_test.go` (new, includes the fake substrate)

**Interfaces:**
- Consumes (Task 1): `adgate.VerifiedControlledLabProvenance`, `adgate.Decide`, `adgate.Request`, `adgate.Authorization`, `adgate.Decision`.
- Consumes: `adprimitive.Primitive` (for `RiskClass`), `adprimitive.Capability`, `scenario.ExecutionClass`.
- Produces: `Substrate`, `LabSpec`, `Target`, `IsolationResult`, `ValidationCase`, `Observation`, `Evidence`, `Status`, `Result`, `Runtime`, `func (r *Runtime) Validate(ctx, Request) Result`.

- [ ] **Step 1: Write the failing tests (with the fake substrate)**

Create `orchestrator/internal/adlabrt/runtime_test.go`:

```go
package adlabrt

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/adprimitive"
)

// fakeSub is an in-process Substrate whose every stage is scriptable.
type fakeSub struct {
	provErr      error
	iso          IsolationResult
	isoErr       error
	obs          Observation
	execErr      error
	execPanic    bool
	teardowns    int
	teardownErr  error
}

func (f *fakeSub) Provision(ctx context.Context, s LabSpec) (Target, error) {
	if f.provErr != nil {
		return Target{}, f.provErr
	}
	return Target{ID: "t-" + s.Name}, nil
}
func (f *fakeSub) VerifyIsolation(ctx context.Context, t Target) (IsolationResult, error) {
	return f.iso, f.isoErr
}
func (f *fakeSub) Execute(ctx context.Context, t Target, vc ValidationCase) (Observation, error) {
	if f.execPanic {
		panic("boom during execute")
	}
	return f.obs, f.execErr
}
func (f *fakeSub) Teardown(ctx context.Context, t Target) error {
	f.teardowns++
	return f.teardownErr
}

func dcsyncPrimitive() adprimitive.Primitive {
	return adprimitive.Primitive{ID: "dcsync", TechniqueID: "T1003.006", RiskClass: adprimitive.RiskPotentiallyDestructive}
}

func baseReq() Request {
	return Request{
		RunID: "run-1",
		Lab:   LabSpec{Name: "dcsync-dc"},
		Case: ValidationCase{
			Name:                "dcsync-replication",
			Primitive:           dcsyncPrimitive(),
			ExpectPostcondition: adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial},
		},
		Authorization: adgate.Authorization{Authorized: true},
	}
}

func verified() IsolationResult { return IsolationResult{Verified: true, Method: "fake"} }

func TestValidate_HappyPathValidated(t *testing.T) {
	f := &fakeSub{iso: verified(), obs: Observation{PostconditionObserved: true, Complete: true}}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusValidated {
		t.Fatalf("want validated, got %q (%+v)", res.Status, res)
	}
	if !res.Evidence.PostconditionObserved || !res.Evidence.Complete || res.Evidence.TargetID == "" {
		t.Fatalf("evidence incomplete: %+v", res.Evidence)
	}
	if f.teardowns != 1 {
		t.Fatalf("teardown must run exactly once, ran %d", f.teardowns)
	}
}

func TestValidate_ProvisionFailed(t *testing.T) {
	f := &fakeSub{provErr: errors.New("no capacity")}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusProvisionFailed {
		t.Fatalf("want provision_failed, got %q", res.Status)
	}
}

func TestValidate_IsolationUnverifiedBlocksAndMintsNoProvenance(t *testing.T) {
	f := &fakeSub{iso: IsolationResult{Verified: false, Detail: "probe reached prod"}, obs: Observation{PostconditionObserved: true, Complete: true}}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusIsolationUnverified {
		t.Fatalf("want isolation_unverified, got %q", res.Status)
	}
	if res.Evidence.PostconditionObserved {
		t.Fatalf("must NOT execute when isolation unverified: %+v", res.Evidence)
	}
	if f.teardowns != 1 {
		t.Fatalf("teardown must still run, ran %d", f.teardowns)
	}
}

func TestValidate_IsolationProbeErrorBlocks(t *testing.T) {
	f := &fakeSub{isoErr: errors.New("probe failed"), iso: IsolationResult{Verified: true}}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusIsolationUnverified {
		t.Fatalf("probe error must be treated as unverified, got %q", res.Status)
	}
}

func TestValidate_GateDeniedWhenNotAuthorized(t *testing.T) {
	f := &fakeSub{iso: verified(), obs: Observation{PostconditionObserved: true, Complete: true}}
	req := baseReq()
	req.Authorization = adgate.Authorization{Authorized: false}
	res := (&Runtime{Sub: f}).Validate(context.Background(), req)
	if res.Status != StatusGateDenied || res.Decision.Reason != adgate.ReasonDeniedMissingAuth {
		t.Fatalf("verified lab but unauthorized must be gate_denied/missing_auth, got %q/%+v", res.Status, res.Decision)
	}
	if res.Evidence.PostconditionObserved {
		t.Fatalf("must not execute when gate denies")
	}
}

func TestValidate_ExecutionErrored(t *testing.T) {
	f := &fakeSub{iso: verified(), execErr: errors.New("agent lost")}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusExecutionErrored {
		t.Fatalf("want execution_errored, got %q", res.Status)
	}
	if f.teardowns != 1 {
		t.Fatalf("teardown must run on execution error, ran %d", f.teardowns)
	}
}

func TestValidate_EvidenceInconclusive(t *testing.T) {
	f := &fakeSub{iso: verified(), obs: Observation{PostconditionObserved: true, Complete: false}}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusEvidenceInconclusive {
		t.Fatalf("incomplete evidence must fail closed, got %q", res.Status)
	}
}

func TestValidate_NegativeControlNotValidated(t *testing.T) {
	f := &fakeSub{iso: verified(), obs: Observation{PostconditionObserved: false, Complete: true}}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.Status != StatusNotValidated {
		t.Fatalf("complete evidence with postcondition NOT observed must be not_validated, got %q", res.Status)
	}
}

func TestValidate_TeardownRunsOnPanic(t *testing.T) {
	f := &fakeSub{iso: verified(), execPanic: true}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if f.teardowns != 1 {
		t.Fatalf("teardown must run exactly once after panic, ran %d", f.teardowns)
	}
	if res.Status != StatusExecutionErrored {
		t.Fatalf("panic must be recovered into execution_errored, got %q", res.Status)
	}
}

func TestValidate_TeardownErrorSurfaced(t *testing.T) {
	f := &fakeSub{iso: verified(), obs: Observation{PostconditionObserved: true, Complete: true}, teardownErr: errors.New("leak")}
	res := (&Runtime{Sub: f}).Validate(context.Background(), baseReq())
	if res.TeardownErr == nil {
		t.Fatal("teardown error must be surfaced in Result, not swallowed")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/adlabrt/...`
Expected: FAIL — build error, `undefined: Runtime`, `undefined: Substrate`, etc.

- [ ] **Step 3: Implement `runtime.go`**

Create `orchestrator/internal/adlabrt/runtime.go`:

```go
// Package adlabrt is the controlled AD lab-runtime: it provisions a controlled
// environment, independently verifies its isolation, mints run-bound provenance,
// gates the action (adgate requires BOTH verified-lab env AND authorization),
// executes an already-reusable validation case, collects lab-local evidence, and
// guarantees teardown. Infrastructure is reached only through Substrate; Phase A
// uses a fake, Phase B (deferred) adds a real disposable-VM adapter. It does not
// touch dispatchRun.
package adlabrt

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/scenario"
)

// Substrate is the only seam to real infrastructure.
type Substrate interface {
	Provision(ctx context.Context, spec LabSpec) (Target, error)
	VerifyIsolation(ctx context.Context, t Target) (IsolationResult, error)
	Execute(ctx context.Context, t Target, vc ValidationCase) (Observation, error)
	Teardown(ctx context.Context, t Target) error
}

type LabSpec struct{ Name string }
type Target struct{ ID string }
type IsolationResult struct {
	Verified bool
	Method   string
	Detail   string
}

// ValidationCase is the action to validate and its expected postcondition.
type ValidationCase struct {
	Name                string
	Primitive           adprimitive.Primitive
	ExpectPostcondition adprimitive.Capability
}

// Observation is the substrate's raw result; the runtime interprets it.
type Observation struct {
	PostconditionObserved bool
	Complete              bool // false => inconclusive
	Detail                string
}

// Evidence is the lab-local record (telemetry adapter is a future boundary).
type Evidence struct {
	RunID                 string
	LabName               string
	TargetID              string
	CaseName              string
	PostconditionObserved bool
	Complete              bool
	Detail                string
	StartedAt             time.Time
	EndedAt               time.Time
}

type Status string

const (
	StatusValidated            Status = "validated"
	StatusProvisionFailed      Status = "provision_failed"
	StatusIsolationUnverified  Status = "isolation_unverified"
	StatusGateDenied           Status = "gate_denied"
	StatusExecutionErrored     Status = "execution_errored"
	StatusEvidenceInconclusive Status = "evidence_inconclusive"
	StatusNotValidated         Status = "not_validated"
)

// Result is the outcome of one Validate run.
type Result struct {
	Status      Status
	Decision    adgate.Decision // zero if the gate was not reached
	Evidence    Evidence
	TeardownErr error
}

// Request is one validation request.
type Request struct {
	RunID         string
	Lab           LabSpec
	Case          ValidationCase
	Authorization adgate.Authorization
}

// Runtime orchestrates the lifecycle. Now is injectable for deterministic tests.
type Runtime struct {
	Sub Substrate
	Now func() time.Time
}

func (r *Runtime) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Validate runs the full controlled lifecycle for one authorized case and
// guarantees teardown on every path.
func (r *Runtime) Validate(ctx context.Context, req Request) (res Result) {
	ev := Evidence{RunID: req.RunID, LabName: req.Lab.Name, CaseName: req.Case.Name, StartedAt: r.now()}

	target, err := r.Sub.Provision(ctx, req.Lab)
	if err != nil {
		ev.Detail = "provision: " + err.Error()
		ev.EndedAt = r.now()
		return Result{Status: StatusProvisionFailed, Evidence: ev}
	}
	ev.TargetID = target.ID

	// Teardown is guaranteed from here on — success, error, or panic.
	defer func() {
		if rec := recover(); rec != nil {
			res.Status = StatusExecutionErrored
			ev.Detail = fmt.Sprintf("panic: %v", rec)
		}
		if e := r.Sub.Teardown(ctx, target); e != nil {
			res.TeardownErr = e
		}
		ev.EndedAt = r.now()
		res.Evidence = ev
	}()

	iso, err := r.Sub.VerifyIsolation(ctx, target)
	if err != nil || !iso.Verified {
		// Unverifiable isolation is treated as NOT isolated: fail closed, no
		// provenance minted, no execution.
		res.Status = StatusIsolationUnverified
		return res
	}

	// Provenance is minted ONLY after verification, bound to this run + target.
	prov := adgate.VerifiedControlledLabProvenance(req.RunID, target.ID)
	decision := adgate.Decide(adgate.Request{
		Class: scenario.ExecutionClass(req.Case.Primitive.RiskClass),
		Env:   prov,
		Auth:  req.Authorization,
	})
	res.Decision = decision
	if !decision.Allowed {
		res.Status = StatusGateDenied
		return res
	}

	obs, err := r.Sub.Execute(ctx, target, req.Case)
	if err != nil {
		res.Status = StatusExecutionErrored
		ev.Detail = "execute: " + err.Error()
		return res
	}
	ev.PostconditionObserved = obs.PostconditionObserved
	ev.Complete = obs.Complete
	if obs.Detail != "" {
		ev.Detail = obs.Detail
	}

	switch {
	case !obs.Complete:
		res.Status = StatusEvidenceInconclusive
	case !obs.PostconditionObserved:
		res.Status = StatusNotValidated
	default:
		res.Status = StatusValidated
	}
	return res
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/adlabrt/...`
Expected: PASS (all 10 tests).

- [ ] **Step 5: gofmt + vet + commit**

```bash
gofmt -w internal/adlabrt/runtime.go internal/adlabrt/runtime_test.go
go vet ./internal/adlabrt/...
git add orchestrator/internal/adlabrt/runtime.go orchestrator/internal/adlabrt/runtime_test.go
git commit -m "feat(adlabrt): add controlled lab-runtime lifecycle (Phase A, fake substrate)"
```

---

## Notes for the executor

- Run all `go` commands from `orchestrator/`.
- `adprimitive.RiskClass` values convert directly to `scenario.ExecutionClass` (same underlying strings — see `adrehearse.chainClass`), so `scenario.ExecutionClass(primitive.RiskClass)` is correct; `RiskPotentiallyDestructive` → `ClassPotentiallyDestructive`, allowed with `Authorized` alone.
- Verify `adprimitive.CapDomainCredentialMaterial` is the exact exported name before relying on it (DCSync's postcondition in `catalog.go`); if it differs, use the real constant and ledger the correction.
- Phase A proves the contract against a fake substrate only. The real disposable-VM substrate + real DCSync atomic + real isolation probe are Phase B, deferred, and get their own spec/plan.
- Scope verification to `./internal/adgate/... ./internal/adlabrt/... ./internal/adrehearse/...`; the full module suite is heavy/Docker-touching and out of scope for this plan.
