# P5 adlabhyperv (lab-independent slice) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the lab-independent core of the real Hyper-V lab substrate — a new `internal/adlabhyperv` package that implements `adlabrt.Substrate` behind a faked command seam, with a declarative M1 topology catalog and a fail-closed isolation evaluator — plus an operator runbook, all TDD against fakes with no hypervisor.

**Architecture:** `adlabhyperv.HyperV` implements the existing `adlabrt.Substrate` seam. All host interaction goes through a narrow `Commander` interface (faked in tests; the real Hyper-V implementation is lab-gated and out of scope). Topology detail lives in a declarative catalog keyed by `LabSpec.Name`, keeping the `Substrate` seam provider-neutral. Isolation is a pure evaluator that aggregates probe results fail-closed.

**Tech Stack:** Go (stdlib + `internal/adlabrt`, `internal/adprimitive`, `internal/adgate`, `internal/scenario`); `go test` on the Windows build host.

**Spec:** `docs/superpowers/specs/2026-10-10-p5-ad-lab-substrate-hyperv-design.md` (§11 is this slice; §10/§12 lab-gated work is excluded).

**Execution:** Native/inline (standing Inline Over Subagents preference) — decided, not a question.

## Global Constraints

- New package `internal/adlabhyperv` only. **No changes** to `adlabrt.Substrate`/`Runtime`, `adgate`, `adlab`, `adcompose`, or `dispatchRun`.
- `adlabhyperv.HyperV` must satisfy `adlabrt.Substrate` (compile-time assertion required).
- Provider-neutral: all host interaction behind the `Commander` seam; topology detail only in the catalog. No Hyper-V binary/PowerShell invocation in this slice.
- Isolation is **fail-closed**: `Verified` is true only when every required check returned a `Determinate` and `Passed` result. Missing or indeterminate ⇒ not verified.
- No attack/payload content authored here. No real provisioning, no live probes, no live DC run (lab-gated, excluded).
- Dependencies limited to the four `internal/*` packages above + Go stdlib.
- TDD throughout; run `go test ./internal/adlabhyperv/ -count=1` per task; `go vet ./internal/adlabhyperv/` must be clean.

## Review Focus

- **Empty required-checks map:** `EvaluateIsolation` with no probe results must fail closed (`Verified:false`), never vacuously pass → Task 2.
- **Indeterminate-but-passed probe:** a `ProbeResult{Passed:true, Determinate:false}` must be treated as NOT isolated → Task 2.
- **Teardown of a half-provisioned target:** `Teardown` after a post-provision failure (e.g. isolation unverified) must return nil when the commander reports done, and be safe to call again → Task 3 + Task 5.
- **Malformed/incomplete execution output:** an `Execute` whose commander `Output.Complete` is false must map to `evidence_inconclusive`, never a false `validated` → Task 4 + Task 5.
- **Unknown topology name:** `Provision` with a `LabSpec.Name` absent from the catalog must error (→ `provision_failed`), never silently provision an empty topology → Task 3 + Task 5.

---

### Task 1: Lab-topology catalog

**Files:**
- Create: `orchestrator/internal/adlabhyperv/topology.go`
- Test: `orchestrator/internal/adlabhyperv/topology_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `Role` (`RoleDC`/`RoleClient`/`RoleADCS`); `VMSpec{Name string; Role Role; BaseCheckpoint string; VCPU, MemoryMB, DiskGB int}`; `AttackerIdentity{Principal, Rights string}`; `Topology{Name, Switch string; VMs []VMSpec; Attacker AttackerIdentity}`; `func LookupTopology(name string) (Topology, bool)`. M1 catalog entry key: `"dc-only"`.

- [ ] **Step 1: Write the failing test**

```go
package adlabhyperv

import "testing"

func TestLookupTopology_DCOnlyIsASingleIsolatedDC(t *testing.T) {
	topo, ok := LookupTopology("dc-only")
	if !ok {
		t.Fatal("dc-only topology must exist")
	}
	if topo.Switch == "" {
		t.Error("topology must name a dedicated private virtual switch")
	}
	if len(topo.VMs) != 1 || topo.VMs[0].Role != RoleDC {
		t.Fatalf("dc-only must be exactly one DC VM, got %+v", topo.VMs)
	}
	if topo.VMs[0].BaseCheckpoint == "" || topo.VMs[0].MemoryMB <= 0 || topo.VMs[0].VCPU <= 0 {
		t.Errorf("DC VM must carry a base checkpoint and positive resource profile: %+v", topo.VMs[0])
	}
	if topo.Attacker.Principal == "" || topo.Attacker.Rights == "" {
		t.Error("topology must name the controlled attacker identity and its granted right")
	}
}

func TestLookupTopology_UnknownNameIsNotFound(t *testing.T) {
	if _, ok := LookupTopology("does-not-exist"); ok {
		t.Fatal("unknown topology name must return ok=false, not a zero-value topology")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/adlabhyperv/ -run TestLookupTopology -count=1`
Expected: FAIL — build error, `undefined: LookupTopology` / undefined types.

- [ ] **Step 3: Write minimal implementation**

```go
// Package adlabhyperv is the real, provider-neutral Hyper-V backing for the
// adlabrt controlled-lab substrate. This slice is lab-independent: the host
// interaction is a faked Commander seam (the real Hyper-V implementation is
// lab-gated). Topology detail lives here so the adlabrt.Substrate seam stays
// provider-neutral. See docs/superpowers/specs/2026-10-10-p5-ad-lab-substrate-hyperv-design.md.
package adlabhyperv

// Role is the function a lab VM performs.
type Role string

const (
	RoleDC     Role = "dc"
	RoleClient Role = "client"
	RoleADCS   Role = "adcs"
)

// VMSpec is one VM in a lab topology and its resource profile.
type VMSpec struct {
	Name           string
	Role           Role
	BaseCheckpoint string // clean, offline, prepared base to clone/revert to
	VCPU           int
	MemoryMB       int
	DiskGB         int
}

// AttackerIdentity is the controlled principal a validation case runs as, and
// the specific right it is granted. Documented, never a production principal.
type AttackerIdentity struct {
	Principal string
	Rights    string
}

// Topology is a declarative lab definition keyed by LabSpec.Name. It is the
// single place lab detail lives, so the adlabrt.Substrate seam stays
// provider-neutral.
type Topology struct {
	Name     string
	Switch   string // dedicated PRIVATE virtual switch; never External
	VMs      []VMSpec
	Attacker AttackerIdentity
}

// catalog holds the supported topologies. M1: a single self-contained DC.
var catalog = map[string]Topology{
	"dc-only": {
		Name:   "dc-only",
		Switch: "audspect-lab-private",
		VMs: []VMSpec{{
			Name:           "dc01",
			Role:           RoleDC,
			BaseCheckpoint: "dc01-base-clean",
			VCPU:           2,
			MemoryMB:       4096,
			DiskGB:         40,
		}},
		Attacker: AttackerIdentity{Principal: `LAB\attacker`, Rights: "AllExtendedRights@domain-root"},
	},
}

// LookupTopology returns the named topology; ok is false for an unknown name,
// so an unknown lab never silently resolves to an empty topology.
func LookupTopology(name string) (Topology, bool) {
	t, ok := catalog[name]
	return t, ok
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/adlabhyperv/ -run TestLookupTopology -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/adlabhyperv/topology.go orchestrator/internal/adlabhyperv/topology_test.go
git commit -m "feat(adlabhyperv): declarative M1 dc-only lab-topology catalog"
```

---

### Task 2: Fail-closed isolation evaluator

**Files:**
- Create: `orchestrator/internal/adlabhyperv/isolation.go`
- Test: `orchestrator/internal/adlabhyperv/isolation_test.go`

**Interfaces:**
- Consumes: `adlabrt.IsolationResult` (fields `Verified bool`, `Method string`, `Detail string`).
- Produces: `CheckKind` (`CheckPrivateSwitch`/`CheckNoExternalRoute`/`CheckNoProductionAD`/`CheckDistinctIdentity`); `ProbeResult{Passed, Determinate bool; Detail string}`; `func RequiredChecks() []CheckKind`; `func EvaluateIsolation(required []CheckKind, results map[CheckKind]ProbeResult) adlabrt.IsolationResult`.

- [ ] **Step 1: Write the failing test**

```go
package adlabhyperv

import (
	"strings"
	"testing"
)

func allPass() map[CheckKind]ProbeResult {
	m := map[CheckKind]ProbeResult{}
	for _, c := range RequiredChecks() {
		m[c] = ProbeResult{Passed: true, Determinate: true}
	}
	return m
}

func TestEvaluateIsolation_AllChecksPassAndDeterminateVerifies(t *testing.T) {
	res := EvaluateIsolation(RequiredChecks(), allPass())
	if !res.Verified {
		t.Fatalf("all-pass must verify, got %+v", res)
	}
	if !strings.Contains(res.Method, string(CheckNoExternalRoute)) {
		t.Errorf("Method must record the checks run, got %q", res.Method)
	}
}

func TestEvaluateIsolation_EmptyResultsFailClosed(t *testing.T) {
	res := EvaluateIsolation(RequiredChecks(), map[CheckKind]ProbeResult{})
	if res.Verified {
		t.Fatal("no probe results must fail closed, never verify")
	}
}

func TestEvaluateIsolation_IndeterminateIsNotIsolated(t *testing.T) {
	m := allPass()
	m[CheckNoExternalRoute] = ProbeResult{Passed: true, Determinate: false, Detail: "probe timed out"}
	res := EvaluateIsolation(RequiredChecks(), m)
	if res.Verified {
		t.Fatal("an indeterminate check must be treated as not isolated")
	}
	if !strings.Contains(res.Detail, string(CheckNoExternalRoute)) {
		t.Errorf("Detail should name the failing check, got %q", res.Detail)
	}
}

func TestEvaluateIsolation_FailedCheckDenies(t *testing.T) {
	m := allPass()
	m[CheckPrivateSwitch] = ProbeResult{Passed: false, Determinate: true, Detail: "adapter on External switch"}
	if EvaluateIsolation(RequiredChecks(), m).Verified {
		t.Fatal("a failed check must deny")
	}
}

func TestEvaluateIsolation_MissingOneRequiredCheckDenies(t *testing.T) {
	m := allPass()
	delete(m, CheckDistinctIdentity)
	if EvaluateIsolation(RequiredChecks(), m).Verified {
		t.Fatal("a missing required check must deny (fail closed)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/adlabhyperv/ -run TestEvaluateIsolation -count=1`
Expected: FAIL — `undefined: EvaluateIsolation` / undefined `CheckKind` constants.

- [ ] **Step 3: Write minimal implementation**

```go
package adlabhyperv

import (
	"fmt"
	"strings"

	"github.com/audspect/bas/internal/adlabrt"
)

// CheckKind is one isolation check. All are required for M1.
type CheckKind string

const (
	CheckPrivateSwitch    CheckKind = "private_switch"     // every adapter on the dedicated private switch
	CheckNoExternalRoute  CheckKind = "no_external_route"  // active probe: cannot reach host net / internet / non-lab host
	CheckNoProductionAD   CheckKind = "no_production_ad"   // no trust path to any real directory
	CheckDistinctIdentity CheckKind = "distinct_identity"  // lab SIDs/creds are the lab's own
)

// ProbeResult is one check's outcome. Determinate=false means the check could
// not be conclusively evaluated and MUST be treated as not isolated.
type ProbeResult struct {
	Passed      bool
	Determinate bool
	Detail      string
}

// RequiredChecks is the full M1 isolation checklist.
func RequiredChecks() []CheckKind {
	return []CheckKind{CheckPrivateSwitch, CheckNoExternalRoute, CheckNoProductionAD, CheckDistinctIdentity}
}

// EvaluateIsolation aggregates probe results FAIL-CLOSED: Verified is true only
// when every required check has a Determinate, Passed result. A missing or
// indeterminate result denies. Method records which checks ran and their
// outcomes; Detail names the first failing/missing check.
func EvaluateIsolation(required []CheckKind, results map[CheckKind]ProbeResult) adlabrt.IsolationResult {
	var method []string
	verified := true
	detail := ""
	for _, c := range required {
		r, present := results[c]
		status := "ok"
		switch {
		case !present:
			status = "missing"
		case !r.Determinate:
			status = "indeterminate"
		case !r.Passed:
			status = "failed"
		}
		method = append(method, fmt.Sprintf("%s=%s", c, status))
		if status != "ok" && verified {
			verified = false
			detail = fmt.Sprintf("%s: %s (%s)", c, status, r.Detail)
		}
	}
	return adlabrt.IsolationResult{
		Verified: verified,
		Method:   "checks[" + strings.Join(method, ",") + "]",
		Detail:   detail,
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/adlabhyperv/ -run TestEvaluateIsolation -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/adlabhyperv/isolation.go orchestrator/internal/adlabhyperv/isolation_test.go
git commit -m "feat(adlabhyperv): fail-closed isolation evaluator"
```

---

### Task 3: Command seam + adapter Provision/Teardown

**Files:**
- Create: `orchestrator/internal/adlabhyperv/command.go`
- Create: `orchestrator/internal/adlabhyperv/adapter.go`
- Create: `orchestrator/internal/adlabhyperv/support_test.go` (shared fake commander)
- Test: `orchestrator/internal/adlabhyperv/adapter_test.go`

**Interfaces:**
- Consumes: `LookupTopology` (Task 1); `adlabrt.LabSpec{Name string}`, `adlabrt.Target{ID string}`.
- Produces: `CommandKind` (`CmdProvision`/`CmdProbe`/`CmdExecuteCase`/`CmdTeardown`); `Command{Kind CommandKind; Args map[string]string}`; `Output{OK bool; TargetID string; Passed, Determinate, PostconditionObserved, Complete bool; Detail string}`; `Commander` interface with `Run(ctx context.Context, cmd Command) (Output, error)`; `HyperV{Cmd Commander}` with `Provision`/`Teardown` (the remaining two methods land in Task 4); test helper `newFakeCommander()` returning `*fakeCommander` with happy-path defaults and per-kind override funcs.

- [ ] **Step 1: Write the failing test**

```go
package adlabhyperv

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/adlabrt"
)

func TestProvision_UnknownTopologyErrors(t *testing.T) {
	h := &HyperV{Cmd: newFakeCommander()}
	if _, err := h.Provision(context.Background(), adlabrt.LabSpec{Name: "nope"}); err == nil {
		t.Fatal("unknown topology must error, never silently provision nothing")
	}
}

func TestProvision_HappyPathReturnsTarget(t *testing.T) {
	h := &HyperV{Cmd: newFakeCommander()}
	tgt, err := h.Provision(context.Background(), adlabrt.LabSpec{Name: "dc-only"})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if tgt.ID == "" {
		t.Fatal("provision must return a non-empty Target handle")
	}
}

func TestProvision_CommanderErrorSurfaces(t *testing.T) {
	f := newFakeCommander()
	f.provision = func(Command) (Output, error) { return Output{}, errors.New("hyper-v down") }
	h := &HyperV{Cmd: f}
	if _, err := h.Provision(context.Background(), adlabrt.LabSpec{Name: "dc-only"}); err == nil {
		t.Fatal("a commander error must surface as a provision error")
	}
}

func TestTeardown_IdempotentOnCommanderDone(t *testing.T) {
	h := &HyperV{Cmd: newFakeCommander()}
	if err := h.Teardown(context.Background(), adlabrt.Target{ID: "dc-only/run1"}); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	// Safe to call again (half-provisioned / already-gone target).
	if err := h.Teardown(context.Background(), adlabrt.Target{ID: ""}); err != nil {
		t.Fatalf("second teardown on empty target must not error: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/adlabhyperv/ -run 'TestProvision|TestTeardown' -count=1`
Expected: FAIL — `undefined: HyperV`, `undefined: newFakeCommander`.

- [ ] **Step 3: Write minimal implementation**

`command.go`:

```go
package adlabhyperv

import "context"

// CommandKind is the kind of host operation the Commander performs.
type CommandKind string

const (
	CmdProvision   CommandKind = "provision"
	CmdProbe       CommandKind = "probe"
	CmdExecuteCase CommandKind = "execute_case"
	CmdTeardown    CommandKind = "teardown"
)

// Command is one host operation. Args carries kind-specific parameters
// (topology name, switch, target id, probe check, case name).
type Command struct {
	Kind CommandKind
	Args map[string]string
}

// Output is the structured result the adapter interprets. Which fields are
// meaningful depends on Command.Kind: provision -> OK, TargetID; probe ->
// Passed, Determinate; execute_case -> PostconditionObserved, Complete;
// teardown -> OK. Detail is diagnostic text for any kind.
type Output struct {
	OK                    bool
	TargetID              string
	Passed                bool
	Determinate           bool
	PostconditionObserved bool
	Complete              bool
	Detail                string
}

// Commander is the ONLY seam to real infrastructure. Faked in tests; the real
// Hyper-V implementation is lab-gated and lives in a future file.
type Commander interface {
	Run(ctx context.Context, cmd Command) (Output, error)
}
```

`adapter.go`:

```go
package adlabhyperv

import (
	"context"
	"fmt"

	"github.com/audspect/bas/internal/adlabrt"
)

// HyperV implements adlabrt.Substrate against a Commander. It holds no Hyper-V
// specifics itself: topology comes from the catalog, host ops go through Cmd.
type HyperV struct {
	Cmd Commander
}

// compile-time proof HyperV satisfies the substrate seam (interface unchanged).
var _ adlabrt.Substrate = (*HyperV)(nil)

// Provision resolves the topology and asks the Commander to stand it up on the
// topology's dedicated private switch. An unknown topology errors rather than
// provisioning an empty environment.
func (h *HyperV) Provision(ctx context.Context, spec adlabrt.LabSpec) (adlabrt.Target, error) {
	topo, ok := LookupTopology(spec.Name)
	if !ok {
		return adlabrt.Target{}, fmt.Errorf("unknown lab topology %q", spec.Name)
	}
	out, err := h.Cmd.Run(ctx, Command{Kind: CmdProvision, Args: map[string]string{
		"topology": topo.Name,
		"switch":   topo.Switch,
	}})
	if err != nil {
		return adlabrt.Target{}, fmt.Errorf("provision %q: %w", topo.Name, err)
	}
	if !out.OK {
		return adlabrt.Target{}, fmt.Errorf("provision %q did not complete: %s", topo.Name, out.Detail)
	}
	id := out.TargetID
	if id == "" {
		id = topo.Name
	}
	return adlabrt.Target{ID: id}, nil
}

// Teardown asks the Commander to revert and destroy the run's VMs. It is
// idempotent: a commander that reports the target already gone returns OK, and
// an empty target id is a no-op success.
func (h *HyperV) Teardown(ctx context.Context, t adlabrt.Target) error {
	out, err := h.Cmd.Run(ctx, Command{Kind: CmdTeardown, Args: map[string]string{"target": t.ID}})
	if err != nil {
		return fmt.Errorf("teardown %q: %w", t.ID, err)
	}
	if !out.OK {
		return fmt.Errorf("teardown %q did not complete: %s", t.ID, out.Detail)
	}
	return nil
}
```

`support_test.go`:

```go
package adlabhyperv

import "context"

// fakeCommander is a programmable Commander for tests. Each kind has a default
// happy-path func that override fields replace per test.
type fakeCommander struct {
	provision func(Command) (Output, error)
	probe     func(Command) (Output, error)
	execute   func(Command) (Output, error)
	teardown  func(Command) (Output, error)
	calls     []Command
}

func newFakeCommander() *fakeCommander {
	return &fakeCommander{
		provision: func(Command) (Output, error) { return Output{OK: true, TargetID: "dc-only/run1"}, nil },
		probe:     func(Command) (Output, error) { return Output{Passed: true, Determinate: true}, nil },
		execute:   func(Command) (Output, error) { return Output{PostconditionObserved: true, Complete: true}, nil },
		teardown:  func(Command) (Output, error) { return Output{OK: true}, nil },
	}
}

func (f *fakeCommander) Run(_ context.Context, cmd Command) (Output, error) {
	f.calls = append(f.calls, cmd)
	switch cmd.Kind {
	case CmdProvision:
		return f.provision(cmd)
	case CmdProbe:
		return f.probe(cmd)
	case CmdExecuteCase:
		return f.execute(cmd)
	case CmdTeardown:
		return f.teardown(cmd)
	}
	return Output{}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/adlabhyperv/ -run 'TestProvision|TestTeardown' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/adlabhyperv/command.go orchestrator/internal/adlabhyperv/adapter.go orchestrator/internal/adlabhyperv/support_test.go orchestrator/internal/adlabhyperv/adapter_test.go
git commit -m "feat(adlabhyperv): Commander seam + Substrate Provision/Teardown"
```

---

### Task 4: Adapter VerifyIsolation + Execute

**Files:**
- Modify: `orchestrator/internal/adlabhyperv/adapter.go`
- Test: `orchestrator/internal/adlabhyperv/adapter_test.go`

**Interfaces:**
- Consumes: `RequiredChecks`, `ProbeResult`, `EvaluateIsolation`, `CheckKind` (Task 2); `Commander`/`Command`/`Output` (Task 3); `adlabrt.IsolationResult`, `adlabrt.ValidationCase{Name string; Primitive adprimitive.Primitive; ExpectPostcondition adprimitive.Capability}`, `adlabrt.Observation{PostconditionObserved, Complete bool; Detail string}`, `adlabrt.Target`.
- Produces: `HyperV.VerifyIsolation` and `HyperV.Execute`, completing the `adlabrt.Substrate` implementation.

- [ ] **Step 1: Write the failing test**

```go
package adlabhyperv

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/adlabrt"
)

func TestVerifyIsolation_AllProbesPassVerifies(t *testing.T) {
	h := &HyperV{Cmd: newFakeCommander()}
	res, err := h.VerifyIsolation(context.Background(), adlabrt.Target{ID: "dc-only/run1"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Verified {
		t.Fatalf("all probes passing must verify, got %+v", res)
	}
}

func TestVerifyIsolation_OneIndeterminateProbeDenies(t *testing.T) {
	f := newFakeCommander()
	f.probe = func(cmd Command) (Output, error) {
		if cmd.Args["check"] == string(CheckNoExternalRoute) {
			return Output{Passed: true, Determinate: false, Detail: "probe timed out"}, nil
		}
		return Output{Passed: true, Determinate: true}, nil
	}
	h := &HyperV{Cmd: f}
	res, _ := h.VerifyIsolation(context.Background(), adlabrt.Target{ID: "dc-only/run1"})
	if res.Verified {
		t.Fatal("an indeterminate probe must leave the lab unverified")
	}
}

func TestVerifyIsolation_ProbeErrorIsUnverifiedNotFatal(t *testing.T) {
	f := newFakeCommander()
	f.probe = func(Command) (Output, error) { return Output{}, errors.New("probe exec failed") }
	h := &HyperV{Cmd: f}
	res, err := h.VerifyIsolation(context.Background(), adlabrt.Target{ID: "dc-only/run1"})
	if err != nil {
		t.Fatalf("a probe error should be recorded as unverified, not returned as error: %v", err)
	}
	if res.Verified {
		t.Fatal("a probe error must leave the lab unverified (fail closed)")
	}
}

func TestExecute_IncompleteObservationIsInconclusive(t *testing.T) {
	f := newFakeCommander()
	f.execute = func(Command) (Output, error) { return Output{PostconditionObserved: false, Complete: false, Detail: "garbled"}, nil }
	h := &HyperV{Cmd: f}
	obs, err := h.Execute(context.Background(), adlabrt.Target{ID: "dc-only/run1"}, adlabrt.ValidationCase{Name: "dcsync-pos"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if obs.Complete {
		t.Fatal("an incomplete commander output must map to Complete=false")
	}
}

func TestExecute_CommanderErrorSurfaces(t *testing.T) {
	f := newFakeCommander()
	f.execute = func(Command) (Output, error) { return Output{}, errors.New("exec failed") }
	h := &HyperV{Cmd: f}
	if _, err := h.Execute(context.Background(), adlabrt.Target{ID: "dc-only/run1"}, adlabrt.ValidationCase{Name: "x"}); err == nil {
		t.Fatal("a commander execute error must surface")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/adlabhyperv/ -run 'TestVerifyIsolation|TestExecute' -count=1`
Expected: FAIL — `h.VerifyIsolation undefined`, `h.Execute undefined`.

- [ ] **Step 3: Write minimal implementation** (append to `adapter.go`)

```go
// VerifyIsolation runs each required isolation check through the Commander and
// aggregates them fail-closed. A probe that errors is recorded as an
// indeterminate result (never isolated), so a failed probe can never be
// mistaken for a verified-isolated lab.
func (h *HyperV) VerifyIsolation(ctx context.Context, t adlabrt.Target) (adlabrt.IsolationResult, error) {
	required := RequiredChecks()
	results := make(map[CheckKind]ProbeResult, len(required))
	for _, c := range required {
		out, err := h.Cmd.Run(ctx, Command{Kind: CmdProbe, Args: map[string]string{"target": t.ID, "check": string(c)}})
		if err != nil {
			results[c] = ProbeResult{Passed: false, Determinate: false, Detail: "probe error: " + err.Error()}
			continue
		}
		results[c] = ProbeResult{Passed: out.Passed, Determinate: out.Determinate, Detail: out.Detail}
	}
	return EvaluateIsolation(required, results), nil
}

// Execute runs the validation case through the Commander and maps its output to
// an Observation. It authors no attack content: it passes the case/primitive
// identity to the Commander (the lab-gated real runner resolves it to existing
// reusable content). An incomplete output stays Complete=false (inconclusive).
func (h *HyperV) Execute(ctx context.Context, t adlabrt.Target, vc adlabrt.ValidationCase) (adlabrt.Observation, error) {
	out, err := h.Cmd.Run(ctx, Command{Kind: CmdExecuteCase, Args: map[string]string{
		"target":    t.ID,
		"case":      vc.Name,
		"primitive": vc.Primitive.ID,
	}})
	if err != nil {
		return adlabrt.Observation{}, fmt.Errorf("execute case %q: %w", vc.Name, err)
	}
	return adlabrt.Observation{
		PostconditionObserved: out.PostconditionObserved,
		Complete:              out.Complete,
		Detail:                out.Detail,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/adlabhyperv/ -run 'TestVerifyIsolation|TestExecute' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/adlabhyperv/adapter.go orchestrator/internal/adlabhyperv/adapter_test.go
git commit -m "feat(adlabhyperv): Substrate VerifyIsolation + Execute (fail-closed)"
```

---

### Task 5: Contract tests — drive adlabrt.Runtime.Validate to every terminal state

**Files:**
- Test: `orchestrator/internal/adlabhyperv/contract_test.go`

**Interfaces:**
- Consumes: `HyperV`, `newFakeCommander`, `CheckKind`/`CheckNoExternalRoute`; `adlabrt.Runtime{Sub adlabrt.Substrate; Now func() time.Time}`, `adlabrt.Request{RunID string; Lab adlabrt.LabSpec; Case adlabrt.ValidationCase; Authorization adgate.Authorization}`, `adlabrt.Result{Status adlabrt.Status; ... TeardownErr error}`, the `adlabrt.Status*` constants; `adgate.Authorization{Authorized, DestructiveApproved bool}`; `adprimitive.Primitive{ID string; RiskClass adprimitive.RiskClass}`, `adprimitive.RiskNonDestructive`.
- Produces: nothing (capstone proving the adapter satisfies the full lifecycle).

- [ ] **Step 1: Write the failing test**

```go
package adlabhyperv

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/adlabrt"
	"github.com/audspect/bas/internal/adprimitive"
)

func runWith(f *fakeCommander, auth adgate.Authorization) adlabrt.Result {
	rt := &adlabrt.Runtime{Sub: &HyperV{Cmd: f}, Now: func() time.Time { return time.Unix(0, 0) }}
	return rt.Validate(context.Background(), adlabrt.Request{
		RunID: "run1",
		Lab:   adlabrt.LabSpec{Name: "dc-only"},
		Case: adlabrt.ValidationCase{
			Name:      "dcsync-positive",
			Primitive: adprimitive.Primitive{ID: "dcsync", RiskClass: adprimitive.RiskNonDestructive},
		},
		Authorization: auth,
	})
}

func authorized() adgate.Authorization { return adgate.Authorization{Authorized: true} }

func TestContract_Validated(t *testing.T) {
	res := runWith(newFakeCommander(), authorized())
	if res.Status != adlabrt.StatusValidated {
		t.Fatalf("status = %q, want validated", res.Status)
	}
	if res.TeardownErr != nil {
		t.Errorf("teardown must succeed on the happy path: %v", res.TeardownErr)
	}
}

func TestContract_ProvisionFailed(t *testing.T) {
	f := newFakeCommander()
	f.provision = func(Command) (Output, error) { return Output{OK: false, Detail: "no base checkpoint"}, nil }
	if got := runWith(f, authorized()).Status; got != adlabrt.StatusProvisionFailed {
		t.Fatalf("status = %q, want provision_failed", got)
	}
}

func TestContract_IsolationUnverifiedMintsNoProvenance(t *testing.T) {
	f := newFakeCommander()
	f.probe = func(cmd Command) (Output, error) {
		if cmd.Args["check"] == string(CheckNoExternalRoute) {
			return Output{Passed: false, Determinate: true, Detail: "route to host net"}, nil
		}
		return Output{Passed: true, Determinate: true}, nil
	}
	res := runWith(f, authorized())
	if res.Status != adlabrt.StatusIsolationUnverified {
		t.Fatalf("status = %q, want isolation_unverified", res.Status)
	}
	if res.Decision.Allowed {
		t.Error("gate must not be reached (no provenance) when isolation is unverified")
	}
	if res.TeardownErr != nil {
		t.Errorf("teardown must still run: %v", res.TeardownErr)
	}
}

func TestContract_GateDeniedWhenUnauthorized(t *testing.T) {
	if got := runWith(newFakeCommander(), adgate.Authorization{Authorized: false}).Status; got != adlabrt.StatusGateDenied {
		t.Fatalf("status = %q, want gate_denied", got)
	}
}

func TestContract_ExecutionErrored(t *testing.T) {
	f := newFakeCommander()
	f.execute = func(Command) (Output, error) { return Output{}, errors.New("boom") }
	if got := runWith(f, authorized()).Status; got != adlabrt.StatusExecutionErrored {
		t.Fatalf("status = %q, want execution_errored", got)
	}
}

func TestContract_EvidenceInconclusive(t *testing.T) {
	f := newFakeCommander()
	f.execute = func(Command) (Output, error) { return Output{Complete: false}, nil }
	if got := runWith(f, authorized()).Status; got != adlabrt.StatusEvidenceInconclusive {
		t.Fatalf("status = %q, want evidence_inconclusive", got)
	}
}

func TestContract_NegativeControlNotValidated(t *testing.T) {
	f := newFakeCommander()
	// Negative control: the primitive runs but the postcondition is NOT observed.
	f.execute = func(Command) (Output, error) { return Output{PostconditionObserved: false, Complete: true}, nil }
	if got := runWith(f, authorized()).Status; got != adlabrt.StatusNotValidated {
		t.Fatalf("status = %q, want not_validated", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/adlabhyperv/ -run TestContract -count=1`
Expected: FAIL — initially a build/compile issue only if earlier tasks incomplete; otherwise these pass once Tasks 1-4 are in. If any FAIL on status mismatch, fix the adapter (not the test) per systematic-debugging.

- [ ] **Step 3: Write minimal implementation**

No new production code expected — this task proves Tasks 1-4 compose correctly through `adlabrt.Runtime`. If a test fails, the defect is in the Task 1-4 adapter logic; fix it there and re-run.

- [ ] **Step 4: Run the full package test + vet**

Run: `cd orchestrator && go test ./internal/adlabhyperv/ -count=1 && go vet ./internal/adlabhyperv/`
Expected: PASS, vet clean.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/adlabhyperv/contract_test.go
git commit -m "test(adlabhyperv): drive adlabrt.Runtime.Validate to every terminal state via the fake"
```

---

### Task 6: Operator runbook

**Files:**
- Create: `docs/operations/p5-ad-lab-operator-runbook.md`

**Interfaces:**
- Consumes: the topology/resource/isolation facts from the spec and Task 1-2 code.
- Produces: an operator-facing doc (no code).

- [ ] **Step 1: Write the runbook**

Write `docs/operations/p5-ad-lab-operator-runbook.md` with these sections, each populated from the spec (§5, §6, §7, §8, §10) and the Task 1 catalog — no placeholders:

1. **Scope & safety** — this runs on dedicated Hyper-V hardware, never the dev host; no cloud spend; the lab is a throwaway domain with no trust to production.
2. **Prerequisites** — dedicated Hyper-V host; a dedicated **private** virtual switch named `audspect-lab-private`; a prepared offline sysprepped Windows Server base checkpoint `dc01-base-clean` promoted to a DC; resource profile from the spec §8 table (M1: 2 vCPU / 4 GB / ~40 GB).
3. **Stand up (M1 dc-only)** — the `LabSpec.Name = "dc-only"` topology; the controlled attacker identity `LAB\attacker` granted `AllExtendedRights` on the domain root.
4. **Verify isolation** — the four required checks (`private_switch`, `no_external_route` [active probe], `no_production_ad`, `distinct_identity`); any failed/indeterminate/missing check means the lab is NOT isolated and nothing runs.
5. **Run a validation (positive + mandatory negative control)** — run the case; then run the same primitive as an identity LACKING the right; accept a `validated` result only when the paired negative control returned `not_validated` in the same build.
6. **Evidence** — lab-local evidence only in this phase; shipping to SIEM/EDR for detection is P6.
7. **Teardown** — revert to `dc01-base-clean` and delete per-run VMs/checkpoints; teardown runs even on failure paths.
8. **Readiness checklist** — the five §10 criteria that gate building/running the real adapter.

- [ ] **Step 2: Verify the doc renders and has no placeholders**

Run: `grep -niE "TBD|TODO|FIXME|\\bXXX\\b" docs/operations/p5-ad-lab-operator-runbook.md`
Expected: no matches.

- [ ] **Step 3: Commit**

```bash
git add docs/operations/p5-ad-lab-operator-runbook.md
git commit -m "docs(p5): operator runbook for the Hyper-V AD validation lab"
```

---

## Self-Review

**1. Spec coverage (§11 slice):**
- §11.1 adlabhyperv skeleton + topology catalog → Task 1; Substrate impl behind faked seam → Tasks 3-4; resolution/isolation-sequencing/teardown-idempotency logic unit tested → Tasks 3-5. ✓
- §11.2 isolation-check policy as data + pure evaluator, fail-closed on every combo → Task 2. ✓
- §11.3 operator runbook → Task 6. ✓
- §11.4 resource-profile + readiness checklist → Task 6 (§2, §8 of runbook). ✓
- Compile-time `adlabrt.Substrate` assertion → Task 3 (`var _ adlabrt.Substrate = (*HyperV)(nil)`). ✓
- Excluded (lab-gated): real Hyper-V execution, live probes, live DC validation — no task implements these. ✓

**2. Placeholder scan:** no TBD/TODO; every code step has concrete code; the runbook task enumerates exact section content and values. ✓

**3. Type consistency:** `Commander.Run(ctx, Command) (Output, error)`, `Command{Kind, Args}`, `Output{OK,TargetID,Passed,Determinate,PostconditionObserved,Complete,Detail}`, `HyperV{Cmd Commander}`, `CheckKind`/`ProbeResult`/`EvaluateIsolation`, `Topology`/`LookupTopology` used identically across Tasks 1-5. `adlabrt`/`adgate`/`adprimitive` signatures match the real code (`Authorization{Authorized, DestructiveApproved}`, `Primitive{ID, RiskClass}`, `ValidationCase{Name, Primitive, ExpectPostcondition}`, `Observation{PostconditionObserved, Complete, Detail}`). ✓

**4. Review Focus:** empty-results fail-closed + indeterminate-not-isolated → Task 2; teardown of half-provisioned target → Task 3 + Task 5 (`IsolationUnverified` path asserts `TeardownErr==nil`); incomplete execution → inconclusive → Task 4 + Task 5; unknown topology → provision_failed → Task 3 + Task 5. All five pinned. ✓
