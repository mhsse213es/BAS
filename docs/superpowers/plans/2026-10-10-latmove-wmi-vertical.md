# Lateral-Movement Vertical 1 (WMI T1047) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Build the self-contained, fake-backed, lab-gated execution-validation vertical for WMI remote process creation (T1047) between two domain-joined client machines, plus the lab-topology catalog entry it needs.

**Architecture:** New package `internal/latmove`: technique identity, an evidence model where destination-marker readback is the sole primary determinant (call outcome and parent-process/WMI-Activity are corroboration only), a fake-backed `ExecutionObserver` seam, and a pure `ClassifyAttempt` classifier. One additive topology entry in `internal/adlabhyperv`. No real observer, no live wiring, no rights-gating layer.

**Tech Stack:** Go (`github.com/audspect/bas`), stdlib `testing`. `go test ./internal/latmove/ ./internal/adlabhyperv/` from `orchestrator/`.

**Spec:** `docs/superpowers/specs/2026-10-10-latmove-wmi-vertical-design.md`

**Execution:** Native/inline — decided.

## Global Constraints

- `internal/latmove` imports `adprimitive` (the `RiskClass` type only) + stdlib. No `admatrix`, no `controlval`, no vendor, no DB.
- `ClassifyAttempt` is pure: no I/O, no clock, no hidden state.
- Marker readback is the **sole** determinant of `Executed`. A reported call success, or any corroboration field, never independently establishes `Executed`.
- `AccessDenied` requires BOTH an absent marker AND a corroborating `access_denied` call outcome — never from corroboration alone, never from an absent marker alone.
- Anything else (uncorrelated marker; absent marker with no denial signal) → `Indeterminate` — never guessed toward either `Executed` or `AccessDenied`.
- The `adlabhyperv` change is additive only: one new catalog entry (`"client-pair"`); `dc-only` and the `Topology`/`VMSpec`/`AttackerIdentity` struct shapes are unchanged.
- No real `ExecutionObserver`, no wiring into any execution/reporting path, no rights-gating (Vertical 1b is a separate future slice).
- Commit trailer `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`; push after every commit.

## Review Focus

- **Corroboration flips the result on its own** (spec §2): `ParentProcessObserved=true` or `WMIActivityLogged=true` with an uncorrelated/absent marker must still be `Indeterminate`/not-`Executed` — `TestClassifyAttempt_CorroborationNeverDeterminesResultAlone` (Task 1).
- **A reported call success is trusted without the marker** (spec §2, "verify postconditions not command-success"): `Call=CallSucceeded` with marker absent/uncorrelated must NOT be `Executed` — `TestClassifyAttempt_CallSuccessAloneIsNotExecuted` (Task 1).
- **`AccessDenied` manufactured from an absent marker alone** (spec §2): absent marker with `Call=CallUnknown`/`CallErrored` (no denial signal) → `Indeterminate`, never `AccessDenied` — `TestClassifyAttempt_AbsentMarkerNoDenialSignalIsIndeterminate` (Task 1).
- **`client-pair` addition perturbs `dc-only`** (spec §4): `dc-only`'s topology and `AttackerIdentity` must be byte-identical before/after — `TestLookupTopology_DCOnlyUnchanged` (Task 2).
- **`FakeObserver` fabricates evidence for an uncaptured key** (spec §7, mirrors `adefficacy`'s fake discipline): an uncaptured `AttemptKey` must return an uncorrelated/indeterminate observation, never reuse another key's canned data — `TestFakeObserver_UncapturedKeyFabricatesNothing` (Task 3).

---

### Task 1: Evidence model + `ClassifyAttempt`

**Files:**
- Create: `orchestrator/internal/latmove/observation.go`
- Test: `orchestrator/internal/latmove/observation_test.go`

**Interfaces:**
- Consumes: stdlib only (`time`).
- Produces:
  - `type TimeWindow struct { Start, End time.Time }`.
  - `type AttemptKey struct { RunID, Source, Destination, Technique string; Window TimeWindow }`.
  - `type CallOutcome string` (`CallSucceeded="succeeded"`, `CallAccessDenied="access_denied"`, `CallErrored="errored"`, `CallUnknown="unknown"`).
  - `type MarkerCheck struct { Correlated, Found bool }`.
  - `type Corroboration struct { ParentProcessObserved bool; ParentProcessName string; WMIActivityLogged bool }`.
  - `type Observation struct { Key AttemptKey; Call CallOutcome; Marker MarkerCheck; Corroboration Corroboration; Detail string }`.
  - `type AttemptResult string` (`ResultExecuted="executed"`, `ResultAccessDenied="access_denied"`, `ResultIndeterminate="indeterminate"`).
  - `func ClassifyAttempt(obs Observation) AttemptResult`.

- [ ] **Step 1: Write the failing tests**

```go
package latmove

import "testing"

func TestClassifyAttempt_MarkerFoundIsExecuted(t *testing.T) {
	obs := Observation{Call: CallSucceeded, Marker: MarkerCheck{Correlated: true, Found: true}}
	if got := ClassifyAttempt(obs); got != ResultExecuted {
		t.Fatalf("result = %q, want executed", got)
	}
}

func TestClassifyAttempt_UncorrelatedMarkerIsIndeterminate(t *testing.T) {
	obs := Observation{Call: CallSucceeded, Marker: MarkerCheck{Correlated: false, Found: true}}
	if got := ClassifyAttempt(obs); got != ResultIndeterminate {
		t.Fatalf("result = %q, want indeterminate (can't trust an uncorrelated check)", got)
	}
}

func TestClassifyAttempt_CallSuccessAloneIsNotExecuted(t *testing.T) {
	// "verify postconditions, not command-success": a reported success with no
	// marker confirmation must NOT be Executed.
	obs := Observation{Call: CallSucceeded, Marker: MarkerCheck{Correlated: true, Found: false}}
	if got := ClassifyAttempt(obs); got == ResultExecuted {
		t.Fatal("a call-reported success alone must never establish Executed")
	}
}

func TestClassifyAttempt_AbsentMarkerWithDenialIsAccessDenied(t *testing.T) {
	obs := Observation{Call: CallAccessDenied, Marker: MarkerCheck{Correlated: true, Found: false}}
	if got := ClassifyAttempt(obs); got != ResultAccessDenied {
		t.Fatalf("result = %q, want access_denied", got)
	}
}

func TestClassifyAttempt_AbsentMarkerNoDenialSignalIsIndeterminate(t *testing.T) {
	obs := Observation{Call: CallUnknown, Marker: MarkerCheck{Correlated: true, Found: false}}
	if got := ClassifyAttempt(obs); got != ResultIndeterminate {
		t.Fatalf("result = %q, want indeterminate (absent marker alone never proves denial)", got)
	}
}

func TestClassifyAttempt_CorroborationNeverDeterminesResultAlone(t *testing.T) {
	// Strong corroboration (parent process + WMI-Activity) with an uncorrelated
	// marker must still be Indeterminate -- corroboration never decides alone.
	obs := Observation{
		Call:          CallSucceeded,
		Marker:        MarkerCheck{Correlated: false, Found: false},
		Corroboration: Corroboration{ParentProcessObserved: true, ParentProcessName: "WmiPrvSE.exe", WMIActivityLogged: true},
	}
	if got := ClassifyAttempt(obs); got != ResultIndeterminate {
		t.Fatalf("result = %q, want indeterminate (corroboration alone must not decide)", got)
	}
}

func TestClassifyAttempt_ErroredCallWithAbsentMarkerIsIndeterminate(t *testing.T) {
	obs := Observation{Call: CallErrored, Marker: MarkerCheck{Correlated: true, Found: false}}
	if got := ClassifyAttempt(obs); got != ResultIndeterminate {
		t.Fatalf("result = %q, want indeterminate (a generic error is not a denial signal)", got)
	}
}
```

- [ ] **Step 2: Run to verify RED**

Run: `go test ./internal/latmove/`
Expected: FAIL — package does not exist / undefined `Observation`, `ClassifyAttempt`, etc.

- [ ] **Step 3: Implement**

```go
// Package latmove is the first lateral-movement validation vertical: it proves
// WMI remote process creation (T1047) genuinely achieves cross-machine code
// execution between two domain-joined clients. This slice is
// EXECUTION-VALIDATION ONLY -- no rights-gating, no real observer, no live
// wiring. Self-contained: it does not reuse admatrix (AD-object-abuse axes) or
// controlval (generalized only because 4+ vendor consumers justified it); a
// third real consumer of this evidence shape is the trigger to generalize, not
// this one vertical.
package latmove

import "time"

// TimeWindow bounds when an attempt occurred, for correlation.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// AttemptKey identifies one lateral-movement attempt.
type AttemptKey struct {
	RunID       string
	Source      string
	Destination string
	Technique   string
	Window      TimeWindow
}

// CallOutcome is the WMI call's OWN immediate result. SECONDARY/diagnostic
// only -- it never independently establishes Executed, but a reported denial
// combined with an absent marker yields a meaningful AccessDenied.
type CallOutcome string

const (
	CallSucceeded    CallOutcome = "succeeded"
	CallAccessDenied CallOutcome = "access_denied"
	CallErrored      CallOutcome = "errored"
	CallUnknown      CallOutcome = "unknown"
)

// MarkerCheck is the destination-side readback of a unique, per-attempt token.
// This is the SOLE primary determinant of Executed -- "verify postconditions,
// not command-success". Correlated=false means the check could not be trusted
// as belonging to THIS attempt (wrong window, stale token, etc.).
type MarkerCheck struct {
	Correlated bool
	Found      bool
}

// Corroboration is supporting detail only -- the parent-process chain
// (WmiPrvSE.exe) and the WMI-Activity operational log. NEVER
// outcome-determining on its own, exactly as event 4662 was for DCSync.
type Corroboration struct {
	ParentProcessObserved bool
	ParentProcessName     string
	WMIActivityLogged     bool
}

// Observation is one recorded attempt's full evidence.
type Observation struct {
	Key           AttemptKey
	Call          CallOutcome
	Marker        MarkerCheck
	Corroboration Corroboration
	Detail        string
}

// AttemptResult is the classified outcome of a lateral-movement attempt.
type AttemptResult string

const (
	ResultExecuted      AttemptResult = "executed"
	ResultAccessDenied  AttemptResult = "access_denied"
	ResultIndeterminate AttemptResult = "indeterminate"
)

// ClassifyAttempt is pure: no I/O, no clock, no hidden state. The marker
// readback is the sole primary determinant; the call outcome and
// corroboration inform Detail but never independently decide the result.
func ClassifyAttempt(obs Observation) AttemptResult {
	switch {
	case !obs.Marker.Correlated:
		return ResultIndeterminate
	case obs.Marker.Found:
		return ResultExecuted
	case obs.Call == CallAccessDenied:
		return ResultAccessDenied
	default:
		return ResultIndeterminate
	}
}
```

- [ ] **Step 4: Run to verify GREEN**

Run: `go test ./internal/latmove/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/latmove/observation.go orchestrator/internal/latmove/observation_test.go
git commit -m "feat(latmove): evidence model + pure ClassifyAttempt classifier

Destination marker readback is the sole primary determinant of Executed (verify
postconditions, not command-success). Call outcome + parent-process/WMI-Activity
are corroboration only -- never independently decide. AccessDenied requires an
absent marker AND a corroborating denial signal; anything else -> Indeterminate.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 2: `adlabhyperv` `client-pair` topology (additive)

**Files:**
- Modify: `orchestrator/internal/adlabhyperv/topology.go` (add one catalog entry only)
- Test: `orchestrator/internal/adlabhyperv/topology_clientpair_test.go` (create)

**Interfaces:**
- Consumes: existing `Topology`, `VMSpec`, `Role`, `RoleClient`, `AttackerIdentity`, `LookupTopology` (unchanged shapes).
- Produces: the `"client-pair"` entry in the existing `catalog` map (no new exported symbols).

- [ ] **Step 1: Write the failing tests**

```go
package adlabhyperv

import "testing"

func TestLookupTopology_ClientPairHasTwoClientVMs(t *testing.T) {
	topo, ok := LookupTopology("client-pair")
	if !ok {
		t.Fatal("client-pair topology not found")
	}
	if topo.Switch != "audspect-lab-private" {
		t.Fatalf("switch = %q, want audspect-lab-private (same isolated switch, no new switch)", topo.Switch)
	}
	if len(topo.VMs) != 2 {
		t.Fatalf("len(VMs) = %d, want 2", len(topo.VMs))
	}
	for _, vm := range topo.VMs {
		if vm.Role != RoleClient {
			t.Fatalf("VM %s role = %q, want client", vm.Name, vm.Role)
		}
		if vm.BaseCheckpoint == "" {
			t.Fatalf("VM %s has no BaseCheckpoint", vm.Name)
		}
	}
	if topo.VMs[0].Name == topo.VMs[1].Name {
		t.Fatal("the two client VMs must have distinct names")
	}
}

func TestLookupTopology_DCOnlyUnchanged(t *testing.T) {
	// Regression lock: adding client-pair must not perturb dc-only.
	topo, ok := LookupTopology("dc-only")
	if !ok {
		t.Fatal("dc-only topology missing")
	}
	if len(topo.VMs) != 1 || topo.VMs[0].Name != "dc01" || topo.VMs[0].Role != RoleDC {
		t.Fatalf("dc-only topology changed: %+v", topo)
	}
	if topo.Attacker.Principal != `LAB\attacker` || topo.Attacker.Rights != "AllExtendedRights@domain-root" {
		t.Fatalf("dc-only Attacker changed: %+v", topo.Attacker)
	}
}
```

- [ ] **Step 2: Run to verify RED**

Run: `go test ./internal/adlabhyperv/ -run 'ClientPair|DCOnlyUnchanged'`
Expected: `TestLookupTopology_ClientPairHasTwoClientVMs` FAILs (`ok` is false); `TestLookupTopology_DCOnlyUnchanged` passes already (it is the pre-change regression baseline).

- [ ] **Step 3: Implement**

Add one entry to the existing `catalog` map in `topology.go` (do not touch the `"dc-only"` entry or any struct definition):

```go
	"client-pair": {
		Name:   "client-pair",
		Switch: "audspect-lab-private",
		VMs: []VMSpec{
			{Name: "ws01", Role: RoleClient, BaseCheckpoint: "ws01-base-clean", VCPU: 2, MemoryMB: 4096, DiskGB: 40},
			{Name: "ws02", Role: RoleClient, BaseCheckpoint: "ws02-base-clean", VCPU: 2, MemoryMB: 4096, DiskGB: 40},
		},
		// Attacker is intentionally zero-value: this topology backs the
		// execution-validation-only latmove vertical (Vertical 1). Rights-gating
		// (Vertical 1b) assigns identities when that slice is built.
	},
```

- [ ] **Step 4: Run to verify GREEN**

Run: `go test ./internal/adlabhyperv/`
Expected: PASS (whole package, including every pre-existing `adlabhyperv` test — the addition must not break Phase 5's DCSync lab substrate).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/adlabhyperv/topology.go orchestrator/internal/adlabhyperv/topology_clientpair_test.go
git commit -m "feat(adlabhyperv): add client-pair topology (two client VMs, same private switch)

Additive only: one new catalog entry (ws01+ws02, RoleClient, same
audspect-lab-private switch, ~2vCPU/4GB/40GB per runbook's client profile).
dc-only and the Topology/VMSpec/AttackerIdentity shapes are unchanged
(regression-locked by TestLookupTopology_DCOnlyUnchanged). Attacker left at
zero value -- rights-gating is Vertical 1b, not this slice.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 3: `ExecutionObserver` seam + `FakeObserver`

**Files:**
- Create: `orchestrator/internal/latmove/observer.go`
- Test: `orchestrator/internal/latmove/observer_test.go`

**Interfaces:**
- Consumes: `AttemptKey`, `Observation`, `CallOutcome`, `CallUnknown`, `MarkerCheck`, `Corroboration` (Task 1).
- Produces:
  - `type ExecutionObserver interface { Observe(ctx context.Context, key AttemptKey) (Observation, error) }`.
  - `type FakeObserver struct { Obs map[string]Observation; Err map[string]error }` keyed by an opaque string the test builds from the `AttemptKey` (e.g. `key.RunID+"/"+key.Technique`).
  - `func (f *FakeObserver) Observe(ctx context.Context, key AttemptKey) (Observation, error)`.

- [ ] **Step 1: Write the failing tests**

```go
package latmove

import (
	"context"
	"errors"
	"testing"
)

func lookupKey(k AttemptKey) string { return k.RunID + "/" + k.Technique }

func TestFakeObserver_ReturnsCannedObservationWithKey(t *testing.T) {
	k := AttemptKey{RunID: "r1", Source: "ws01", Destination: "ws02", Technique: "wmi-remote-process-creation"}
	f := &FakeObserver{Obs: map[string]Observation{
		lookupKey(k): {Call: CallSucceeded, Marker: MarkerCheck{Correlated: true, Found: true}},
	}}
	got, err := f.Observe(context.Background(), k)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Key != k {
		t.Fatalf("Observe must stamp the requested key; got %+v want %+v", got.Key, k)
	}
	if ClassifyAttempt(got) != ResultExecuted {
		t.Fatalf("expected Executed, got %+v", got)
	}
}

func TestFakeObserver_UncapturedKeyFabricatesNothing(t *testing.T) {
	k1 := AttemptKey{RunID: "r1", Technique: "wmi-remote-process-creation"}
	k2 := AttemptKey{RunID: "r2", Technique: "wmi-remote-process-creation"}
	f := &FakeObserver{Obs: map[string]Observation{
		lookupKey(k1): {Call: CallSucceeded, Marker: MarkerCheck{Correlated: true, Found: true}},
	}}
	got, err := f.Observe(context.Background(), k2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Marker.Found {
		t.Fatal("must not reuse another key's canned marker")
	}
	if got.Marker.Correlated {
		t.Fatal("an uncaptured key must not claim correlation")
	}
	if got.Call != CallUnknown {
		t.Fatalf("call = %q, want unknown for an uncaptured key", got.Call)
	}
	if ClassifyAttempt(got) != ResultIndeterminate {
		t.Fatal("an uncaptured key must classify as Indeterminate, never Executed or AccessDenied")
	}
}

func TestFakeObserver_ConfiguredErrorPropagates(t *testing.T) {
	k := AttemptKey{RunID: "boom", Technique: "wmi-remote-process-creation"}
	f := &FakeObserver{Err: map[string]error{lookupKey(k): errors.New("winrm down")}}
	if _, err := f.Observe(context.Background(), k); err == nil {
		t.Fatal("expected the configured error to propagate")
	}
}

func TestFakeObserver_SatisfiesExecutionObserver(t *testing.T) {
	var _ ExecutionObserver = (*FakeObserver)(nil)
}
```

- [ ] **Step 2: Run to verify RED**

Run: `go test ./internal/latmove/ -run TestFakeObserver`
Expected: FAIL — undefined `FakeObserver`, `ExecutionObserver`.

- [ ] **Step 3: Implement**

```go
package latmove

import "context"

// ExecutionObserver observes a lateral-movement attempt's evidence. It does
// NOT perform the attempt itself. No real implementation ships in this slice.
type ExecutionObserver interface {
	Observe(ctx context.Context, key AttemptKey) (Observation, error)
}

// FakeObserver is the only observer in this slice, keyed by RunID+"/"+Technique.
// An uncaptured key returns an uncorrelated, Call=Unknown observation -- never
// reusing another key's canned data and never fabricating a positive or
// negative result.
type FakeObserver struct {
	Obs map[string]Observation
	Err map[string]error
}

func (f *FakeObserver) key(k AttemptKey) string { return k.RunID + "/" + k.Technique }

func (f *FakeObserver) Observe(_ context.Context, key AttemptKey) (Observation, error) {
	lk := f.key(key)
	if err, ok := f.Err[lk]; ok {
		return Observation{}, err
	}
	if o, ok := f.Obs[lk]; ok {
		o.Key = key
		return o, nil
	}
	return Observation{
		Key:    key,
		Call:   CallUnknown,
		Marker: MarkerCheck{Correlated: false, Found: false},
		Detail: "no correlated observation for this attempt",
	}, nil
}
```

- [ ] **Step 4: Run to verify GREEN**

Run: `go test ./internal/latmove/`
Expected: PASS (Task 1 + Task 3 — `technique.go`/`technique_test.go` are added in Task 4, so this is the full suite so far minus that file).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/latmove/observer.go orchestrator/internal/latmove/observer_test.go
git commit -m "feat(latmove): ExecutionObserver seam + fake-backed FakeObserver

Observe reports an attempt's evidence, does not perform the attempt. An
uncaptured key returns Call=Unknown + uncorrelated marker (never reuses
another key's data, never fabricates Executed or AccessDenied). No real
observer ships.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 4: Technique identity + final verification

**Files:**
- Create: `orchestrator/internal/latmove/technique.go`
- Test: `orchestrator/internal/latmove/technique_test.go`

**Interfaces:**
- Consumes: `adprimitive.RiskClass`, `adprimitive.RiskNonDestructive` (`orchestrator/internal/adprimitive/types.go:149`).
- Produces: `type Technique struct { ID, Name, MitreID string; RiskClass adprimitive.RiskClass }`, `func WMIRemoteProcessCreation() Technique`.

- [ ] **Step 1: Write the failing test**

```go
package latmove

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestWMIRemoteProcessCreation_StableIdentity(t *testing.T) {
	tech := WMIRemoteProcessCreation()
	if tech.ID != "wmi-remote-process-creation" {
		t.Fatalf("id = %q", tech.ID)
	}
	if tech.MitreID != "T1047" {
		t.Fatalf("mitreID = %q, want T1047", tech.MitreID)
	}
	if tech.RiskClass != adprimitive.RiskNonDestructive {
		t.Fatalf("riskClass = %q, want non_destructive", tech.RiskClass)
	}
	if tech.Name == "" {
		t.Fatal("technique must have a human-readable name")
	}
}
```

- [ ] **Step 2: Run to verify RED**

Run: `go test ./internal/latmove/ -run WMIRemoteProcessCreation`
Expected: FAIL — undefined `Technique`, `WMIRemoteProcessCreation`.

- [ ] **Step 3: Implement**

```go
package latmove

import "github.com/audspect/bas/internal/adprimitive"

// Technique identifies one lateral-movement technique this vertical validates.
type Technique struct {
	ID        string
	Name      string
	MitreID   string
	RiskClass adprimitive.RiskClass
}

// WMIRemoteProcessCreation is the first (and in this slice, only) technique:
// WMI remote process creation, T1047. RiskClass is non-destructive: the
// attempt writes a benign, self-identifying marker and creates no persistence.
func WMIRemoteProcessCreation() Technique {
	return Technique{
		ID:        "wmi-remote-process-creation",
		Name:      "WMI Remote Process Creation",
		MitreID:   "T1047",
		RiskClass: adprimitive.RiskNonDestructive,
	}
}
```

- [ ] **Step 4: Run to verify GREEN**

Run: `go test ./internal/latmove/`
Expected: PASS (full package).

- [ ] **Step 5: Run the full related-package verification**

Run: `go test ./internal/latmove/ ./internal/adlabhyperv/ ./internal/adprimitive/`
Expected: PASS (all three).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/latmove/technique.go orchestrator/internal/latmove/technique_test.go
git commit -m "feat(latmove): WMI remote process creation technique identity (T1047)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```
