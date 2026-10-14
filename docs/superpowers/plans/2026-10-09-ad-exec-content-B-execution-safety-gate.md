# AD Executable-Content Sub-Project B — Execution Safety Gate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `orchestrator/internal/adgate`: a pure-Go, fail-closed `Decide(Request) Decision` that allows an action to run only against a positively-synthetic environment, consuming the existing `scenario.ExecutionClass`; then stamp `adlab`'s synthetic labs with synthetic provenance at origin.

**Architecture:** `adgate` defines an unforgeable-by-struct-literal `Provenance` (zero value = Unknown = deny), minted synthetic only via `SyntheticProvenance()`; `Decide` applies a fixed fail-closed rule order over provenance, the existing classification, and operator `Authorization`. `adlab` imports `adgate` and stamps each `SyntheticProvider` lab. No runtime/dispatch wiring (that is sub-project D).

**Tech Stack:** Go (stdlib only). No DB, no containers, no network.

**Spec:** `docs/superpowers/specs/2026-10-09-ad-exec-content-B-execution-safety-gate-design.md`

## Global Constraints

- Go stdlib only; no new third-party dependencies. `go 1.26.6`, module `github.com/audspect/bas`.
- `adgate` depends one-way on `scenario` only; it imports no lab code. `adlab → adgate` (no cycle).
- Consume `scenario.ExecutionClass` (`ClassNonDestructive`, `ClassPotentiallyDestructive`, `ClassDestructive`); do NOT add risk tiers or touch `ResolveExecutionClass`/`AttachExecutionClassifications`/`adprimitive.RiskClass`.
- `Decide` is pure and total: no error return, no panic; every `Request` yields a `Decision`.
- Fail-closed: Unknown/ambiguous/invalid/unverified environment or classification, or missing authorization, all deny.
- No execution, network, DB, orchestrator, or agent side effects. No dispatch wiring — B is a decision library, not enforcement.

## Review Focus

- **Zero-value provenance denies:** `adgate.Provenance{}` (what a caller gets without the constructor) must be Unknown and deny `denied_environment_not_synthetic`, never allow. → Task 1, Step 1.
- **Rule order is first-failing-wins:** a request failing several rules (e.g. live environment *and* unknown class) returns the earliest rule's reason, deterministically. → Task 1, Step 1.
- **Unknown class is fail-closed:** an empty `ExecutionClass` and a bogus non-constant value both deny `denied_unknown_classification`, not allow. → Task 1, Step 1.
- **Destructive needs explicit approval even when synthetic+authorized:** `ClassDestructive` with `Authorized` but `!DestructiveApproved` denies. → Task 1, Step 1.
- **Origin stamping is real, not a label:** every `SyntheticProvider` lab carries a synthetic `Attestation` that flows through `Decide` to allow; a hand-built `adlab.Lab{}` (no stamp) carries zero-value provenance and denies. → Task 2, Step 1.

---

### Task 1: The `adgate` decision library

**Files:**
- Create: `orchestrator/internal/adgate/gate.go`
- Test: `orchestrator/internal/adgate/gate_test.go`

**Interfaces:**
- Consumes: `scenario.ExecutionClass` and its constants.
- Produces: `type Provenance`, `func SyntheticProvenance() Provenance`, `func LiveADProvenance() Provenance`, `type Authorization struct{ Authorized, DestructiveApproved bool }`, `type Request struct{ Class scenario.ExecutionClass; Env Provenance; Auth Authorization }`, `type Reason string` (+ five constants), `type Decision struct{ Allowed bool; Reason Reason }`, `func Decide(Request) Decision`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adgate/gate_test.go
package adgate

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestProvenanceZeroValueIsNotSynthetic(t *testing.T) {
	// What a caller gets without the constructor must fail closed.
	d := Decide(Request{Class: scenario.ClassNonDestructive, Env: Provenance{}, Auth: Authorization{Authorized: true}})
	if d.Allowed || d.Reason != ReasonDeniedNotSynthetic {
		t.Fatalf("zero-value provenance must deny not_synthetic, got %+v", d)
	}
}

func TestDecide_AllowsSyntheticAuthorizedKnownClass(t *testing.T) {
	d := Decide(Request{Class: scenario.ClassNonDestructive, Env: SyntheticProvenance(), Auth: Authorization{Authorized: true}})
	if !d.Allowed || d.Reason != ReasonAllowedSyntheticAuthorized {
		t.Fatalf("expected allow, got %+v", d)
	}
}

func TestDecide_DeniesLiveEnvironment(t *testing.T) {
	d := Decide(Request{Class: scenario.ClassNonDestructive, Env: LiveADProvenance(), Auth: Authorization{Authorized: true}})
	if d.Allowed || d.Reason != ReasonDeniedNotSynthetic {
		t.Fatalf("expected deny not_synthetic for live env, got %+v", d)
	}
}

func TestDecide_DeniesUnknownClass(t *testing.T) {
	for _, c := range []scenario.ExecutionClass{"", scenario.ExecutionClass("bogus")} {
		d := Decide(Request{Class: c, Env: SyntheticProvenance(), Auth: Authorization{Authorized: true}})
		if d.Allowed || d.Reason != ReasonDeniedUnknownClass {
			t.Fatalf("class %q must deny unknown_classification, got %+v", c, d)
		}
	}
}

func TestDecide_DeniesMissingAuthorization(t *testing.T) {
	d := Decide(Request{Class: scenario.ClassNonDestructive, Env: SyntheticProvenance(), Auth: Authorization{Authorized: false}})
	if d.Allowed || d.Reason != ReasonDeniedMissingAuth {
		t.Fatalf("expected deny missing_authorization, got %+v", d)
	}
}

func TestDecide_DestructiveNeedsExplicitApproval(t *testing.T) {
	base := Request{Class: scenario.ClassDestructive, Env: SyntheticProvenance(), Auth: Authorization{Authorized: true}}
	if d := Decide(base); d.Allowed || d.Reason != ReasonDeniedDestructiveNotApproved {
		t.Fatalf("destructive without approval must deny, got %+v", d)
	}
	base.Auth.DestructiveApproved = true
	if d := Decide(base); !d.Allowed || d.Reason != ReasonAllowedSyntheticAuthorized {
		t.Fatalf("destructive with approval (synthetic+authorized) must allow, got %+v", d)
	}
}

func TestDecide_RuleOrderFirstFailingWins(t *testing.T) {
	// Live env AND unknown class: environment rule is first, so not_synthetic.
	d := Decide(Request{Class: "", Env: LiveADProvenance(), Auth: Authorization{}})
	if d.Reason != ReasonDeniedNotSynthetic {
		t.Fatalf("expected first-failing rule (not_synthetic), got %+v", d)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adgate/...`
Expected: FAIL — `undefined: Decide` / `undefined: Provenance` / etc.

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adgate/gate.go

// Package adgate is AD executable-content sub-project B: a pure, fail-closed
// policy that decides whether an action may run against a given environment.
// It is DISTINCT from classification -- scenario.ExecutionClass says what an
// action is; adgate says whether this action may run in this environment now.
// It executes nothing and is not wired into dispatch; turning this decision
// into an enforced control is sub-project D. Depends one-way on scenario.
package adgate

import "github.com/audspect/bas/internal/scenario"

type provenanceKind int

const (
	provUnknown   provenanceKind = iota // zero value -> fail closed
	provSynthetic
	provLiveAD
)

// Provenance records where an environment came from. It is unforgeable by
// struct literal: the kind field is unexported, so a plain Provenance{} is
// Unknown, which denies. A synthetic value is obtainable only via
// SyntheticProvenance, called by environment producers at origin.
type Provenance struct{ kind provenanceKind }

// SyntheticProvenance mints the synthetic stamp. Producers call it at the
// environment's point of origin (in v1, adlab.SyntheticProvider).
func SyntheticProvenance() Provenance { return Provenance{kind: provSynthetic} }

// LiveADProvenance marks a real/live AD environment. Such environments deny
// in B; a live-authorization policy is a future sub-project.
func LiveADProvenance() Provenance { return Provenance{kind: provLiveAD} }

// Authorization is the operator consent / policy context the caller supplies.
type Authorization struct {
	Authorized          bool // operator consented to this controlled run
	DestructiveApproved bool // extra consent required for a destructive-class action
}

// Request is one gate query.
type Request struct {
	Class scenario.ExecutionClass // consumed, never re-derived
	Env   Provenance
	Auth  Authorization
}

// Reason is a stable, machine-readable decision reason.
type Reason string

const (
	ReasonAllowedSyntheticAuthorized   Reason = "allowed_synthetic_authorized"
	ReasonDeniedNotSynthetic           Reason = "denied_environment_not_synthetic"
	ReasonDeniedUnknownClass           Reason = "denied_unknown_classification"
	ReasonDeniedMissingAuth            Reason = "denied_missing_authorization"
	ReasonDeniedDestructiveNotApproved Reason = "denied_destructive_not_approved"
)

// Decision is the gate's answer.
type Decision struct {
	Allowed bool
	Reason  Reason
}

// Decide applies the fail-closed rule order; the first failing rule wins.
func Decide(req Request) Decision {
	if req.Env.kind != provSynthetic {
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
	return Decision{Allowed: true, Reason: ReasonAllowedSyntheticAuthorized}
}

func deny(r Reason) Decision { return Decision{Allowed: false, Reason: r} }

func knownClass(c scenario.ExecutionClass) bool {
	switch c {
	case scenario.ClassNonDestructive, scenario.ClassPotentiallyDestructive, scenario.ClassDestructive:
		return true
	default:
		return false
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adgate/... -v`
Expected: PASS — all seven tests.

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adgate/ && go vet ./internal/adgate/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adgate/gate.go orchestrator/internal/adgate/gate_test.go
git commit -m "$(cat <<'EOF'
feat(adgate): add fail-closed execution safety gate (sub-project B task 1 of 2)

Decide answers "may this action run in this environment now" (distinct
from classification), fail-closed: only a positively-synthetic
Provenance (unforgeable by struct literal; zero value = Unknown = deny)
with a known ExecutionClass and operator authorization allows; a
destructive-class action needs explicit DestructiveApproved. Consumes
scenario.ExecutionClass, adds no tiers, executes nothing. Not yet wired
into dispatch -- enforcement is sub-project D.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Origin-stamp `adlab` synthetic labs

**Files:**
- Modify: `orchestrator/internal/adlab/lab.go` (add `Attestation` field to `Lab`)
- Modify: `orchestrator/internal/adlab/labs.go` (stamp the four `SyntheticProvider` labs)
- Test: `orchestrator/internal/adlab/attestation_test.go`

**Interfaces:**
- Consumes: `adgate.Provenance`, `adgate.SyntheticProvenance`, `adgate.Decide`, `adgate.Request`, `adgate.Authorization`, `adgate.ReasonAllowedSyntheticAuthorized` (Task 1); `scenario.ClassNonDestructive`.
- Produces: `adlab.Lab.Attestation adgate.Provenance`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/adlab/attestation_test.go
package adlab

import (
	"testing"

	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/scenario"
)

func TestSyntheticLabsAreStampedAndFlowThroughGate(t *testing.T) {
	labs, err := SyntheticProvider{}.Labs()
	if err != nil {
		t.Fatalf("synthetic provider must not error: %v", err)
	}
	for _, l := range labs {
		d := adgate.Decide(adgate.Request{
			Class: scenario.ClassNonDestructive,
			Env:   l.Attestation,
			Auth:  adgate.Authorization{Authorized: true},
		})
		if !d.Allowed || d.Reason != adgate.ReasonAllowedSyntheticAuthorized {
			t.Errorf("lab %q: stamped synthetic attestation must allow through the gate, got %+v", l.Name, d)
		}
	}
}

func TestUnstampedLabDeniesThroughGate(t *testing.T) {
	// A hand-built Lab with no stamp carries zero-value provenance -> deny.
	l := Lab{Name: "unstamped"}
	d := adgate.Decide(adgate.Request{
		Class: scenario.ClassNonDestructive,
		Env:   l.Attestation,
		Auth:  adgate.Authorization{Authorized: true},
	})
	if d.Allowed || d.Reason != adgate.ReasonDeniedNotSynthetic {
		t.Fatalf("unstamped lab must deny not_synthetic, got %+v", d)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/adlab/... -run "Stamped|Gate"`
Expected: FAIL — `l.Attestation undefined (type Lab has no field or method Attestation)`.

- [ ] **Step 3: Add the field and stamp the labs**

In `orchestrator/internal/adlab/lab.go`, add the import and the field:

```go
import "github.com/audspect/bas/internal/adgate"
```

```go
type Lab struct {
	Name        string
	Description string
	Env         adenv.Environment
	Attacker    string             // principal name present in Env.Identity — the starting foothold
	Attestation adgate.Provenance  // provenance stamp; synthetic labs are stamped at origin
}
```

In `orchestrator/internal/adlab/labs.go`, add the `adgate` import and set
`Attestation: adgate.SyntheticProvenance()` in each of the four lab
constructors (`aclGenericAllTakeoverLab`, `adcsESC1EnrollableLab`,
`adcsESC1NotEnrollableLab`, `noFootholdSafeLab`). Example for the first:

```go
func aclGenericAllTakeoverLab() Lab {
	return Lab{
		Name:        "acl-genericall-takeover",
		Description: "Attacker's group holds GenericAll over a service account.",
		Attacker:    "attacker",
		Attestation: adgate.SyntheticProvenance(),
		Env: adenv.Environment{
			Identity: adenv.Identity{Groups: []adenv.Group{
				{Name: "Helpdesk", Members: []string{"attacker"}},
			}},
			Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
				{Principal: "Helpdesk", Target: "svc-admin", Right: adenv.ACLGenericAll},
			}},
		},
	}
}
```

Apply the same `Attestation: adgate.SyntheticProvenance()` line to the other
three lab constructors.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adlab/... -v`
Expected: PASS — the two new tests plus every existing `adlab` test (the
additive field does not affect `Validate` or the existing lab/resolver tests).

- [ ] **Step 5: Run gofmt, go vet, and the full build**

Run: `cd orchestrator && gofmt -l internal/adgate/ internal/adlab/ && go vet ./internal/adgate/... ./internal/adlab/... && go build ./...`
Expected: gofmt/vet print nothing; build succeeds.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adlab/lab.go orchestrator/internal/adlab/labs.go orchestrator/internal/adlab/attestation_test.go
git commit -m "$(cat <<'EOF'
feat(adlab): stamp synthetic labs with adgate provenance at origin (sub-project B task 2 of 2)

Lab gains an Attestation adgate.Provenance field; SyntheticProvider
stamps each of its four labs synthetic at construction. This realizes
the gate's trust anchor: a synthetic stamp exists only because the
synthetic factory minted it at origin, and it flows through adgate.Decide
to an allow. A hand-built unstamped Lab carries the zero-value (Unknown)
provenance and denies. Closes sub-project B.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing "Inline Over Subagents" preference and explicit instruction to start plan + inline execution — already decided, not asking.** 2 sequential tasks; Task 2 consumes Task 1's `adgate` API. Proceeding via `superpowers:executing-plans`, final self-review at the end (subagent reviewer dispatch has been hitting hard `[cyber]` blocks on AD-framed prompts this session).
