# AD-M05 Chain Planner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the capability-state chaining mechanism `adprimitive`'s own doc comment anticipates (AD-M05 will consume `Capability` equality between one primitive's `Postconditions` and another's `Prerequisites.Capabilities` to decide what can follow what). Pure graph-reachability/path-search over typed values — no technique narrative, matching the mechanical/structural framing that worked for M07.

**Architecture:** New package `orchestrator/internal/adchain`, depending one-way on `adprimitive` (consistent with every other dependency direction in this initiative — `adenv` depends on `attackpath`, never the reverse). A `ConditionResolver` interface (one method, `Resolve(key string) bool`) is the seam where a primitive's `Prerequisites.Conditions` string keys (the `"acl_right_held:<RightName>"` / `"esc<N>_..."` conventions already established across `adprimitive`'s catalogs) get resolved — against what, is explicitly out of scope for this phase; M05 ships the algorithm and a trivial in-memory map-backed resolver for its own tests, not any real environment-graph integration. `Reachable` computes the full capability closure from a starting set by repeatedly applying any primitive whose prerequisites are met; `Plan` does the same search but tracks and returns one ordered primitive path to a specific target capability.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — bounded, conversationally-approved task, following the user-approved wave process (wave → short design → bounded plan → execute → verify, no per-phase pause). Source: `orchestrator/internal/adprimitive/types.go`'s own doc comment (lines 13-17) naming this exact mechanism as M05's job.

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- `adchain` depends on `adprimitive` only — no dependency on `adenv`, `attackpath`, or `scenario`.
- `Capability` equality for matching Postconditions against Prerequisites.Capabilities is exact struct equality (`Kind` AND `Target` must both match) — a capability with an empty `Target` (host-agnostic, e.g. `CapDomainUser`) only satisfies a prerequisite that also has an empty `Target`, never one scoped to a specific host. This mirrors `adprimitive.Capability`'s own doc comment distinction between host-agnostic and host-scoped capabilities.
- `DomainJoined`/`Privileges` fields on `Prerequisites` are NOT evaluated by this phase's search (no caller-supplied "is the attacker domain-joined" input exists yet) — a primitive is considered applicable based solely on `Capabilities` (held-set equality) and `Conditions` (resolver), the two fields that have a well-defined evaluation rule already. Treating `DomainJoined`/`Privileges` as always-satisfied is a scoping decision for THIS phase, not a bug; a future phase can add a caller-supplied attacker-context input if needed.

## Review Focus

- A primitive with an EMPTY `Prerequisites.Conditions` map must still be correctly evaluated as "conditions satisfied" (vacuously true) — a resolver that is never called is not a bug, since not every primitive has conditions (e.g. `kerberoast-tgs-request` has none). Tested in Task 1, Step 1.
- `Reachable` must terminate even when the catalog contains a cycle (e.g. two primitives whose postcondition satisfies the other's prerequisite) — a naive repeated-pass loop without a "did anything new get added this pass" termination check would loop forever. Tested in Task 2, Step 1.
- `Plan`'s returned path must be primitives IN THE ORDER they must be executed (prerequisite-satisfying primitive before the one that consumes its postcondition), not just an unordered set of "primitives involved" — a caller executing the steps out of order would fail at the first unmet prerequisite. Tested in Task 2, Step 1.

---

### Task 1: `ConditionResolver` and prerequisite satisfaction

**Files:**
- Create: `orchestrator/internal/adchain/resolver.go`
- Create: `orchestrator/internal/adchain/satisfied.go`
- Test: `orchestrator/internal/adchain/satisfied_test.go`

**Interfaces:**
- Consumes: `adprimitive.Primitive`, `adprimitive.Capability`, `adprimitive.Prerequisites`.
- Produces: `ConditionResolver` interface, `MapResolver` (a `map[string]bool`-backed implementation for tests), `satisfied(p adprimitive.Primitive, held []adprimitive.Capability, resolver ConditionResolver) bool` — Task 2 calls this exact function per-candidate-primitive during search.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adchain/satisfied_test.go
package adchain

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestSatisfied_RequiresEveryHeldCapabilityPresent(t *testing.T) {
	p := adprimitive.Primitive{
		Prerequisites: adprimitive.Prerequisites{
			Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}},
		},
	}
	if satisfied(p, nil, MapResolver{}) {
		t.Error("expected false: required capability not held")
	}
	if !satisfied(p, []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}, MapResolver{}) {
		t.Error("expected true: required capability held")
	}
}

func TestSatisfied_TargetScopedCapabilityDoesNotMatchHostAgnosticHeld(t *testing.T) {
	p := adprimitive.Primitive{
		Prerequisites: adprimitive.Prerequisites{
			Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapLocalAdmin, Target: "SERVER01"}},
		},
	}
	held := []adprimitive.Capability{{Kind: adprimitive.CapLocalAdmin}} // no Target
	if satisfied(p, held, MapResolver{}) {
		t.Error("expected false: held capability has no Target, prerequisite requires Target=SERVER01")
	}
}

func TestSatisfied_EmptyConditionsIsVacuouslyTrue(t *testing.T) {
	p := adprimitive.Primitive{} // no Capabilities, no Conditions
	if !satisfied(p, nil, MapResolver{}) {
		t.Error("expected true: no requirements at all")
	}
}

func TestSatisfied_ConditionsResolvedViaResolver(t *testing.T) {
	p := adprimitive.Primitive{
		Prerequisites: adprimitive.Prerequisites{
			Conditions: map[string]bool{"acl_right_held:GenericAll": true},
		},
	}
	if satisfied(p, nil, MapResolver{}) {
		t.Error("expected false: resolver has no entry, defaults to false")
	}
	resolver := MapResolver{"acl_right_held:GenericAll": true}
	if !satisfied(p, nil, resolver) {
		t.Error("expected true: resolver confirms the condition")
	}
}

func TestSatisfied_AConditionRequiredFalseMustNotBeResolvedTrue(t *testing.T) {
	// Prerequisites.Conditions maps key -> required boolean value; a
	// primitive could in principle require a condition to be FALSE.
	p := adprimitive.Primitive{
		Prerequisites: adprimitive.Prerequisites{
			Conditions: map[string]bool{"manager_approval_required": false},
		},
	}
	resolver := MapResolver{"manager_approval_required": true}
	if satisfied(p, nil, resolver) {
		t.Error("expected false: condition requires false, resolver says true")
	}
	resolver2 := MapResolver{"manager_approval_required": false}
	if !satisfied(p, nil, resolver2) {
		t.Error("expected true: condition requires false, resolver agrees")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adchain/... -v`
Expected: FAIL — `undefined: satisfied` / `undefined: MapResolver` (package doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adchain/resolver.go

// Package adchain implements AD-M05: the capability-state chaining
// mechanism adprimitive's own doc comment names as this phase's job --
// matching one primitive's Postconditions against another's
// Prerequisites.Capabilities by equality. Depends one-way on
// adprimitive only.
package adchain

// ConditionResolver answers whether a Prerequisites.Conditions key holds
// true in some environment context. Resolving a key against a REAL
// environment's graph (attackpath/adenv) is explicitly out of scope for
// this phase -- ConditionResolver is the seam a later phase fills in.
type ConditionResolver interface {
	Resolve(key string) bool
}

// MapResolver is a trivial ConditionResolver backed by a plain map, for
// tests and for any caller that already has a fully-resolved condition
// set in hand. A key with no entry resolves to false (the catalog's own
// fail-closed convention: an unconfirmed condition is not satisfied).
type MapResolver map[string]bool

func (m MapResolver) Resolve(key string) bool {
	return m[key]
}
```

```go
// orchestrator/internal/adchain/satisfied.go
package adchain

import "github.com/audspect/bas/internal/adprimitive"

// satisfied reports whether p's Prerequisites are met: every required
// Capability is present in held (by exact Kind+Target equality), and
// every Conditions entry resolves to the required boolean value.
// Prerequisites.DomainJoined/Privileges are not evaluated here -- no
// caller-supplied attacker-context input exists yet for this phase.
func satisfied(p adprimitive.Primitive, held []adprimitive.Capability, resolver ConditionResolver) bool {
	for _, want := range p.Prerequisites.Capabilities {
		if !containsCapability(held, want) {
			return false
		}
	}
	for key, want := range p.Prerequisites.Conditions {
		if resolver.Resolve(key) != want {
			return false
		}
	}
	return true
}

func containsCapability(held []adprimitive.Capability, want adprimitive.Capability) bool {
	for _, h := range held {
		if h == want {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adchain/... -v`
Expected: PASS — all 5 new tests.

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adchain/ && go vet ./internal/adchain/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adchain/resolver.go orchestrator/internal/adchain/satisfied.go orchestrator/internal/adchain/satisfied_test.go
git commit -m "$(cat <<'EOF'
feat(adchain): add ConditionResolver and prerequisite satisfaction (AD-M05 task 1 of 2)

New package adchain, depending one-way on adprimitive only. satisfied()
checks a Primitive's Prerequisites against a held-capability set (exact
Kind+Target equality) and a ConditionResolver (fail-closed: unresolved
key = not satisfied). DomainJoined/Privileges are not evaluated this
phase -- no caller-supplied attacker-context input exists yet.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `Reachable` and `Plan`

**Files:**
- Create: `orchestrator/internal/adchain/search.go`
- Test: `orchestrator/internal/adchain/search_test.go`

**Interfaces:**
- Consumes: `satisfied` (Task 1), `MapResolver` (Task 1), `adprimitive.Primitive`/`Capability`.
- Produces: `Reachable(catalog []adprimitive.Primitive, held []adprimitive.Capability, resolver ConditionResolver) []adprimitive.Capability`, `Plan(catalog []adprimitive.Primitive, held []adprimitive.Capability, target adprimitive.Capability, resolver ConditionResolver) ([]adprimitive.Primitive, bool)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adchain/search_test.go
package adchain

import (
	"reflect"
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func chainCatalog() []adprimitive.Primitive {
	return []adprimitive.Primitive{
		{
			ID:             "step-a",
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapKerberoastableTargetKnown}},
		},
		{
			ID:             "step-b",
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapKerberoastableTargetKnown}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapServiceAccountCredential}},
		},
		{
			// Unreachable from CapDomainUser alone -- requires a capability
			// nothing in this catalog ever produces.
			ID:             "step-unreachable",
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapLocalAdmin}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapDomainCredentialMaterial}},
		},
	}
}

func TestReachable_FollowsMultiStepChain(t *testing.T) {
	got := Reachable(chainCatalog(), []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}, MapResolver{})
	want := map[adprimitive.Capability]bool{
		{Kind: adprimitive.CapDomainUser}:               true,
		{Kind: adprimitive.CapKerberoastableTargetKnown}: true,
		{Kind: adprimitive.CapServiceAccountCredential}:  true,
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d reachable capabilities, got %d: %+v", len(want), len(got), got)
	}
	for _, c := range got {
		if !want[c] {
			t.Errorf("unexpected reachable capability %+v", c)
		}
	}
}

func TestReachable_TerminatesOnCyclicCatalog(t *testing.T) {
	cyclic := []adprimitive.Primitive{
		{
			ID:             "cycle-a",
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapGroupMember}},
		},
		{
			ID:             "cycle-b",
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapGroupMember}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}, // already held -- would loop forever without a fixpoint check
		},
	}
	done := make(chan []adprimitive.Capability, 1)
	go func() {
		done <- Reachable(cyclic, []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}, MapResolver{})
	}()
	select {
	case got := <-done:
		if len(got) != 2 {
			t.Errorf("expected 2 reachable capabilities (DomainUser, GroupMember), got %d: %+v", len(got), got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Reachable did not terminate on a cyclic catalog")
	}
}

func TestPlan_ReturnsOrderedPathToTarget(t *testing.T) {
	path, ok := Plan(chainCatalog(), []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}, adprimitive.Capability{Kind: adprimitive.CapServiceAccountCredential}, MapResolver{})
	if !ok {
		t.Fatal("expected target to be reachable")
	}
	var ids []string
	for _, p := range path {
		ids = append(ids, p.ID)
	}
	if !reflect.DeepEqual(ids, []string{"step-a", "step-b"}) {
		t.Fatalf("expected ordered path [step-a step-b], got %v", ids)
	}
}

func TestPlan_UnreachableTargetReturnsFalse(t *testing.T) {
	_, ok := Plan(chainCatalog(), []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}, adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial}, MapResolver{})
	if ok {
		t.Fatal("expected target to be unreachable (step-unreachable requires CapLocalAdmin, never produced)")
	}
}
```

Add `"time"` to the test file's imports (used by the cyclic-termination test's timeout).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adchain/... -v`
Expected: FAIL — `undefined: Reachable` / `undefined: Plan`.

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adchain/search.go
package adchain

import "github.com/audspect/bas/internal/adprimitive"

// Reachable computes the full closure of capabilities reachable from
// held by repeatedly applying any primitive in catalog whose
// Prerequisites become satisfied, until a pass adds nothing new (a
// fixpoint) -- which also bounds the loop on a catalog containing a
// cycle, since a cycle stops producing anything new once every capability
// it can reach is already held.
func Reachable(catalog []adprimitive.Primitive, held []adprimitive.Capability, resolver ConditionResolver) []adprimitive.Capability {
	for {
		added := false
		for _, p := range catalog {
			if !satisfied(p, held, resolver) {
				continue
			}
			for _, post := range p.Postconditions {
				if !containsCapability(held, post) {
					held = append(held, post)
					added = true
				}
			}
		}
		if !added {
			return held
		}
	}
}

// Plan searches for one ordered sequence of primitives from catalog
// that, applied in order starting from held, produces target. Returns
// ok=false if target is never reachable under catalog/held/resolver.
func Plan(catalog []adprimitive.Primitive, held []adprimitive.Capability, target adprimitive.Capability, resolver ConditionResolver) ([]adprimitive.Primitive, bool) {
	var path []adprimitive.Primitive
	for _, c := range held {
		if c == target {
			return path, true
		}
	}
	for {
		applied := false
		for _, p := range catalog {
			if !satisfied(p, held, resolver) {
				continue
			}
			newCapability := false
			for _, post := range p.Postconditions {
				if !containsCapability(held, post) {
					held = append(held, post)
					newCapability = true
				}
			}
			if !newCapability {
				continue
			}
			path = append(path, p)
			applied = true
			for _, post := range p.Postconditions {
				if post == target {
					return path, true
				}
			}
		}
		if !applied {
			return nil, false
		}
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adchain/... -v`
Expected: PASS — all tests (5 from Task 1, 4 new).

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adchain/ && go vet ./internal/adchain/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adchain/search.go orchestrator/internal/adchain/search_test.go
git commit -m "$(cat <<'EOF'
feat(adchain): add Reachable and Plan search (AD-M05 task 2 of 2)

Reachable: fixpoint closure over a catalog -- repeatedly applies any
primitive whose prerequisites are met until a pass adds nothing new,
which also bounds the loop on a cyclic catalog. Plan: same search,
tracking and returning one ordered primitive path to a specific
target capability, or ok=false if unreachable.

Pure graph-reachability algorithm over typed values -- no technique
narrative. Closes AD-M05; a real environment-graph ConditionResolver
implementation (bridging to adenv/attackpath) is a future phase's job,
not this one's.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** 2 small, sequential tasks over a brand-new package; proceeding directly to execution via `superpowers:executing-plans`.
