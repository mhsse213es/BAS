# E1 — AD Runtime Capability Inventory (ART/Caldera) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided: native/inline). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pure-Go `adlibinv` package that reports, per ATT&CK technique, whether the live ART/Caldera libraries already cover a set of AD gap primitives (reusable) or not (genuinely missing).

**Architecture:** A new leaf package `orchestrator/internal/adlibinv` defines two narrow source interfaces (`ARTSource`, `CalderaSource`) that the real `*scenario.ARTStore`/`*scenario.CalderaStore` already satisfy, plus a pure `Inventory(primitives, art, caldera) Report` that groups primitives by technique and counts library hits. The pure logic + seam are built and fixture-tested now; live wiring (DB pool / running Caldera) is documented, not built.

**Tech Stack:** Go; packages `github.com/audspect/bas/internal/scenario` (for the `ScenarioStep` type) and `github.com/audspect/bas/internal/adprimitive` (for `Primitive`); standard `sort`.

**Spec:** `docs/superpowers/specs/2026-10-09-e1-ad-library-inventory-design.md`

## Global Constraints

- Pure Go, leaf package. Dependencies limited to `scenario` and `adprimitive` only — no DB, no containers, no network.
- Module path is `github.com/audspect/bas`; package import paths are `github.com/audspect/bas/internal/<pkg>`.
- No payloads, no executable/attack content, no execution of anything.
- No changes to `scenario.ARTStore`, `scenario.CalderaStore`, `dispatchRun`, run modes, or execution behavior.
- Do NOT assign technique IDs to the ACL/RBCD primitives; empty `TechniqueID` is reported via `Report.NoTechniqueID` (preserve the catalog's deliberate "empty is more honest").
- No platform-specific filtering in v1: "the library has any atomic/ability for this technique" is the signal.
- `Inventory` is pure and total: no error return, no panics on `nil` sources or empty input.
- Package test command: `go test ./internal/adlibinv/...` (run from `orchestrator/`).

## Review Focus

- Empty `TechniqueID` must route to `Report.NoTechniqueID`, never become a `""` technique row — pinned in Task 1, `TestInventory_EmptyTechniqueIDGoesToNoTechniqueID`.
- A `nil` ART or Caldera source must not panic (one store down is normal) — pinned in Task 1, `TestInventory_NilSourcesDoNotPanicAndFallToMissing`.
- Multiple primitives sharing one technique must collapse to a single row carrying all primitive IDs — pinned in Task 1, `TestInventory_PrimitivesSharingTechniqueCollapseToOneRow`.
- Output ordering must be deterministic regardless of input primitive order — pinned in Task 1, `TestInventory_OutputIsSortedByTechniqueID`.
- The real `*scenario.CalderaStore` (not just a fake) must flow through the seam and be counted as coverage — pinned in Task 2, `TestInventory_RealCalderaStoreFromStepsIsCounted`.

---

### Task 1: Core inventory logic, types, and seam (with fakes)

**Files:**
- Create: `orchestrator/internal/adlibinv/inventory.go`
- Test: `orchestrator/internal/adlibinv/inventory_test.go`

**Interfaces:**
- Consumes: `scenario.ScenarioStep` (struct, used only for its slice length); `adprimitive.Primitive` (fields `ID string`, `TechniqueID string`).
- Produces:
  - `type ARTSource interface { GetSteps(techniqueID string) []scenario.ScenarioStep }`
  - `type CalderaSource interface { GetAbilities(techniqueID string) []scenario.ScenarioStep }`
  - `type TechCoverage struct { TechniqueID string; PrimitiveIDs []string; ARTAtomics int; CalderaAbils int; Covered bool }`
  - `type Report struct { Covered []TechCoverage; Missing []TechCoverage; NoTechniqueID []string }`
  - `func Inventory(primitives []adprimitive.Primitive, art ARTSource, caldera CalderaSource) Report`

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/adlibinv/inventory_test.go`:

```go
package adlibinv

import (
	"reflect"
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/scenario"
)

// fakeART / fakeCaldera are in-memory sources keyed by technique ID.
type fakeART map[string][]scenario.ScenarioStep

func (f fakeART) GetSteps(t string) []scenario.ScenarioStep { return f[t] }

type fakeCaldera map[string][]scenario.ScenarioStep

func (f fakeCaldera) GetAbilities(t string) []scenario.ScenarioStep { return f[t] }

func prim(id, tech string) adprimitive.Primitive {
	return adprimitive.Primitive{ID: id, TechniqueID: tech}
}

func steps(n int) []scenario.ScenarioStep {
	return make([]scenario.ScenarioStep, n)
}

func TestInventory_TechniqueCoveredByARTIsReportedCovered(t *testing.T) {
	rep := Inventory(
		[]adprimitive.Primitive{prim("dcsync", "T1003.006")},
		fakeART{"T1003.006": steps(2)},
		fakeCaldera{},
	)
	if len(rep.Covered) != 1 || len(rep.Missing) != 0 {
		t.Fatalf("expected 1 covered / 0 missing, got %+v", rep)
	}
	c := rep.Covered[0]
	if c.TechniqueID != "T1003.006" || c.ARTAtomics != 2 || c.CalderaAbils != 0 || !c.Covered {
		t.Fatalf("unexpected coverage row: %+v", c)
	}
}

func TestInventory_TechniqueCoveredOnlyByCalderaIsReportedCovered(t *testing.T) {
	rep := Inventory(
		[]adprimitive.Primitive{prim("p", "T9999")},
		fakeART{},
		fakeCaldera{"T9999": steps(3)},
	)
	if len(rep.Covered) != 1 || rep.Covered[0].CalderaAbils != 3 || rep.Covered[0].ARTAtomics != 0 {
		t.Fatalf("expected caldera-only coverage, got %+v", rep)
	}
}

func TestInventory_TechniqueInNeitherStoreIsMissing(t *testing.T) {
	rep := Inventory(
		[]adprimitive.Primitive{prim("adcs-esc1", "T1649")},
		fakeART{},
		fakeCaldera{},
	)
	if len(rep.Missing) != 1 || rep.Missing[0].Covered || len(rep.Covered) != 0 {
		t.Fatalf("expected 1 missing / 0 covered, got %+v", rep)
	}
}

func TestInventory_PrimitivesSharingTechniqueCollapseToOneRow(t *testing.T) {
	rep := Inventory(
		[]adprimitive.Primitive{prim("adcs-esc2", "T1649"), prim("adcs-esc1", "T1649")},
		fakeART{},
		fakeCaldera{},
	)
	if len(rep.Missing) != 1 {
		t.Fatalf("expected the two T1649 primitives to collapse to one row, got %+v", rep.Missing)
	}
	got := rep.Missing[0].PrimitiveIDs
	if !reflect.DeepEqual(got, []string{"adcs-esc1", "adcs-esc2"}) {
		t.Fatalf("expected sorted primitive IDs, got %v", got)
	}
}

func TestInventory_EmptyTechniqueIDGoesToNoTechniqueID(t *testing.T) {
	rep := Inventory(
		[]adprimitive.Primitive{prim("rbcd-impersonate", ""), prim("acl-genericall-takeover", "")},
		fakeART{},
		fakeCaldera{},
	)
	if len(rep.Covered) != 0 || len(rep.Missing) != 0 {
		t.Fatalf("empty-technique primitives must not appear in Covered/Missing, got %+v", rep)
	}
	if !reflect.DeepEqual(rep.NoTechniqueID, []string{"acl-genericall-takeover", "rbcd-impersonate"}) {
		t.Fatalf("expected sorted NoTechniqueID, got %v", rep.NoTechniqueID)
	}
}

func TestInventory_NilSourcesDoNotPanicAndFallToMissing(t *testing.T) {
	rep := Inventory([]adprimitive.Primitive{prim("dcsync", "T1003.006")}, nil, nil)
	if len(rep.Missing) != 1 || rep.Missing[0].ARTAtomics != 0 || rep.Missing[0].CalderaAbils != 0 {
		t.Fatalf("nil sources must yield a missing row with zero counts, got %+v", rep)
	}
}

func TestInventory_OutputIsSortedByTechniqueID(t *testing.T) {
	rep := Inventory(
		[]adprimitive.Primitive{prim("c", "T3000"), prim("a", "T1000"), prim("b", "T2000")},
		fakeART{"T1000": steps(1), "T2000": steps(1), "T3000": steps(1)},
		fakeCaldera{},
	)
	if len(rep.Covered) != 3 ||
		rep.Covered[0].TechniqueID != "T1000" ||
		rep.Covered[1].TechniqueID != "T2000" ||
		rep.Covered[2].TechniqueID != "T3000" {
		t.Fatalf("expected techniques sorted ascending, got %+v", rep.Covered)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/adlibinv/...`
Expected: FAIL — build error, `undefined: Inventory` (and the types), because `inventory.go` does not exist yet.

- [ ] **Step 3: Write the minimal implementation**

Create `orchestrator/internal/adlibinv/inventory.go`:

```go
// Package adlibinv inventories whether the live ART atomic and Caldera ability
// libraries already cover a set of AD gap primitives, per ATT&CK technique. It
// answers sub-project E's "reusable vs genuinely missing" question without
// authoring or executing any content.
//
// The ART/Caldera libraries are runtime-only (ART in Postgres, Caldera in the
// bas-caldera image), so the pure logic here is wired to the live stores only
// at runtime. Deferred live wiring, for when a running system is available:
//
//	art, _ := scenario.NewARTStoreFromDB(ctx, pool, payloads)
//	caldera := scenario.NewCalderaStore(calderaURL, apiKey)
//	rep := adlibinv.Inventory(primitives, art, caldera)
//
// That construction needs the DB pool and a running Caldera, so it is not built
// or tested in this package; the logic and the interface seam below are.
package adlibinv

import (
	"sort"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/scenario"
)

// ARTSource is the subset of *scenario.ARTStore this package consumes.
type ARTSource interface {
	GetSteps(techniqueID string) []scenario.ScenarioStep
}

// CalderaSource is the subset of *scenario.CalderaStore this package consumes.
type CalderaSource interface {
	GetAbilities(techniqueID string) []scenario.ScenarioStep
}

// TechCoverage is the inventory result for one distinct ATT&CK technique that
// at least one input primitive maps to.
type TechCoverage struct {
	TechniqueID  string
	PrimitiveIDs []string
	ARTAtomics   int
	CalderaAbils int
	Covered      bool
}

// Report is the full inventory over a set of primitives.
type Report struct {
	Covered       []TechCoverage
	Missing       []TechCoverage
	NoTechniqueID []string
}

// Inventory reports, per technique, whether the live ART/Caldera libraries
// already cover it. A nil source contributes zero (fail-safe: the inventory
// still runs with one store unavailable). Pure and total; executes nothing.
func Inventory(primitives []adprimitive.Primitive, art ARTSource, caldera CalderaSource) Report {
	byTech := map[string][]string{}
	var techniques []string
	var noTech []string
	for _, p := range primitives {
		if p.TechniqueID == "" {
			noTech = append(noTech, p.ID)
			continue
		}
		if _, seen := byTech[p.TechniqueID]; !seen {
			techniques = append(techniques, p.TechniqueID)
		}
		byTech[p.TechniqueID] = append(byTech[p.TechniqueID], p.ID)
	}

	sort.Strings(noTech)
	sort.Strings(techniques)

	rep := Report{NoTechniqueID: noTech}
	for _, tid := range techniques {
		ids := byTech[tid]
		sort.Strings(ids)
		artN := 0
		if art != nil {
			artN = len(art.GetSteps(tid))
		}
		calN := 0
		if caldera != nil {
			calN = len(caldera.GetAbilities(tid))
		}
		tc := TechCoverage{
			TechniqueID:  tid,
			PrimitiveIDs: ids,
			ARTAtomics:   artN,
			CalderaAbils: calN,
			Covered:      artN+calN > 0,
		}
		if tc.Covered {
			rep.Covered = append(rep.Covered, tc)
		} else {
			rep.Missing = append(rep.Missing, tc)
		}
	}
	return rep
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/adlibinv/...`
Expected: PASS (all 7 tests).

- [ ] **Step 5: Run gofmt and vet**

Run: `gofmt -l internal/adlibinv/ && go vet ./internal/adlibinv/...`
Expected: no output from `gofmt -l` (already formatted); `go vet` clean.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adlibinv/inventory.go orchestrator/internal/adlibinv/inventory_test.go
git commit -m "feat(adlibinv): add AD ART/Caldera capability inventory core"
```

---

### Task 2: Real-store seam binding + deferred-wiring guard

**Files:**
- Create: `orchestrator/internal/adlibinv/binding_test.go`

**Interfaces:**
- Consumes (from Task 1): `ARTSource`, `CalderaSource`, `Inventory`, `TechCoverage`, `Report`.
- Consumes (from `scenario`): `*scenario.ARTStore`, `*scenario.CalderaStore`, `scenario.NewCalderaStoreFromSteps(map[string][]scenario.ScenarioStep) *scenario.CalderaStore`, `scenario.ScenarioStep{Command, Name, TechniqueID string}`.
- Produces: no new production symbols — this task proves the real stores satisfy the Task 1 seam and that a real Caldera store flows through `Inventory`.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/adlibinv/binding_test.go`:

```go
package adlibinv

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/scenario"
)

// Compile-time proof that the real runtime stores satisfy the seam. If either
// store's method set drifts, this file fails to build — the drift alarm.
var (
	_ ARTSource     = (*scenario.ARTStore)(nil)
	_ CalderaSource = (*scenario.CalderaStore)(nil)
)

// A real *scenario.CalderaStore (built from steps, no live Caldera needed) must
// flow through the seam and be counted as coverage — not just the test fakes.
func TestInventory_RealCalderaStoreFromStepsIsCounted(t *testing.T) {
	store := scenario.NewCalderaStoreFromSteps(map[string][]scenario.ScenarioStep{
		"T1003.006": {{Command: "mimikatz", Name: "dcsync", TechniqueID: "T1003.006"}},
	})
	rep := Inventory(
		[]adprimitive.Primitive{prim("dcsync", "T1003.006")},
		nil,   // no ART in this test
		store, // the real Caldera store
	)
	if len(rep.Covered) != 1 || rep.Covered[0].CalderaAbils < 1 || !rep.Covered[0].Covered {
		t.Fatalf("real Caldera store must flow through the seam and count as coverage, got %+v", rep)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails for the right reason**

Run: `go test ./internal/adlibinv/... -run TestInventory_RealCalderaStoreFromStepsIsCounted -v`
Expected: this is a binding/regression test over logic that already exists from Task 1, so it should PASS immediately once the file compiles. The meaningful failure modes it guards are compile-time (a store no longer satisfies the seam) or behavioral (the real Caldera store's `GetAbilities` returns nothing for a technique it was given). If it fails to compile, the seam or a signature is wrong — fix via systematic-debugging before continuing. If it fails at runtime (0 abilities), investigate whether `NewCalderaStoreFromSteps` normalizes the technique-ID key (e.g. upper-casing); align the fixture key accordingly.

- [ ] **Step 3: Run the full package test suite**

Run: `go test ./internal/adlibinv/...`
Expected: PASS (Task 1's 7 tests + this binding test).

- [ ] **Step 4: Run gofmt and vet**

Run: `gofmt -l internal/adlibinv/ && go vet ./internal/adlibinv/...`
Expected: no output from `gofmt -l`; `go vet` clean.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/adlibinv/binding_test.go
git commit -m "test(adlibinv): bind inventory seam to the real ART/Caldera stores"
```

---

## Notes for the executor

- Run all `go test`/`gofmt`/`go vet` commands from the `orchestrator/` directory (that is where `go.mod` for the module lives in this repo layout; the import path `github.com/audspect/bas/internal/adlibinv` maps to `orchestrator/internal/adlibinv`).
- If `go test ./...` across the whole module is run as the final gate, expect it to be slow/Docker-touching in other packages — scope the suite to `./internal/adlibinv/...` for this plan's verification, and note any pre-existing unrelated failures by name rather than treating them as E1 regressions.
- This plan builds pure logic + the seam only. Running `Inventory` against the live ART (`NewARTStoreFromDB`) and a running Caldera is deliberately out of scope (documented in the `inventory.go` package comment).
