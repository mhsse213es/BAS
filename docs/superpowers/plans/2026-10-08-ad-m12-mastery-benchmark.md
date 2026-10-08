# AD-M12 Mastery Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give AD-M12 ("AD Mastery Benchmark") — the final phase — a pure, read-only aggregation that measures the AD primitive library this initiative built: total primitives, breakdown by `RiskClass`, how many are MITRE-technique-mapped (the ones `addetect`/`adcve` can bridge), and the distinct ATT&CK techniques covered. A thin rollup over the in-memory catalogs, matching the repo's lightweight `dashboard.Snapshot` "thin consumer, nil-safe zero-value" model. No DB, no new security content, no scoring of any real environment.

**Architecture:** New package `orchestrator/internal/adbench`, depending one-way on `adprimitive` only. `Compute(catalogs ...[]adprimitive.Primitive) Benchmark` aggregates any set of primitive catalogs into a `Benchmark` struct (counts + a sorted distinct-technique list). `All() []adprimitive.Primitive` returns the five shipped catalogs (`Kerberoasting`/`ACLAbuse`/`RBCD`/`DCSync`/`ADCS`) concatenated, so a caller gets the real library's benchmark with one call. Pure in-memory counting — no ratio against an external universe (unlike `coverage.Compute`, which joins against DB-sourced membership sets; the AD catalogs are self-contained Go data, so the benchmark measures the library itself, not its coverage of some external target).

**Tech Stack:** Go (stdlib `sort` only; no new dependencies). No DB — pure function over typed values, tested without any container.

**Spec:** No separate written spec document — bounded, conversationally-approved task, the final phase of the user-approved wave process. Source: `orchestrator/internal/adprimitive/{catalog.go,types.go}` (the five catalogs + `Primitive`/`RiskClass`).

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- `adbench` depends on `adprimitive` only — no `adchain`/`adenv`/`attackpath`/DB/`analytics`.
- No change to `adprimitive` or any other existing package.
- `Benchmark`'s maps/slices are always non-nil and safe to range over even for empty input (nil-safe zero-value convention, matching `dashboard.Snapshot`).
- No narrative about what any primitive or technique does — this is counting and categorizing opaque IDs.

## Review Focus

- `Compute` with NO catalogs (or only empty ones) must return a zero-value-but-non-nil `Benchmark` (`TotalPrimitives`=0, `ByRiskClass` an empty non-nil map, `DistinctTechniques` an empty non-nil slice) — a caller ranging over the maps/slice must never nil-panic. Tested in Task 1, Step 1.
- `ByRiskClass` counts must sum exactly to `TotalPrimitives` — every primitive is counted in exactly one risk bucket (including the empty/unclassified `RiskClass` as its own key), so a drift between the per-class sum and the total would mean a primitive was dropped or double-counted. Tested in Task 1, Step 1.
- `DistinctTechniques` must dedup (ADCS's 4 primitives all share `T1649`; Kerberoasting's 2 share `T1558.003`) and must NOT contain the empty string (the 6 primitives with no `TechniqueID` contribute nothing), and must be sorted for deterministic output. Tested in Task 1, Step 1.
- `TechniqueMapped` must equal the count of primitives with a non-empty `TechniqueID` (8 of the real 14), NOT the count of distinct techniques (6) — these differ because of the shared IDs, and conflating them would misreport how many primitives are detection-bridgeable. Tested in Task 1, Step 1.

---

### Task 1: `Benchmark`, `Compute`, and `All`

**Files:**
- Create: `orchestrator/internal/adbench/benchmark.go`
- Test: `orchestrator/internal/adbench/benchmark_test.go`

**Interfaces:**
- Consumes: `adprimitive.Primitive`/`RiskClass`, the five `adprimitive.*Catalog` vars.
- Produces: `Benchmark` struct, `Compute(catalogs ...[]adprimitive.Primitive) Benchmark`, `All() []adprimitive.Primitive`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adbench/benchmark_test.go
package adbench

import (
	"reflect"
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestCompute_EmptyInputIsZeroValueButNonNil(t *testing.T) {
	b := Compute()
	if b.TotalPrimitives != 0 {
		t.Errorf("expected 0 total, got %d", b.TotalPrimitives)
	}
	if b.ByRiskClass == nil {
		t.Error("ByRiskClass must be non-nil even for empty input")
	}
	if b.DistinctTechniques == nil {
		t.Error("DistinctTechniques must be non-nil even for empty input")
	}
	if len(b.ByRiskClass) != 0 || len(b.DistinctTechniques) != 0 {
		t.Errorf("expected empty maps/slices, got %+v", b)
	}
}

func TestCompute_CountsDedupsAndSorts(t *testing.T) {
	catalog := []adprimitive.Primitive{
		{ID: "a", TechniqueID: "T1649", RiskClass: adprimitive.RiskPotentiallyDestructive},
		{ID: "b", TechniqueID: "T1649", RiskClass: adprimitive.RiskPotentiallyDestructive}, // shares T1649
		{ID: "c", TechniqueID: "T1003.006", RiskClass: adprimitive.RiskPotentiallyDestructive},
		{ID: "d", TechniqueID: "", RiskClass: adprimitive.RiskNonDestructive}, // no technique
	}
	b := Compute(catalog)

	if b.TotalPrimitives != 4 {
		t.Errorf("expected 4 total, got %d", b.TotalPrimitives)
	}
	// Risk buckets sum to total.
	sum := 0
	for _, n := range b.ByRiskClass {
		sum += n
	}
	if sum != b.TotalPrimitives {
		t.Errorf("ByRiskClass sums to %d, expected %d", sum, b.TotalPrimitives)
	}
	if b.ByRiskClass[adprimitive.RiskPotentiallyDestructive] != 3 || b.ByRiskClass[adprimitive.RiskNonDestructive] != 1 {
		t.Errorf("unexpected risk breakdown: %+v", b.ByRiskClass)
	}
	// TechniqueMapped counts PRIMITIVES with a technique (3), not distinct techniques (2).
	if b.TechniqueMapped != 3 {
		t.Errorf("expected 3 technique-mapped primitives, got %d", b.TechniqueMapped)
	}
	// Distinct techniques: deduped, no empty string, sorted.
	if !reflect.DeepEqual(b.DistinctTechniques, []string{"T1003.006", "T1649"}) {
		t.Errorf("expected [T1003.006 T1649], got %v", b.DistinctTechniques)
	}
}

func TestAll_ReturnsTheFourteenShippedPrimitives(t *testing.T) {
	all := All()
	if len(all) != 14 {
		t.Fatalf("expected 14 primitives across the five shipped catalogs, got %d", len(all))
	}
	b := Compute(All())
	if b.TotalPrimitives != 14 {
		t.Errorf("expected benchmark total 14, got %d", b.TotalPrimitives)
	}
	// Of the 14, exactly 8 carry a TechniqueID (Kerberoasting 3 + DCSync 1 +
	// ADCS 4); the 6 ACL-abuse/RBCD primitives carry none.
	if b.TechniqueMapped != 8 {
		t.Errorf("expected 8 technique-mapped primitives, got %d", b.TechniqueMapped)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adbench/... -v`
Expected: FAIL — `undefined: Compute` / `undefined: All` (package doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adbench/benchmark.go

// Package adbench implements AD-M12 ("AD Mastery Benchmark"): a pure,
// read-only aggregation that measures the AD primitive library built by
// this initiative -- total primitives, breakdown by RiskClass, how many
// are MITRE-technique-mapped, and the distinct ATT&CK techniques covered.
// Depends one-way on adprimitive only; no DB, no external universe to
// measure coverage against -- the catalogs are self-contained Go data, so
// this benchmarks the library itself.
package adbench

import (
	"sort"

	"github.com/audspect/bas/internal/adprimitive"
)

// Benchmark is the read-only summary of a set of primitive catalogs.
type Benchmark struct {
	TotalPrimitives    int
	ByRiskClass        map[adprimitive.RiskClass]int
	TechniqueMapped    int      // primitives with a non-empty TechniqueID
	DistinctTechniques []string // deduped, sorted, no empty string
}

// All returns the five shipped primitive catalogs concatenated, so a
// caller can benchmark the whole library with Compute(All()).
func All() []adprimitive.Primitive {
	var out []adprimitive.Primitive
	out = append(out, adprimitive.KerberoastingCatalog...)
	out = append(out, adprimitive.ACLAbuseCatalog...)
	out = append(out, adprimitive.RBCDCatalog...)
	out = append(out, adprimitive.DCSyncCatalog...)
	out = append(out, adprimitive.ADCSCatalog...)
	return out
}

// Compute aggregates any set of primitive catalogs into a Benchmark. Its
// maps and slices are always non-nil, safe to range over for empty input.
func Compute(catalogs ...[]adprimitive.Primitive) Benchmark {
	b := Benchmark{
		ByRiskClass:        map[adprimitive.RiskClass]int{},
		DistinctTechniques: []string{},
	}
	techniques := map[string]bool{}
	for _, catalog := range catalogs {
		for _, p := range catalog {
			b.TotalPrimitives++
			b.ByRiskClass[p.RiskClass]++
			if p.TechniqueID != "" {
				b.TechniqueMapped++
				techniques[p.TechniqueID] = true
			}
		}
	}
	for id := range techniques {
		b.DistinctTechniques = append(b.DistinctTechniques, id)
	}
	sort.Strings(b.DistinctTechniques)
	return b
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adbench/... -v`
Expected: PASS — all 3 tests.

- [ ] **Step 5: Run gofmt, go vet, and the full build**

Run: `cd orchestrator && gofmt -l internal/adbench/ && go vet ./internal/adbench/... && go build ./... && git status --short internal/adprimitive`
Expected: gofmt/vet print nothing, build succeeds, `git status` on `adprimitive` prints nothing (confirming this phase touched nothing existing).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adbench/benchmark.go orchestrator/internal/adbench/benchmark_test.go
git commit -m "$(cat <<'EOF'
feat(adbench): add AD-M12 mastery benchmark (read-only catalog aggregation)

Compute aggregates primitive catalogs into a Benchmark: total count,
per-RiskClass breakdown (buckets sum to total), count of
technique-mapped primitives (8 of the real 14), and the deduped/sorted
distinct ATT&CK techniques covered (6, since ADCS's 4 share T1649 and
Kerberoasting's 2 share T1558.003). All() returns the five shipped
catalogs concatenated. Pure in-memory, nil-safe, no DB, no new content.

Closes AD-M12 -- the final phase. The AD Mastery initiative's full
pipeline (M01 ontology -> M02 mapping -> M03 graph flags -> M04
primitives -> M05 chains -> M07 risk -> M08 detection bridge -> M09
registry wiring -> M10 CVE bridge -> M11 adaptive engine -> M12
benchmark) is now complete.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Single task, pure aggregation over one already-existing package; proceeding directly to execution via `superpowers:executing-plans`.
