# E1 — AD Runtime Capability Inventory (ART/Caldera) Design

**Date:** 2026-10-09
**Sub-project:** E, slice E1 (first slice of the AD coverage-gap implementation track)
**Status:** Design — awaiting spec review before planning.

## Purpose

Sub-project E must answer, for the 11 identified AD coverage gaps, *which are
already covered by the live ART / Caldera capability libraries (reusable) and
which are genuinely missing (would need authored content)*. Sub-project A
already proved there is **zero scenario-corpus coverage** for these techniques,
but A was explicit that the **ART atomic index and Caldera ability library are
runtime-only** (ART in Postgres, Caldera baked into the `bas-caldera` image) —
they cannot be inventoried statically from the repo.

E1 builds the **inventory logic and the interface seam** that, given those two
runtime stores, reports per-technique coverage. The pure logic and the seam are
built and unit-tested now with fixtures; only the *live wiring* (constructing
the stores from a running DB / Caldera and running the inventory against them)
is deferred, because it needs a live system.

E1 is read-only analysis. It authors no attack content, executes nothing, and
changes no existing store, scenario, or dispatch code.

## Non-goals / exclusions

- No payloads, no new executable content, no scenario authoring (that is E2+,
  gated on this inventory + lab infrastructure).
- No changes to `scenario.ARTStore`, `scenario.CalderaStore`, `dispatchRun`,
  run modes, or execution behavior.
- No technique-ID assignment to the 6 ACL/RBCD primitives — the catalog
  deliberately leaves those empty ("empty is more honest"), and E1 preserves
  that by reporting them as un-inventoriable-by-technique rather than inventing
  IDs.
- No platform-specific (Windows-only) filtering in v1 — "the library has *any*
  atomic/ability for this technique" is the v1 signal; platform-aware refinement
  is noted as future work.

## Background: verified runtime interfaces

Both stores already expose exactly what an inventory needs (read from
`orchestrator/internal/scenario/art.go` and `caldera_store.go`):

- `*scenario.ARTStore`: `GetSteps(techniqueID string) []ScenarioStep`,
  `ListTechniques() []string`, `UnknownTechniques(ids []string) []string`;
  runtime constructor `NewARTStoreFromDB(ctx, pool, payloads)`.
- `*scenario.CalderaStore`: `GetAbilities(techniqueID string) []ScenarioStep`,
  `ListTechniqueIDs() []string`; constructors `NewCalderaStore(url, apiKey)`
  and `NewCalderaStoreFromSteps(map[string][]ScenarioStep)` (the latter needs no
  live Caldera — usable in tests).

E1 depends on these through **narrow local interfaces**, so it never couples to
the stores' construction and is fully testable with fakes.

## Architecture

New pure-Go package `orchestrator/internal/adlibinv` ("AD library inventory").
Dependencies: `scenario` (for the `ScenarioStep` type only) and `adprimitive`
(for `Primitive`). No DB, no containers, no network.

### Source seam

```go
// ARTSource is the subset of *scenario.ARTStore adlibinv consumes.
type ARTSource interface {
    GetSteps(techniqueID string) []scenario.ScenarioStep
}

// CalderaSource is the subset of *scenario.CalderaStore adlibinv consumes.
type CalderaSource interface {
    GetAbilities(techniqueID string) []scenario.ScenarioStep
}
```

Compile-time assertions in the package's test file prove the real stores
satisfy these seams without a live system:

```go
var _ ARTSource = (*scenario.ARTStore)(nil)
var _ CalderaSource = (*scenario.CalderaStore)(nil)
```

### Data model

```go
// TechCoverage is the inventory result for one distinct ATT&CK technique that
// at least one input primitive maps to.
type TechCoverage struct {
    TechniqueID  string   // e.g. "T1003.006"
    PrimitiveIDs []string // gap primitives mapping to this technique, sorted
    ARTAtomics   int      // count of ART steps the store returns for it
    CalderaAbils int      // count of Caldera steps the store returns for it
    Covered      bool     // ARTAtomics+CalderaAbils > 0
}

// Report is the full inventory over a set of primitives.
type Report struct {
    Covered       []TechCoverage // Covered == true,  sorted by TechniqueID
    Missing       []TechCoverage // Covered == false, sorted by TechniqueID
    NoTechniqueID []string       // primitive IDs with empty TechniqueID, sorted
}
```

### Entry point

```go
// Inventory reports, per technique, whether the live ART/Caldera libraries
// already cover it. A nil source contributes zero (fail-safe: the inventory
// still runs with one store unavailable). Pure and total; executes nothing.
func Inventory(primitives []adprimitive.Primitive, art ARTSource, caldera CalderaSource) Report
```

Behavior:
1. Group the input primitives by `TechniqueID`. Primitives whose `TechniqueID`
   is `""` go to `Report.NoTechniqueID` (by primitive `ID`), never to
   Covered/Missing.
2. For each distinct non-empty technique, count `len(art.GetSteps(tid))` and
   `len(caldera.GetAbilities(tid))`; `Covered = (sum > 0)`.
3. A `nil` `art`/`caldera` is treated as contributing 0 (no panic).
4. All slices are deterministically sorted (`TechCoverage` by `TechniqueID`;
   `PrimitiveIDs` and `NoTechniqueID` lexicographically).

### What the report says about the 11 gaps

- **5 technique-bearing gaps** (`dcsync` T1003.006; the four ADCS primitives,
  all T1649 → one `TechCoverage` with four `PrimitiveIDs`) are classified
  Covered vs Missing once run against the live stores.
- **6 ACL/RBCD gaps** (empty `TechniqueID`) land in `NoTechniqueID` — honestly
  reported as not inventoriable by technique, no ID invented.

## Live wiring (deferred — documented, not built)

A package-level doc comment records the one-time runtime invocation for when a
live system is available:

```
art, _ := scenario.NewARTStoreFromDB(ctx, pool, payloads)
caldera := scenario.NewCalderaStore(calderaURL, apiKey) // or inject loaded steps
rep := adlibinv.Inventory(adbench.All(), art, caldera)
```

This is not built or tested in E1 because it requires the Postgres pool and a
running Caldera; E1 ships the tested logic + seam and this note.

## Error handling

Pure and total: no error return. Nil sources and empty libraries are normal
inputs yielding zeroed counts, not errors. The caller owns store construction
and its failure modes (that is the deferred live-wiring concern).

## Testing

TDD, synthetic fixtures only (no live system):

1. Technique covered by ART (`GetSteps` returns ≥1) → in `Covered`, `ARTAtomics`
   correct, `Covered == true`.
2. Technique covered only by Caldera → in `Covered`, `CalderaAbils` correct.
3. Technique in neither store → in `Missing`, `Covered == false`.
4. Multiple primitives sharing one technique (two T1649 primitives) → a single
   `TechCoverage` with both `PrimitiveIDs`, sorted.
5. Primitives with empty `TechniqueID` → in `NoTechniqueID` (sorted), absent
   from Covered/Missing.
6. `nil` art and/or caldera source → no panic; techniques fall to `Missing`.
7. Determinism: `Covered`/`Missing` sorted by `TechniqueID`.
8. Compile-time: `*scenario.ARTStore` satisfies `ARTSource`,
   `*scenario.CalderaStore` satisfies `CalderaSource` (the seam binds to the
   real stores).
9. Real-store binding without a live system: build a `CalderaStore` via
   `NewCalderaStoreFromSteps` with a fixture ability, inventory a matching
   primitive, assert it is Covered (proves the real Caldera store flows through
   the seam, not just a fake).

Package test command: `go test ./internal/adlibinv/...`.

## Review focus (inputs the tests must pin)

- Empty `TechniqueID` must route to `NoTechniqueID`, never be counted as a
  technique (would create a phantom "" technique row).
- A `nil` source must not panic (one store down is a normal operating state).
- Duplicate primitives / shared techniques must collapse to one row with all
  contributing primitive IDs, not duplicate rows.
- Output ordering must be deterministic regardless of input primitive order.
