# AD Executable-Content Sub-Project A — Capability Coverage Map — Design Spec

**Status:** Draft for review
**Date:** 2026-10-08
**Parent initiative:** AD Mastery — "Executable AD content" (deferred execution layer), sub-project A of a five-part decomposition.

## Where this sits

"Executable AD content" was decomposed (user-approved 2026-10-08) into five
separately-specced sub-projects, in dependency order:

- **A — Capability inventory + Primitive→capability mapping** (this spec). No
  execution; pure cataloging of already-shipped content.
- B — Execution safety contract/gate (distinct from `execclass` classification;
  prerequisite for any controlled execution).
- C — Scenario composition (targeting the M06 synthetic lab).
- D — Controlled execution + validation (M06 lab ONLY, never production/customer
  AD; gated by B).
- E — Raw authoring for genuine coverage gaps (separate, explicitly-scoped; each
  gap gets its own go/no-go after establishing env state, expected outcome,
  safety classification, cleanup/rollback, and validation criteria).

Sub-project A authors no offensive content and executes nothing. It reads the
*metadata* of already-shipped, already-vetted scenario content and reports which
M04 primitives it already implements and which it does not. A's `Gaps` output is
the hand-off artifact that feeds E's per-gap decisions.

## Purpose

Establish, without authoring or running anything, that (and where) the M04
`adprimitive` primitives correspond to executable capabilities Audspect already
ships — and produce an honest, deterministic list of the primitives that have no
existing coverage.

## Scope

### In scope

- A new `orchestrator/internal/adcoverage` package (pure Go, no DB, no
  execution).
- A pure `Map` function joining `adprimitive` primitives to existing scenario
  steps by MITRE `TechniqueID`.
- A separable `IndexScenarios` loader that parses the in-repo scenario corpus
  into a `TechniqueID → []StepRef` index.
- A `Report` distinguishing covered primitives from gap primitives.

### Out of scope

- Any execution, scenario authoring, or new offensive commands (sub-projects
  C/D/E).
- Inventorying the ART atomic / Caldera ability *libraries* directly: those are
  runtime artifacts (images/Postgres), not in git. A keys on the in-repo
  **scenario steps**, which already carry the ART (`TestIndex`) and Caldera
  (`AbilityID`) references. A deeper runtime inventory is a possible later
  enhancement, not part of A.
- A hand-maintained name→capability association for the non-technique primitives.
  Those are reported as gaps (see Design decisions).

## Context (grounding facts, verified 2026-10-08)

- 220 scenario YAMLs are tracked in git under `scenarios/`.
- `scenario.Step` carries `TechniqueID`, `Framework` (`art`|`caldera`|`custom`),
  `AbilityID` (Caldera), `TestIndex` (ART), and risk/telemetry metadata.
- Of the 8 technique-mapped primitives: `T1558.003` and `T1558.004`
  (Kerberoasting SPN-enum / TGS-request / AS-REP-discover) have existing scenario
  coverage; `T1003.006` (DCSync) and `T1649` (all four ADCS primitives) have
  none.
- The 6 ACL-abuse and RBCD primitives have no `TechniqueID` at all.
- Expected A outcome over the real corpus: ~3 covered, ~11 gaps.

## Architecture

New package `orchestrator/internal/adcoverage`, depending one-way on
`adprimitive` and `scenario` (for the `Scenario`/`Step` types and YAML parsing).
No dependency on `adenv`/`adchain`/`adlab`/DB. Nothing imports it back.

### Types

```go
// StepRef points at an existing capability: one step in a shipped scenario.
type StepRef struct {
    Scenario    string // scenario file path or ID
    StepName    string
    Framework   string // art | caldera | custom
    TechniqueID string
}

// PrimitiveCoverage pairs one primitive with the existing scenario steps that
// implement its technique. Steps empty => this primitive is a gap.
type PrimitiveCoverage struct {
    Primitive adprimitive.Primitive
    Steps     []StepRef
}

// Report separates covered primitives from gaps.
type Report struct {
    Covered []PrimitiveCoverage // >= 1 matching step
    Gaps    []PrimitiveCoverage // no TechniqueID, or no matching step
}
```

### The pure mapping

```go
// Map joins each primitive to index by TechniqueID equality. A primitive with
// an empty TechniqueID, or one whose technique has no entry in index, lands in
// Gaps. Output ordering is deterministic (sorted by primitive ID within each
// bucket).
func Map(primitives []adprimitive.Primitive, index map[string][]StepRef) Report
```

### The loader (separable, so Map stays pure)

```go
// IndexScenarios parses every scenario YAML reachable under fsys into a
// TechniqueID -> []StepRef index. A step with an empty TechniqueID is skipped
// (it cannot be joined by technique). Returns an error only on a read/parse
// failure, not on an empty corpus.
func IndexScenarios(fsys fs.FS) (map[string][]StepRef, error)
```

Splitting `IndexScenarios` from `Map` mirrors the M06 fixture/logic split: `Map`
is a pure function tested with injected indexes; `IndexScenarios` is the thin IO
edge, tested once against the real corpus.

## Design decisions

- **Join key is `TechniqueID` equality only.** It is the honest, already-present
  key. The 6 non-technique primitives (ACL-abuse, RBCD) therefore land in `Gaps`
  — which is correct: they have no existing scenario implementation either. A
  hand-maintained name→capability table is deliberately avoided; it would drift
  and would assert coverage the corpus does not actually have.
- **`Gaps` is the deliverable, not a failure.** It is the explicit input to
  sub-project E's per-gap go/no-go. A primitive being a gap is a fact to report,
  not an error.
- **Covered means "a scenario step with this technique exists."** It does not
  claim the step is a perfect semantic match for the primitive — only that
  Audspect already ships executable content for that technique. Finer semantic
  matching, if ever needed, is out of scope for A.

## Testing

Pure `go test`, no DB, no containers.

- `Map` with injected indexes: a covered primitive (technique present in index),
  a technique-but-no-step gap (primitive has a technique, index lacks it), and a
  no-technique gap (primitive `TechniqueID == ""`).
- Deterministic ordering: two primitives with the same bucket come back sorted
  by ID.
- `IndexScenarios` integration test over the real `scenarios/` dir (via
  `os.DirFS`): asserts `T1558.003`/`T1558.004` resolve to ≥1 `StepRef` and that a
  full `Map(adbench.All(), index)` puts the Kerberoasting/AS-REP primitives in
  `Covered` and the DCSync + ADCS primitives in `Gaps`. (`adbench` appears only
  in this test.)

## Error handling

- `Map` is pure; no error path.
- `IndexScenarios` returns an error only on a filesystem read or YAML parse
  failure. An empty corpus yields an empty index and a nil error. A step with no
  `TechniqueID` is skipped silently (it is un-joinable, not malformed).

## Dependencies & boundaries

- `adcoverage` → `adprimitive`, `scenario` (one-way; nothing imports it back).
- `adbench` used only in the integration test.
- No new third-party dependencies (reuse `scenario`'s existing YAML parsing).
- No change to `adprimitive`, `scenario`, or any shipped scenario file.

## Success criteria

- `Map` correctly buckets covered vs. gap primitives for injected indexes,
  deterministically.
- `IndexScenarios` over the real corpus reflects reality: Kerberoasting/AS-REP
  covered, DCSync/ADCS/ACL/RBCD as gaps.
- `go build ./...`, `go vet`, `gofmt -l` clean.
- The `Gaps` list is a usable, honest hand-off to sub-project E.
