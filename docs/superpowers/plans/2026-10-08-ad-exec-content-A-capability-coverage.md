# AD Executable-Content Sub-Project A — Capability Coverage Map — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `orchestrator/internal/adcoverage`: a pure `Map` that joins `adprimitive` primitives to existing in-repo scenario steps by `TechniqueID`, plus a separable `IndexScenarios` loader, producing a covered/gap `Report`. No execution, authors nothing.

**Architecture:** New `adcoverage` package depending one-way on `adprimitive` + `scenario`. `Map(primitives, index)` is pure (tested with injected indexes); `IndexScenarios(fsys)` is the thin IO edge that parses the scenario corpus into a `TechniqueID → []StepRef` index (tested with a fake FS plus one real-corpus integration test).

**Tech Stack:** Go (stdlib `sort`/`io/fs`/`strings`/`fmt` + existing `gopkg.in/yaml.v3`). No DB, no containers.

**Spec:** `docs/superpowers/specs/2026-10-08-ad-exec-content-A-capability-coverage-design.md`

## Global Constraints

- Go stdlib + existing `gopkg.in/yaml.v3` only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- `adcoverage` depends on `adprimitive` and `scenario` only (one-way; nothing imports it back). `adbench` may appear only in a test file.
- No change to `adprimitive`, `scenario`, or any shipped scenario file.
- Join is `TechniqueID` equality only. A primitive with empty `TechniqueID`, or whose technique has no matching step, is a gap — not an error.
- `Map` is pure (no error path). `IndexScenarios` errors only on a read/parse failure; an empty corpus yields an empty index and nil error; a step with no `TechniqueID` is skipped silently.

## Review Focus

- **No-technique primitive** (`TechniqueID == ""`, the 6 ACL/RBCD): must land in `Gaps`, never matched via an empty-string index key. → Task 1, Step 1.
- **Technique-present-but-no-step primitive** (e.g. DCSync `T1003.006`): must land in `Gaps`, distinct from a no-technique gap only in that its primitive carries a technique. → Task 1, Step 1.
- **Deterministic ordering**: two primitives in the same bucket come back sorted by ID, so the report is stable run-to-run. → Task 1, Step 1.
- **Non-`.yaml` and empty-technique steps**: `IndexScenarios` skips `.yaml.sig` and other non-`.yaml` files, and skips steps with no `TechniqueID`. → Task 2, Step 1.
- **Real-corpus reality check**: over the actual `scenarios/` dir, Kerberoasting/AS-REP primitives resolve to `Covered` and DCSync/ADCS to `Gaps`. → Task 2, Step 1.

---

### Task 1: Types and the pure `Map`

**Files:**
- Create: `orchestrator/internal/adcoverage/coverage.go`
- Test: `orchestrator/internal/adcoverage/coverage_test.go`

**Interfaces:**
- Consumes: `adprimitive.Primitive` (reads `.ID`, `.TechniqueID`).
- Produces: `type StepRef`, `type PrimitiveCoverage`, `type Report`, `func Map(primitives []adprimitive.Primitive, index map[string][]StepRef) Report`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adcoverage/coverage_test.go
package adcoverage

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestMap_CoveredGapAndNoTechnique(t *testing.T) {
	index := map[string][]StepRef{
		"T1558.003": {{Scenario: "kerb.yaml", StepName: "SPN enum", Framework: "custom", TechniqueID: "T1558.003"}},
	}
	primitives := []adprimitive.Primitive{
		{ID: "spn-enumerate", TechniqueID: "T1558.003"},   // covered
		{ID: "dcsync", TechniqueID: "T1003.006"},          // technique present on primitive, absent from index -> gap
		{ID: "acl-genericall-takeover", TechniqueID: ""},  // no technique -> gap
	}
	rep := Map(primitives, index)

	if len(rep.Covered) != 1 || rep.Covered[0].Primitive.ID != "spn-enumerate" {
		t.Fatalf("expected spn-enumerate covered, got %+v", rep.Covered)
	}
	if len(rep.Covered[0].Steps) != 1 || rep.Covered[0].Steps[0].Scenario != "kerb.yaml" {
		t.Fatalf("expected the matching step attached, got %+v", rep.Covered[0].Steps)
	}
	gapIDs := map[string]bool{}
	for _, g := range rep.Gaps {
		gapIDs[g.Primitive.ID] = true
		if len(g.Steps) != 0 {
			t.Errorf("gap %s must carry no steps, got %+v", g.Primitive.ID, g.Steps)
		}
	}
	if !gapIDs["dcsync"] || !gapIDs["acl-genericall-takeover"] {
		t.Fatalf("expected dcsync and acl-genericall-takeover in gaps, got %+v", rep.Gaps)
	}
}

func TestMap_DeterministicOrderWithinBuckets(t *testing.T) {
	index := map[string][]StepRef{"T1": {{TechniqueID: "T1"}}}
	// Supplied out of ID order; both covered.
	primitives := []adprimitive.Primitive{
		{ID: "zeta", TechniqueID: "T1"},
		{ID: "alpha", TechniqueID: "T1"},
	}
	rep := Map(primitives, index)
	if len(rep.Covered) != 2 || rep.Covered[0].Primitive.ID != "alpha" || rep.Covered[1].Primitive.ID != "zeta" {
		t.Fatalf("expected covered sorted by ID [alpha zeta], got %+v", rep.Covered)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adcoverage/... -v`
Expected: FAIL — `undefined: StepRef` / `undefined: Map`.

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adcoverage/coverage.go

// Package adcoverage maps AD-M04 primitives to the executable capabilities
// Audspect already ships, by joining each primitive to existing scenario
// steps on MITRE TechniqueID. It authors nothing and executes nothing --
// it reads already-shipped scenario metadata and reports coverage vs. gaps
// (sub-project A of the executable-content decomposition). Depends one-way
// on adprimitive and scenario.
package adcoverage

import (
	"sort"

	"github.com/audspect/bas/internal/adprimitive"
)

// StepRef points at an existing capability: one step in a shipped scenario.
type StepRef struct {
	Scenario    string
	StepName    string
	Framework   string // art | caldera | custom
	TechniqueID string
}

// PrimitiveCoverage pairs one primitive with the existing scenario steps
// that implement its technique. Steps empty => the primitive is a gap.
type PrimitiveCoverage struct {
	Primitive adprimitive.Primitive
	Steps     []StepRef
}

// Report separates covered primitives from gaps.
type Report struct {
	Covered []PrimitiveCoverage
	Gaps    []PrimitiveCoverage
}

// Map joins each primitive to index by TechniqueID equality. A primitive
// with an empty TechniqueID, or one whose technique has no index entry,
// lands in Gaps. Both buckets are sorted by primitive ID.
func Map(primitives []adprimitive.Primitive, index map[string][]StepRef) Report {
	var rep Report
	for _, p := range primitives {
		if steps := index[p.TechniqueID]; p.TechniqueID != "" && len(steps) > 0 {
			rep.Covered = append(rep.Covered, PrimitiveCoverage{Primitive: p, Steps: steps})
		} else {
			rep.Gaps = append(rep.Gaps, PrimitiveCoverage{Primitive: p})
		}
	}
	sort.Slice(rep.Covered, func(i, j int) bool { return rep.Covered[i].Primitive.ID < rep.Covered[j].Primitive.ID })
	sort.Slice(rep.Gaps, func(i, j int) bool { return rep.Gaps[i].Primitive.ID < rep.Gaps[j].Primitive.ID })
	return rep
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adcoverage/... -v`
Expected: PASS — both tests.

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adcoverage/ && go vet ./internal/adcoverage/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adcoverage/coverage.go orchestrator/internal/adcoverage/coverage_test.go
git commit -m "$(cat <<'EOF'
feat(adcoverage): add primitive->capability coverage Map (sub-project A task 1 of 2)

Pure Map joins adprimitive primitives to scenario StepRefs by
TechniqueID equality, bucketing into Covered/Gaps (sorted by ID). A
no-technique primitive or one whose technique has no matching step is a
gap -- the honest hand-off artifact for the later raw-authoring
workstream, not an error. Reads metadata only; authors/executes nothing.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `IndexScenarios` loader + real-corpus integration

**Files:**
- Create: `orchestrator/internal/adcoverage/index.go`
- Test: `orchestrator/internal/adcoverage/index_test.go`

**Interfaces:**
- Consumes: `scenario.Scenario`/`Step` (YAML types), `StepRef` (Task 1), `Map` (Task 1), `adbench.All` (test only).
- Produces: `func IndexScenarios(fsys fs.FS) (map[string][]StepRef, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adcoverage/index_test.go
package adcoverage

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/audspect/bas/internal/adbench"
)

func TestIndexScenarios_GroupsByTechniqueSkipsNonYAMLAndEmptyTechnique(t *testing.T) {
	fsys := fstest.MapFS{
		"a.yaml": {Data: []byte("id: scen-a\nname: A\nsteps:\n" +
			"  - name: step1\n    technique_id: T1001\n    framework: custom\n" +
			"  - name: no-tech\n    technique_id: \"\"\n    framework: custom\n")},
		"b.yaml": {Data: []byte("id: scen-b\nname: B\nsteps:\n" +
			"  - name: step2\n    technique_id: T1001\n    framework: art\n")},
		"a.yaml.sig": {Data: []byte("not a scenario, must be ignored")},
		"notes.txt":  {Data: []byte("ignored")},
	}
	index, err := IndexScenarios(fsys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(index["T1001"]) != 2 {
		t.Fatalf("expected 2 steps for T1001 (from a.yaml + b.yaml), got %+v", index["T1001"])
	}
	if _, ok := index[""]; ok {
		t.Error("empty-technique step must be skipped, not indexed under \"\"")
	}
}

func TestIndexScenarios_EmptyCorpusIsEmptyIndexNilError(t *testing.T) {
	index, err := IndexScenarios(fstest.MapFS{})
	if err != nil {
		t.Fatalf("empty corpus must not error: %v", err)
	}
	if len(index) != 0 {
		t.Fatalf("expected empty index, got %+v", index)
	}
}

// Integration: the REAL scenarios/ corpus must reflect reality.
func TestIndexScenarios_RealCorpusReflectsReality(t *testing.T) {
	// adcoverage is at orchestrator/internal/adcoverage; scenarios/ is at the
	// repo root, three levels up.
	index, err := IndexScenarios(os.DirFS("../../../scenarios"))
	if err != nil {
		t.Fatalf("indexing the real corpus failed: %v", err)
	}
	if len(index["T1558.003"]) == 0 {
		t.Fatal("expected real scenario coverage for T1558.003 (Kerberoasting)")
	}

	rep := Map(adbench.All(), index)
	covered := map[string]bool{}
	for _, c := range rep.Covered {
		covered[c.Primitive.ID] = true
	}
	gaps := map[string]bool{}
	for _, g := range rep.Gaps {
		gaps[g.Primitive.ID] = true
	}
	// Kerberoasting/AS-REP primitives carry T1558.003/004 -> covered.
	for _, id := range []string{"spn-enumerate", "kerberoast-tgs-request", "asrep-roast-discover"} {
		if !covered[id] {
			t.Errorf("expected %s covered by the real corpus", id)
		}
	}
	// DCSync (T1003.006) and ADCS (T1649) have no scenario coverage -> gaps.
	for _, id := range []string{"dcsync", "adcs-esc1", "adcs-esc2", "adcs-esc3", "adcs-esc4"} {
		if !gaps[id] {
			t.Errorf("expected %s in gaps (no scenario coverage)", id)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adcoverage/... -run TestIndexScenarios -v`
Expected: FAIL — `undefined: IndexScenarios`.

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adcoverage/index.go
package adcoverage

import (
	"fmt"
	"io/fs"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

// IndexScenarios parses every *.yaml scenario reachable under fsys into a
// TechniqueID -> []StepRef index. Non-.yaml files (including .yaml.sig) are
// skipped; steps with an empty TechniqueID are skipped (un-joinable). An
// empty corpus yields an empty index and a nil error.
func IndexScenarios(fsys fs.FS) (map[string][]StepRef, error) {
	index := map[string][]StepRef{}
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		var sc scenario.Scenario
		if err := yaml.Unmarshal(raw, &sc); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		scID := sc.ID
		if scID == "" {
			scID = path
		}
		for _, st := range sc.Steps {
			if st.TechniqueID == "" {
				continue
			}
			index[st.TechniqueID] = append(index[st.TechniqueID], StepRef{
				Scenario:    scID,
				StepName:    st.Name,
				Framework:   st.Framework,
				TechniqueID: st.TechniqueID,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return index, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adcoverage/... -v`
Expected: PASS — the whole package (Task 1's plus the three loader tests). If the real-corpus test fails on the `../../../scenarios` path, confirm the path depth from the package dir with `ls ../../../scenarios` and adjust (ledger the ruling); if it fails on a specific file's YAML, read that file and decide whether to skip unparseable files or fix the loader.

- [ ] **Step 5: Run gofmt, go vet, and the full build; confirm no existing package was touched**

Run: `cd orchestrator && gofmt -l internal/adcoverage/ && go vet ./internal/adcoverage/... && go build ./... && git status --short internal/adprimitive internal/scenario`
Expected: gofmt/vet print nothing, build succeeds, `git status` on the two consumed packages prints nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adcoverage/index.go orchestrator/internal/adcoverage/index_test.go
git commit -m "$(cat <<'EOF'
feat(adcoverage): add IndexScenarios loader + real-corpus check (sub-project A task 2 of 2)

IndexScenarios parses the in-repo scenario YAMLs (via fs.FS) into a
TechniqueID -> []StepRef index, skipping non-.yaml files and
empty-technique steps. The integration test over the real scenarios/
corpus confirms reality: Kerberoasting/AS-REP primitives come back
Covered, DCSync and ADCS come back Gaps. Closes sub-project A -- the
coverage/gap artifact that feeds the later per-gap authoring decisions.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing "Inline Over Subagents" preference — already decided, not asking the user to choose.** 2 sequential tasks; Task 2 consumes Task 1's `StepRef`/`Map`. Proceeding via `superpowers:executing-plans`.
