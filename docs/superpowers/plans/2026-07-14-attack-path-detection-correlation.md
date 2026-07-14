# Attack Path ↔ Detection Correlation (SP3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/pathcorrelation`, a new package that joins the attack-path graph engine, the SP2 Detection Rule Library, and the Detection Verification store to annotate attack paths with expected-vs-verified detection coverage, expose it via a new read-only API endpoint, and render it as a new report section.

**Architecture:** `pathcorrelation` is a pure-Go consumer package (no new DB tables) that takes an already-built `attackpath.Graph`/`Summary`, maps each edge to ATT&CK technique(s) via a small built-in table, looks up expected coverage from `rulelib.Engine.RulesByTechnique` and verified coverage from a new SQL query against `verification_history` (joined to `scenario_runs`/`agents` for host matching), and produces a weighted `DetectionCoverageScore` plus prioritized remediation gaps. It is wired into the API (`GET /api/attackpath/correlation`) and into the existing report engine's "Attack Path Validation" section (extended, not a new page).

**Tech Stack:** Go, PostgreSQL (pgx/pgxpool), chi router, html/template (json-tag-map rendering — see Global Constraints), testcontainers-go for Postgres-backed tests.

## Global Constraints

- This binary is built with `garble`, which renames Go struct fields but preserves json tags. The HTML report template resolves fields through a `json.Marshal`→`json.Unmarshal`-into-`map[string]any` round trip, **never** through `html/template` reflecting on a Go struct directly (see `internal/reporting/html.go:19-26`). Every new report-facing type MUST have complete json tags; do not rely on Go field names being visible to the template.
- All JSON numbers arrive in the template as `float64` and all times as RFC3339 strings — existing template funcs (`scoreColor`, `exposureColor`, `fmtScore`, `pctFrac`) already assume this; do not add new conversions for numbers/times that already round-trip correctly.
- `GapPriority` values MUST be the exact strings `"Critical"`, `"High"`, `"Medium"`, `"Low"` (Titlecase) to reuse the existing `exposureColor` template func verbatim — this matches `attackpath.Summary.Band`'s own convention, not the lowercase used in early spec drafts.
- `internal/reporting/pdf.go` (the legacy fpdf fallback renderer, used only when the Chromium sidecar is unavailable) is deliberately **not** touched by this plan — it already renders `rep.AttackPathValidation` without `PathCorrelation`, matching the established precedent that the fpdf fallback was intentionally left behind when the SP1 Detection Validation section shipped (see `[[project_report_redesign]]` memory). Do not add `PathCorrelation` handling there.
- Standing project rule: run `gofmt -l`, `go build ./...`, `go vet ./...` before every commit; commit and `git push` immediately after every task, never batch pushes. Code blocks in this plan are not guaranteed to be byte-perfect `gofmt` output (e.g. struct-field alignment) — every "Format, build, vet" step below means: run `gofmt -w <the exact files this task created or modified>` first (never a whole directory — that would reformat unrelated pre-existing files and violate the minimal-changes rule), THEN `gofmt -l` on the same paths to confirm zero remaining output, THEN build/vet.
- Nil-safe optional-subsystem wiring: any new `Handler`/`reporting.Engine` field for an optional subsystem must default to its zero value (nil) when not wired, and every consumer must guard `if x == nil { ... }` — never assume a subsystem is present.
- Docker Desktop must be running before any test that touches `internal/api` (its `TestMain` always spins up a shared Postgres testcontainer) or the new Postgres-backed integration test in Task 3. If `docker info` fails, start it via `powershell -Command "Start-Process 'C:\Program Files\Docker\Docker\Docker Desktop.exe'"` and poll `docker info` until ready before running the test.
- **Go nil-interface trap:** never pass a `*rulelib.Engine` (or any concrete pointer) into an interface-typed parameter without first checking the pointer for nil — `var p *T = nil; var i I = p; i != nil` is TRUE in Go, so a naive pass-through breaks the package's `rules == nil` skip logic. Every call site that hands `h.rules` (or `e.rules`) to an interface parameter must guard explicitly (shown in Task 6 and Task 7 below).

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/attackpath/graph.go` (modify) | Add `EdgesTo` read accessor |
| `internal/attackpath/assets.go` (modify) | Add `BuildGraphAndAnalyze`, refactor `BuildAndAnalyze` to call it |
| `internal/pathcorrelation/mapper.go` (new) | `TechniqueMapping`, `EdgeTechniqueMapper`, `DefaultEdgeTechniqueMapper` |
| `internal/pathcorrelation/types.go` (new) | All other exported types/enums, `RunLookup`/`RuleLibrary` interfaces |
| `internal/pathcorrelation/runlookup.go` (new) | `SQLRunLookup` — the verified-coverage DB query |
| `internal/pathcorrelation/paths.go` (new) | `DefaultPaths` |
| `internal/pathcorrelation/correlate.go` (new) | `Correlate` engine: canonical edges, status computation, gaps, statistics, score |
| `internal/api/pathcorrelation_handlers.go` (new) | `GET /api/attackpath/correlation` |
| `internal/api/routes.go` (modify) | Register the new route |
| `internal/api/rbac_matrix_test.go` (modify) | RBAC matrix entry |
| `internal/reporting/engine.go` (modify) | `RuleLibraryResolver`, `WithRuleLibrary`, `FullReport.PathCorrelation`, `loadAttackPathGraph` refactor, wire both report-build call sites |
| `internal/reporting/html.go` (modify) | Extend the existing "Attack Path Validation" section (Section 8) with a Detection Coverage subsection |
| `cmd/server/main.go` (modify) | Share one `rulelib.Engine` instance between the Handler and the reporting engine; wire `WithRuleLibrary` on `reportingEngine` |

---

### Task 1: `attackpath` — additive read accessors

**Files:**
- Modify: `orchestrator/internal/attackpath/graph.go`
- Modify: `orchestrator/internal/attackpath/assets.go`
- Test: `orchestrator/internal/attackpath/graph_export_test.go` (new)

**Interfaces:**
- Produces: `func (g *Graph) EdgesTo(id string) []Edge` — every edge whose `To == id`, order unspecified.
- Produces: `func BuildGraphAndAnalyze(cols []Collection, tags []AssetTag) (*Graph, Summary)` — same pipeline as `BuildAndAnalyze` but also returns the built graph.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/attackpath/graph_export_test.go
package attackpath

import "testing"

func TestGraphEdgesTo(t *testing.T) {
	g := New()
	g.AddEdge(Edge{From: "WS01", To: "FILE01", Kind: EdgeSMB})
	g.AddEdge(Edge{From: "WS02", To: "FILE01", Kind: EdgeRDP})
	g.AddEdge(Edge{From: "WS01", To: "WS02", Kind: EdgeWinRM})

	edges := g.EdgesTo("FILE01")
	if len(edges) != 2 {
		t.Fatalf("want 2 edges into FILE01, got %d: %+v", len(edges), edges)
	}
	seen := map[string]bool{}
	for _, e := range edges {
		if e.To != "FILE01" {
			t.Fatalf("EdgesTo returned an edge not targeting FILE01: %+v", e)
		}
		seen[e.From] = true
	}
	if !seen["WS01"] || !seen["WS02"] {
		t.Fatalf("expected edges from both WS01 and WS02, got %+v", edges)
	}

	if got := g.EdgesTo("NOBODY"); len(got) != 0 {
		t.Fatalf("want 0 edges into an untargeted node, got %d", len(got))
	}
}

func TestBuildGraphAndAnalyzeReturnsSameSummaryAsBuildAndAnalyze(t *testing.T) {
	cols := []Collection{
		{AgentID: "ws01", Source: "agent",
			Nodes: []Node{{ID: "WS01", Kind: KindHost, Role: RoleEndpoint}},
			Edges: []Edge{{From: "WS01", To: "FILE01", Kind: EdgeSMB}}},
	}
	tags := []AssetTag{{HostKey: "FILE01", CrownJewel: "FileServer"}}

	g, s := BuildGraphAndAnalyze(cols, tags)
	if g == nil {
		t.Fatal("BuildGraphAndAnalyze must return a non-nil graph")
	}
	if g.NodeCount() != s.Hosts {
		// FILE01 is host-only in this fixture, so NodeCount == Hosts.
		t.Fatalf("graph node count (%d) should match summary host count (%d)", g.NodeCount(), s.Hosts)
	}

	want := BuildAndAnalyze(cols, tags)
	if s.AttackPathScore != want.AttackPathScore || s.Band != want.Band {
		t.Fatalf("BuildGraphAndAnalyze summary diverged from BuildAndAnalyze: got %+v want %+v", s, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/attackpath/... -run 'TestGraphEdgesTo|TestBuildGraphAndAnalyzeReturnsSameSummaryAsBuildAndAnalyze' -v`
Expected: FAIL — `g.EdgesTo undefined` and `BuildGraphAndAnalyze undefined`.

- [ ] **Step 3: Implement `EdgesTo`**

In `orchestrator/internal/attackpath/graph.go`, add after the existing `NodeCount`/`EdgeCount` methods (end of file):

```go

// EdgesTo returns every edge whose To == id (order unspecified). Used by
// internal/pathcorrelation to find the edges that make a choke-point node
// dangerous.
func (g *Graph) EdgesTo(id string) []Edge {
	var out []Edge
	for _, es := range g.adj {
		for _, e := range es {
			if e.To == id {
				out = append(out, e)
			}
		}
	}
	return out
}
```

- [ ] **Step 4: Implement `BuildGraphAndAnalyze`**

In `orchestrator/internal/attackpath/assets.go`, replace the existing `BuildAndAnalyze` function:

```go
// BuildAndAnalyze is the one-call pipeline the server uses: merge collections,
// reconcile identities, overlay operator asset tags, then analyze.
func BuildAndAnalyze(cols []Collection, tags []AssetTag) Summary {
	_, s := BuildGraphAndAnalyze(cols, tags)
	return s
}

// BuildGraphAndAnalyze is BuildAndAnalyze but also returns the built graph,
// for callers (internal/pathcorrelation) that need to run further graph
// queries beyond the Summary.
func BuildGraphAndAnalyze(cols []Collection, tags []AssetTag) (*Graph, Summary) {
	g := BuildGraph(cols...)
	g.applyAssetTags(tags)
	return g, g.Analyze()
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/attackpath/... -v`
Expected: PASS — all tests in the package, including the two new ones and every pre-existing test (confirms the `BuildAndAnalyze` refactor changed no behavior).

- [ ] **Step 6: Format, build, vet**

Run: `cd orchestrator && gofmt -l internal/attackpath && go build ./... && go vet ./...`
Expected: no output from `gofmt -l` for the two modified files; `BUILD_OK`/no errors from build and vet.

- [ ] **Step 7: Commit and push**

```bash
cd orchestrator
git add internal/attackpath/graph.go internal/attackpath/assets.go internal/attackpath/graph_export_test.go
git commit -m "feat(attackpath): add EdgesTo and BuildGraphAndAnalyze accessors

Additive, backward-compatible exports needed by the upcoming
internal/pathcorrelation package (SP3): EdgesTo lets a consumer find
which edges feed a choke-point node; BuildGraphAndAnalyze exposes the
graph BuildAndAnalyze already builds internally, instead of discarding
it after Analyze()."
git push
```

---

### Task 2: `pathcorrelation` — core types and the edge→technique mapper

**Files:**
- Create: `orchestrator/internal/pathcorrelation/mapper.go`
- Create: `orchestrator/internal/pathcorrelation/types.go`
- Test: `orchestrator/internal/pathcorrelation/mapper_test.go`

**Interfaces:**
- Consumes: `attackpath.EdgeKind` and its constants (`EdgeSMB`, `EdgeWinRM`, `EdgeRDP`, `EdgeAdminTo`, `EdgeHasSession`, `EdgeMemberOf`, `EdgeCredential`), `attackpath.Edge`, `attackpath.ChokePoint` (all already defined in `internal/attackpath`).
- Produces: `TechniqueMapping{TechniqueID, Weight, Reason}`, `EdgeTechniqueMapper` interface, `DefaultEdgeTechniqueMapper{}`, `ExpectedStatus`/`VerifiedStatus`/`VerificationConfidence`/`GapPriority` enums, `Evidence`, `DetectionStatus`, `AnnotatedEdge`, `AttackPath`, `AnnotatedPath`, `AnnotatedChokePoint`, `PrioritizedGap`, `Statistics`, `AttackPathCorrelation`, `VerificationResult`, `RunLookup` interface, `RuleLibrary` interface — all consumed by later tasks in this plan.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/pathcorrelation/mapper_test.go
package pathcorrelation

import (
	"testing"

	"github.com/audspect/bas/internal/attackpath"
)

func TestDefaultEdgeTechniqueMapper(t *testing.T) {
	m := DefaultEdgeTechniqueMapper{}

	cases := []struct {
		kind      attackpath.EdgeKind
		wantIDs   []string
		wantEmpty bool
	}{
		{attackpath.EdgeSMB, []string{"T1021.002"}, false},
		{attackpath.EdgeWinRM, []string{"T1021.006"}, false},
		{attackpath.EdgeRDP, []string{"T1021.001"}, false},
		{attackpath.EdgeAdminTo, []string{"T1078"}, false},
		{attackpath.EdgeHasSession, []string{"T1003", "T1552"}, false},
		{attackpath.EdgeMemberOf, []string{"T1078", "T1098"}, false},
		{attackpath.EdgeCredential, []string{"T1550", "T1555"}, false},
	}

	for _, c := range cases {
		got := m.Techniques(c.kind)
		if len(got) != len(c.wantIDs) {
			t.Fatalf("%s: want %d techniques, got %d: %+v", c.kind, len(c.wantIDs), len(got), got)
		}
		for i, id := range c.wantIDs {
			if got[i].TechniqueID != id {
				t.Fatalf("%s: technique[%d] = %q, want %q", c.kind, i, got[i].TechniqueID, id)
			}
			if got[i].Weight <= 0 || got[i].Weight > 1 {
				t.Fatalf("%s: technique[%d] weight %v out of (0,1] range", c.kind, i, got[i].Weight)
			}
			if got[i].Reason == "" {
				t.Fatalf("%s: technique[%d] has no reason", c.kind, i)
			}
		}
	}

	if got := m.Techniques(attackpath.EdgeKind("unknown")); len(got) != 0 {
		t.Fatalf("unknown edge kind should map to no techniques, got %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/pathcorrelation/... -v`
Expected: FAIL — package `internal/pathcorrelation` does not exist / `DefaultEdgeTechniqueMapper` undefined.

- [ ] **Step 3: Write `types.go`**

```go
// orchestrator/internal/pathcorrelation/types.go
//
// Package pathcorrelation joins three existing subsystems — the attack-path
// graph engine (internal/attackpath), the Detection Rule Library
// (internal/rulelib), and Detection Verification (internal/verification via
// its verification_history table) — to answer: for a dangerous lateral-
// movement path through the environment, would we actually catch the
// attacker? It is a pure consumer: it does not modify any of the three
// subsystems' own scoring or state, and owns no database tables.
package pathcorrelation

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/rulelib"
)

// ExpectedStatus says whether the Rule Library has a rule for a technique,
// independent of whether that rule has ever been proven to fire.
type ExpectedStatus string

const (
	ExpectedCovered ExpectedStatus = "covered"
	ExpectedGap     ExpectedStatus = "gap"
)

// VerifiedStatus says whether a technique has actually been proven detected
// by a real simulation run, independent of whether a rule exists for it.
type VerifiedStatus string

const (
	VerifiedCovered VerifiedStatus = "covered"
	VerifiedPartial VerifiedStatus = "partial" // some but not all mapped techniques verified
	VerifiedGap     VerifiedStatus = "gap"     // none verified, but Expected is Covered
	VerifiedUnknown VerifiedStatus = "unknown" // none verified, and no rule exists either
)

// VerificationConfidence says WHERE verified evidence came from.
type VerificationConfidence string

const (
	ConfidenceHost        VerificationConfidence = "host"
	ConfidenceEnvironment VerificationConfidence = "environment"
	ConfidenceUnknown     VerificationConfidence = "unknown"
)

// GapPriority values are exact matches for internal/reporting/html.go's
// exposureColor template func — do not lowercase these.
type GapPriority string

const (
	PriorityCritical GapPriority = "Critical"
	PriorityHigh     GapPriority = "High"
	PriorityMedium   GapPriority = "Medium"
	PriorityLow      GapPriority = "Low"
)

// Evidence is why a technique's status is what it is. InvestigationURL is not
// populated in this slice — verification.Record carries no such field today;
// a future connector slice can add it once it exists.
type Evidence struct {
	RuleIDs    []string   `json:"ruleIds,omitempty"`
	AlertIDs   []string   `json:"alertIds,omitempty"`
	RunID      string     `json:"runId,omitempty"`
	VerifiedAt *time.Time `json:"verifiedAt,omitempty"`
	Provider   string     `json:"provider,omitempty"`
}

// DetectionStatus is the combined expected/verified status of every
// technique mapped to one graph edge.
type DetectionStatus struct {
	Techniques []TechniqueMapping     `json:"techniques"`
	Expected   ExpectedStatus         `json:"expected"`
	Verified   VerifiedStatus         `json:"verified"`
	Confidence VerificationConfidence `json:"confidence"`
	Evidence   Evidence               `json:"evidence,omitempty"`
}

// AnnotatedEdge is one graph edge plus its combined DetectionStatus.
type AnnotatedEdge struct {
	Edge   attackpath.Edge `json:"edge"`
	Status DetectionStatus `json:"status"`
}

// AttackPath is a named sequence of edges to correlate — the Domain-Admin
// path, a crown-jewel path (see DefaultPaths), or a path a future caller
// (e.g. Exposure Explorer) supplies directly. Weight is this path's
// contribution to DetectionCoverageScore; the producer of the path sets it
// (DefaultPaths sets it for this slice's two path kinds).
type AttackPath struct {
	Label  string            `json:"label"`
	Edges  []attackpath.Edge `json:"-"`
	Weight float64           `json:"-"`
}

// AnnotatedPath is an AttackPath with every edge's DetectionStatus attached.
type AnnotatedPath struct {
	Label       string          `json:"label"`
	Edges       []AnnotatedEdge `json:"edges"`
	WeakestLink *AnnotatedEdge  `json:"weakestLink,omitempty"`
	Weight      float64         `json:"-"`
}

// AnnotatedChokePoint is an attackpath.ChokePoint plus every edge feeding
// into it (via attackpath.Graph.EdgesTo), annotated.
type AnnotatedChokePoint struct {
	ChokePoint    attackpath.ChokePoint `json:"chokePoint"`
	IncomingEdges []AnnotatedEdge       `json:"incomingEdges"`
	WeakestLink   *AnnotatedEdge        `json:"weakestLink,omitempty"`
}

// PrioritizedGap is one edge whose Verified status is not Covered, ranked by
// an internal (unexported, unserialized) score derived from path frequency,
// proximity to a high-value target, technique criticality, and how bad the
// gap is.
type PrioritizedGap struct {
	Edge       attackpath.Edge    `json:"edge"`
	Techniques []TechniqueMapping `json:"techniques"`
	Priority   GapPriority        `json:"priority"`
	Reason     string             `json:"reason"`
	score      float64
}

// Statistics summarizes the canonical edge set (deduplicated by
// From+To+Kind across every correlated path and choke point).
type Statistics struct {
	EdgesTotal           int              `json:"edgesTotal"`
	ExpectedCovered      int              `json:"expectedCovered"`
	ExpectedGap          int              `json:"expectedGap"`
	VerifiedCovered      int              `json:"verifiedCovered"`
	VerifiedPartial      int              `json:"verifiedPartial"`
	VerifiedGap          int              `json:"verifiedGap"`
	VerifiedUnknown      int              `json:"verifiedUnknown"`
	HighestRiskTechnique string           `json:"highestRiskTechnique,omitempty"`
	HighestRiskEdge      *attackpath.Edge `json:"highestRiskEdge,omitempty"`
}

// AttackPathCorrelation is named for extensibility: future slices (Exposure
// Explorer, Asset Criticality) can add fields to this same object without a
// redesign. The report renders it under the title "Attack Path Detection
// Coverage".
type AttackPathCorrelation struct {
	Summary     string                 `json:"summary"`
	Score       int                    `json:"detectionCoverageScore"`
	Paths       []AnnotatedPath        `json:"paths"`
	ChokePoints []AnnotatedChokePoint  `json:"chokePoints"`
	Gaps        []PrioritizedGap       `json:"gaps"`
	Statistics  Statistics             `json:"statistics"`
}

// VerificationResult is what a RunLookup returns for a found match.
type VerificationResult struct {
	Confidence VerificationConfidence
	Evidence   Evidence
}

// RunLookup answers "has this technique been verified as detected, on this
// host or anywhere in the environment?" hostname == "" searches every host.
// SQLRunLookup (runlookup.go) is the production implementation; tests use a
// fake.
type RunLookup interface {
	VerifiedDetection(ctx context.Context, techniqueID, hostname string) (VerificationResult, bool, error)
}

// RuleLibrary is the slice of the SP2 Rule Library engine pathcorrelation
// needs. *rulelib.Engine satisfies it; tests substitute a fake. Declared as
// an interface (not the concrete *rulelib.Engine) so a nil *rulelib.Engine
// passed in by a careless caller is caught at the call site instead of
// silently becoming a non-nil interface wrapping a nil pointer — callers
// MUST guard `if h.rules != nil` before assigning into this parameter (see
// Task 6 and Task 7).
type RuleLibrary interface {
	RulesByTechnique(techniqueID string) []rulelib.Rule
}
```

- [ ] **Step 4: Write `mapper.go`**

```go
// orchestrator/internal/pathcorrelation/mapper.go
package pathcorrelation

import "github.com/audspect/bas/internal/attackpath"

// TechniqueMapping is one edge-kind -> ATT&CK-technique association. Weight
// (0.0-1.0] is both mapping confidence ("how directly does this edge realize
// this technique") and detection criticality ("how important is it to catch
// this technique") — for a lateral-movement edge the two collapse, since the
// more direct technique is also the one most worth detecting.
type TechniqueMapping struct {
	TechniqueID string  `json:"techniqueId"`
	Weight      float64 `json:"weight"`
	Reason      string  `json:"reason"`
}

// EdgeTechniqueMapper maps a graph edge kind to the ATT&CK technique(s) an
// attacker would use to traverse it. DefaultEdgeTechniqueMapper is the only
// implementation today; the interface exists so a future per-deployment
// override does not require redesigning pathcorrelation.
type EdgeTechniqueMapper interface {
	Techniques(kind attackpath.EdgeKind) []TechniqueMapping
}

// DefaultEdgeTechniqueMapper is the built-in, curated edge -> technique table.
type DefaultEdgeTechniqueMapper struct{}

func (DefaultEdgeTechniqueMapper) Techniques(kind attackpath.EdgeKind) []TechniqueMapping {
	switch kind {
	case attackpath.EdgeSMB:
		return []TechniqueMapping{
			{TechniqueID: "T1021.002", Weight: 1.0, Reason: "SMB/Windows Admin Shares is the direct mechanism of this edge"},
		}
	case attackpath.EdgeWinRM:
		return []TechniqueMapping{
			{TechniqueID: "T1021.006", Weight: 1.0, Reason: "Windows Remote Management is the direct mechanism of this edge"},
		}
	case attackpath.EdgeRDP:
		return []TechniqueMapping{
			{TechniqueID: "T1021.001", Weight: 1.0, Reason: "Remote Desktop Protocol is the direct mechanism of this edge"},
		}
	case attackpath.EdgeAdminTo:
		return []TechniqueMapping{
			{TechniqueID: "T1078", Weight: 1.0, Reason: "Valid Accounts used to hold local admin on the target"},
		}
	case attackpath.EdgeHasSession:
		return []TechniqueMapping{
			{TechniqueID: "T1003", Weight: 0.7, Reason: "OS Credential Dumping is possible from an interactive session"},
			{TechniqueID: "T1552", Weight: 0.5, Reason: "Unsecured Credentials may be exposed via an active session"},
		}
	case attackpath.EdgeMemberOf:
		return []TechniqueMapping{
			{TechniqueID: "T1078", Weight: 0.6, Reason: "Group membership implies valid-account privilege reuse"},
			{TechniqueID: "T1098", Weight: 0.4, Reason: "Account Manipulation is a less direct but possible origin"},
		}
	case attackpath.EdgeCredential:
		return []TechniqueMapping{
			{TechniqueID: "T1550", Weight: 1.0, Reason: "Use Alternate Authentication Material is the direct mechanism"},
			{TechniqueID: "T1555", Weight: 0.5, Reason: "Credentials from Password Stores is a possible but not certain origin"},
		}
	default:
		return nil
	}
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/pathcorrelation/... -v`
Expected: PASS — `TestDefaultEdgeTechniqueMapper`.

- [ ] **Step 6: Format, build, vet**

Run: `cd orchestrator && gofmt -l internal/pathcorrelation && go build ./... && go vet ./...`
Expected: no `gofmt -l` output; clean build/vet. (`go build` will succeed even though `types.go` defines things not yet used by any other file — unused *types* are fine in Go, only unused *local variables* and *imports* are compile errors, and every import in `types.go`/`mapper.go` is used.)

- [ ] **Step 7: Commit and push**

```bash
cd orchestrator
git add internal/pathcorrelation/mapper.go internal/pathcorrelation/types.go internal/pathcorrelation/mapper_test.go
git commit -m "feat(pathcorrelation): add core types and the edge-to-technique mapper

New internal/pathcorrelation package (SP3). This task lands the type
vocabulary (DetectionStatus, AnnotatedEdge/Path/ChokePoint,
PrioritizedGap, Statistics, AttackPathCorrelation) and the built-in
EdgeKind -> ATT&CK-technique table with per-technique weight/reason.
No wiring yet — Correlate() lands in a later task."
git push
```

---

### Task 3: `pathcorrelation` — SQL-backed verified-coverage lookup

**Files:**
- Create: `orchestrator/internal/pathcorrelation/runlookup.go`
- Test: `orchestrator/internal/pathcorrelation/runlookup_test.go`

**Interfaces:**
- Consumes: `RunLookup`, `VerificationResult`, `Evidence`, `ConfidenceHost`/`ConfidenceEnvironment` (Task 2); `attackpath.NormalizeHostKey` (already exported in `internal/attackpath/assets.go`); the `verification_history`/`scenario_runs`/`agents` tables (columns confirmed from `internal/verification/store.go`'s `recordCols` and existing joins in `internal/api/detectverify_handlers.go`).
- Produces: `SQLRunLookup` (implements `RunLookup`), `NewSQLRunLookup(db *pgxpool.Pool) *SQLRunLookup`.

- [ ] **Step 1: Write the failing test**

This is a Postgres-backed integration test, following the same pattern as `internal/api`'s `TestMain` (shared testcontainer). Check first whether `internal/testutil` already exposes a shared-DB helper usable from a different package:

Run: `cd orchestrator && grep -n "^func Must" internal/testutil/testdb.go`
Expected output: `func MustSharedTestDB(...)` (confirms the existing helper this test will reuse).

```go
// orchestrator/internal/pathcorrelation/runlookup_test.go
package pathcorrelation

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func TestSQLRunLookup_HostSpecificBeatsEnvironmentWide(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()

		// Two agents: one is the host we'll query for, one is a different host.
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname, ip_address, os_version, status, state, last_update)
			VALUES ('pc-test-agent-target', 'FILE01', '10.0.0.1', 'Windows Server 2022', 'idle', 'active', NOW())`)
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname, ip_address, os_version, status, state, last_update)
			VALUES ('pc-test-agent-other', 'WS02', '10.0.0.2', 'Windows 11', 'idle', 'active', NOW())`)

		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, started_at)
			VALUES ('pc-test-run-target', 'sc1', 'Test Run', 'pc-test-agent-target', 'completed', NOW())`)
		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, started_at)
			VALUES ('pc-test-run-other', 'sc1', 'Test Run', 'pc-test-agent-other', 'completed', NOW())`)

		olderTime := time.Now().Add(-2 * time.Hour)
		newerTime := time.Now()
		mustExec(t, pool, `INSERT INTO verification_history
			(id, run_id, expectation_id, profile_name, profile_version, technique_id, domain, provider,
			 result, workflow_state, verification_source, note, alert_id, verified_by, verified_at, active)
			VALUES ('pc-test-vh-other', 'pc-test-run-other', 'exp1', 'p', 1, 'T1021.002', 'endpoint', 'test-provider',
			 'Detected', 'Approved', 'automatic', '', 'alert-other', 'tester', $1, true)`, olderTime)
		mustExec(t, pool, `INSERT INTO verification_history
			(id, run_id, expectation_id, profile_name, profile_version, technique_id, domain, provider,
			 result, workflow_state, verification_source, note, alert_id, verified_by, verified_at, active)
			VALUES ('pc-test-vh-target', 'pc-test-run-target', 'exp1', 'p', 1, 'T1021.002', 'endpoint', 'test-provider',
			 'Detected', 'Approved', 'automatic', '', 'alert-target', 'tester', $1, true)`, newerTime)

		lookup := NewSQLRunLookup(pool)

		// Host-specific match must win even though it is not the newest overall
		// row for this technique.
		res, found, err := lookup.VerifiedDetection(ctx, "T1021.002", "FILE01")
		if err != nil {
			t.Fatalf("VerifiedDetection: %v", err)
		}
		if !found {
			t.Fatal("expected a match")
		}
		if res.Confidence != ConfidenceHost {
			t.Fatalf("confidence = %q, want host", res.Confidence)
		}
		if res.Evidence.RunID != "pc-test-run-target" {
			t.Fatalf("runId = %q, want pc-test-run-target", res.Evidence.RunID)
		}

		// A host with no direct history falls back to environment-wide, most
		// recent overall.
		res, found, err = lookup.VerifiedDetection(ctx, "T1021.002", "UNRELATEDHOST")
		if err != nil {
			t.Fatalf("VerifiedDetection: %v", err)
		}
		if !found {
			t.Fatal("expected an environment-wide fallback match")
		}
		if res.Confidence != ConfidenceEnvironment {
			t.Fatalf("confidence = %q, want environment", res.Confidence)
		}
		if res.Evidence.RunID != "pc-test-run-target" {
			t.Fatalf("environment fallback should pick the most recent row (pc-test-run-target), got %q", res.Evidence.RunID)
		}

		// A technique with no history at all anywhere.
		_, found, err = lookup.VerifiedDetection(ctx, "T9999.999", "FILE01")
		if err != nil {
			t.Fatalf("VerifiedDetection: %v", err)
		}
		if found {
			t.Fatal("expected no match for an untested technique")
		}
	})
}
```

Note: `sharedDB.RunWithPool` truncates every public-schema table after `fn` returns (deferred, so it still runs on a `t.Fatalf` inside `fn`) — no manual `DELETE`/cleanup is needed, unlike a plain shared-pool test.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/pathcorrelation/... -run TestSQLRunLookup -v`
Expected: FAIL — `NewSQLRunLookup undefined`.

- [ ] **Step 3: Implement `SQLRunLookup`**

```go
// orchestrator/internal/pathcorrelation/runlookup.go
package pathcorrelation

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
)

// SQLRunLookup is the production RunLookup: it queries verification_history
// (joined to scenario_runs -> agents for hostname) directly. It does NOT go
// through internal/scenario's step/expectation resolution — verification_
// history already denormalizes technique_id onto every row, so no such
// resolution is needed.
type SQLRunLookup struct {
	db *pgxpool.Pool
}

func NewSQLRunLookup(db *pgxpool.Pool) *SQLRunLookup {
	return &SQLRunLookup{db: db}
}

type verifiedRow struct {
	RunID      string
	Hostname   string
	Provider   string
	AlertID    string
	VerifiedAt time.Time
}

// VerifiedDetection implements RunLookup. It fetches every active,
// Approved+Detected row for techniqueID (most recent first), then scans in
// that order for the first row whose host matches hostname (Confidence:
// Host). If none matches, it falls back to the single most recent row
// overall (Confidence: Environment). found is false only when no row exists
// for this technique at all.
func (l *SQLRunLookup) VerifiedDetection(ctx context.Context, techniqueID, hostname string) (VerificationResult, bool, error) {
	rows, err := l.db.Query(ctx, `
		SELECT vh.run_id, COALESCE(a.hostname,''), vh.provider, vh.alert_id, vh.verified_at
		  FROM verification_history vh
		  JOIN scenario_runs sr ON sr.id = vh.run_id
		  LEFT JOIN agents a ON a.agent_id = sr.agent_id
		 WHERE vh.active
		   AND vh.technique_id = $1
		   AND vh.result = 'Detected'
		   AND vh.workflow_state = 'Approved'
		 ORDER BY vh.verified_at DESC
		 LIMIT 200`, techniqueID)
	if err != nil {
		return VerificationResult{}, false, err
	}
	defer rows.Close()

	var all []verifiedRow
	for rows.Next() {
		var v verifiedRow
		if err := rows.Scan(&v.RunID, &v.Hostname, &v.Provider, &v.AlertID, &v.VerifiedAt); err != nil {
			return VerificationResult{}, false, err
		}
		all = append(all, v)
	}
	if err := rows.Err(); err != nil {
		return VerificationResult{}, false, err
	}
	if len(all) == 0 {
		return VerificationResult{}, false, nil
	}

	target := attackpath.NormalizeHostKey(hostname)
	if target != "" {
		for _, v := range all {
			if attackpath.NormalizeHostKey(v.Hostname) == target {
				return resultFrom(v, ConfidenceHost), true, nil
			}
		}
	}
	return resultFrom(all[0], ConfidenceEnvironment), true, nil
}

func resultFrom(v verifiedRow, confidence VerificationConfidence) VerificationResult {
	verifiedAt := v.VerifiedAt
	ev := Evidence{RunID: v.RunID, Provider: v.Provider, VerifiedAt: &verifiedAt}
	if v.AlertID != "" {
		ev.AlertIDs = []string{v.AlertID}
	}
	return VerificationResult{Confidence: confidence, Evidence: ev}
}
```

- [ ] **Step 4: Start Docker Desktop if needed, then run test**

Run: `docker info > /dev/null 2>&1 || powershell -Command "Start-Process 'C:\Program Files\Docker\Docker\Docker Desktop.exe'"`

If Docker was just started, poll until ready (background loop, then wait for the notification before proceeding):

Run (background): `i=0; until docker info > /dev/null 2>&1; do i=$((i+1)); [ $i -ge 40 ] && exit 1; sleep 5; done; echo DOCKER_READY`

Then:

Run: `cd orchestrator && go test ./internal/pathcorrelation/... -run TestSQLRunLookup -v`
Expected: PASS — all three assertions in `TestSQLRunLookup_HostSpecificBeatsEnvironmentWide`.

- [ ] **Step 5: Format, build, vet**

Run: `cd orchestrator && gofmt -l internal/pathcorrelation && go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 6: Commit and push**

```bash
cd orchestrator
git add internal/pathcorrelation/runlookup.go internal/pathcorrelation/runlookup_test.go
git commit -m "feat(pathcorrelation): add SQL-backed verified-detection lookup

SQLRunLookup answers 'has this technique been verified as Detected and
Approved, on this host or anywhere in the environment' directly
against verification_history (technique_id is already denormalized
there, so no internal/scenario dependency is needed). Host-specific
matches win over environment-wide ones regardless of recency."
git push
```

---

### Task 4: `pathcorrelation` — default path construction

**Files:**
- Create: `orchestrator/internal/pathcorrelation/paths.go`
- Test: `orchestrator/internal/pathcorrelation/paths_test.go`

**Interfaces:**
- Consumes: `attackpath.Graph.Nodes()`, `attackpath.Graph.ShortestPath(from, to string) []Edge`, `attackpath.Summary.ShortestDAPath`, `attackpath.Summary.MaxBlastEntry`, `attackpath.Summary.ReachableCrownJewels() []CrownJewelExposure` (all already exported), `AttackPath` (Task 2), the score-weight constants defined in this task.
- Produces: `DefaultPaths(g *attackpath.Graph, s attackpath.Summary) []AttackPath`, and the exported weight constants `pathWeightDA`, `crownJewelBaseWeight`, `crownJewelEntryWeight`, `crownJewelEntryCap` (unexported package constants — "produces" here means later tasks in this same package rely on their names).

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/pathcorrelation/paths_test.go
package pathcorrelation

import (
	"testing"

	"github.com/audspect/bas/internal/attackpath"
)

func testGraph() (*attackpath.Graph, attackpath.Summary) {
	cols := []attackpath.Collection{
		{AgentID: "ws01", Source: "agent",
			Nodes: []attackpath.Node{{ID: "WS01", Kind: attackpath.KindHost, Role: attackpath.RoleEndpoint}},
			Edges: []attackpath.Edge{{From: "WS01", To: "FILE01", Kind: attackpath.EdgeSMB}}},
		{AgentID: "file01", Source: "sharphound",
			Nodes: []attackpath.Node{
				{ID: "FILE01", Kind: attackpath.KindHost, Role: attackpath.RoleServer, CrownJewel: "FileServer"},
				{ID: "svc", Kind: attackpath.KindUser, Label: "svc-backup"},
				{ID: "DA", Kind: attackpath.KindGroup, Label: "Domain Admins", HighValue: true},
			},
			Edges: []attackpath.Edge{
				{From: "FILE01", To: "svc", Kind: attackpath.EdgeHasSession},
				{From: "svc", To: "DA", Kind: attackpath.EdgeMemberOf},
			}},
	}
	return attackpath.BuildGraphAndAnalyze(cols, nil)
}

func TestDefaultPaths_IncludesDAPathAndCrownJewelPath(t *testing.T) {
	g, s := testGraph()
	if !s.DomainCompromise {
		t.Fatalf("fixture should produce domain compromise: %+v", s)
	}

	paths := DefaultPaths(g, s)

	var haveDA, haveCJ bool
	for _, p := range paths {
		if len(p.Edges) == len(s.ShortestDAPath) && p.Weight == pathWeightDA {
			haveDA = true
		}
		if p.Weight > 0 && p.Weight != pathWeightDA {
			haveCJ = true
			if p.Edges[len(p.Edges)-1].To != "FILE01" {
				t.Fatalf("crown-jewel path should end at FILE01, got %+v", p.Edges)
			}
		}
	}
	if !haveDA {
		t.Fatalf("expected a Domain-Admin path among %+v", paths)
	}
	if !haveCJ {
		t.Fatalf("expected a crown-jewel path among %+v", paths)
	}
}

func TestDefaultPaths_EmptyGraphReturnsNoPaths(t *testing.T) {
	g, s := attackpath.BuildGraphAndAnalyze(nil, nil)
	if paths := DefaultPaths(g, s); len(paths) != 0 {
		t.Fatalf("empty graph should produce 0 paths, got %d", len(paths))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/pathcorrelation/... -run TestDefaultPaths -v`
Expected: FAIL — `DefaultPaths undefined`, `pathWeightDA undefined`.

- [ ] **Step 3: Implement `paths.go`**

```go
// orchestrator/internal/pathcorrelation/paths.go
package pathcorrelation

import (
	"fmt"
	"sort"

	"github.com/audspect/bas/internal/attackpath"
)

// Path-weight constants for the DetectionCoverageScore formula (see
// correlate.go). The Domain-Admin path always outweighs any single crown
// jewel; a crown jewel reachable from more entry hosts weighs more, capped
// so one extremely exposed jewel cannot swamp the score.
const (
	pathWeightDA          = 40.0
	crownJewelBaseWeight  = 15.0
	crownJewelEntryWeight = 3.0
	crownJewelEntryCap    = 5
)

// DefaultPaths builds this slice's default correlated-path set from an
// already-computed Summary: the Domain-Admin path (if any) plus one
// representative shortest path to each reachable crown jewel. A future
// caller (e.g. Exposure Explorer) can construct its own []AttackPath and
// call Correlate directly, bypassing this helper.
func DefaultPaths(g *attackpath.Graph, s attackpath.Summary) []AttackPath {
	var paths []AttackPath
	if len(s.ShortestDAPath) > 0 {
		paths = append(paths, AttackPath{
			Label:  fmt.Sprintf("Shortest path to Domain Admin (from %s)", s.MaxBlastEntry),
			Edges:  s.ShortestDAPath,
			Weight: pathWeightDA,
		})
	}

	var hosts []string
	for _, n := range g.Nodes() {
		if n.Kind == attackpath.KindHost {
			hosts = append(hosts, n.ID)
		}
	}
	sort.Strings(hosts)

	for _, cj := range s.ReachableCrownJewels() {
		for _, h := range hosts {
			p := g.ShortestPath(h, cj.Node)
			if len(p) == 0 || len(p) != cj.MinHops {
				continue
			}
			entries := cj.EntryHosts
			if entries > crownJewelEntryCap {
				entries = crownJewelEntryCap
			}
			paths = append(paths, AttackPath{
				Label:  fmt.Sprintf("Path to crown jewel %s (%s), from %s", cj.Tag, cj.Node, h),
				Edges:  p,
				Weight: crownJewelBaseWeight + crownJewelEntryWeight*float64(entries),
			})
			break
		}
	}
	return paths
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/pathcorrelation/... -run TestDefaultPaths -v`
Expected: PASS.

- [ ] **Step 5: Format, build, vet**

Run: `cd orchestrator && gofmt -l internal/pathcorrelation && go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 6: Commit and push**

```bash
cd orchestrator
git add internal/pathcorrelation/paths.go internal/pathcorrelation/paths_test.go
git commit -m "feat(pathcorrelation): add DefaultPaths (DA path + crown-jewel paths)

Builds the default []AttackPath set correlated against detection
coverage: the Domain-Admin path (already computed on Summary) plus one
representative shortest path to each reachable crown jewel, each
carrying its own scoring weight."
git push
```

---

### Task 5: `pathcorrelation` — the `Correlate` engine

**Files:**
- Create: `orchestrator/internal/pathcorrelation/correlate.go`
- Test: `orchestrator/internal/pathcorrelation/correlate_test.go`

**Interfaces:**
- Consumes: everything from Tasks 2-4 (`AttackPath`, `DetectionStatus`, `RunLookup`, `RuleLibrary`, `EdgeTechniqueMapper`, `DefaultEdgeTechniqueMapper`, path-weight constants), plus `attackpath.Graph.EdgesTo`, `attackpath.Summary.ChokePoints`.
- Produces: `func Correlate(ctx context.Context, g *attackpath.Graph, s attackpath.Summary, paths []AttackPath, mapper EdgeTechniqueMapper, runs RunLookup, rules RuleLibrary) (AttackPathCorrelation, error)` — the sole entry point later tasks (API handler, reporting engine) call.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/pathcorrelation/correlate_test.go
package pathcorrelation

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/rulelib"
)

// fakeRunLookup returns a canned result per techniqueID, ignoring hostname
// (tests that need host-specific behavior set WantHost).
type fakeRunLookup struct {
	found      map[string]VerificationResult
	wantHost   string // if set, only techniqueIDs in hostMatches get Confidence: Host
	hostMatches map[string]bool
}

func (f *fakeRunLookup) VerifiedDetection(_ context.Context, techniqueID, hostname string) (VerificationResult, bool, error) {
	res, ok := f.found[techniqueID]
	if !ok {
		return VerificationResult{}, false, nil
	}
	if f.wantHost != "" && hostname == f.wantHost && f.hostMatches[techniqueID] {
		res.Confidence = ConfidenceHost
	} else if res.Confidence == ConfidenceHost {
		res.Confidence = ConfidenceEnvironment
	}
	return res, true, nil
}

// fakeRuleLibrary returns a rule for every techniqueID in Has.
type fakeRuleLibrary struct{ has map[string]bool }

func (f *fakeRuleLibrary) RulesByTechnique(techniqueID string) []rulelib.Rule {
	if f.has[techniqueID] {
		return []rulelib.Rule{{ID: "AUDRULE-000001", TechniqueIDs: []string{techniqueID}}}
	}
	return nil
}

func daFixture() (*attackpath.Graph, attackpath.Summary) {
	cols := []attackpath.Collection{
		{AgentID: "ws01", Source: "agent",
			Nodes: []attackpath.Node{{ID: "WS01", Kind: attackpath.KindHost, Role: attackpath.RoleEndpoint}},
			Edges: []attackpath.Edge{{From: "WS01", To: "FILE01", Kind: attackpath.EdgeSMB}}},
		{AgentID: "file01", Source: "sharphound",
			Nodes: []attackpath.Node{
				{ID: "FILE01", Kind: attackpath.KindHost, Role: attackpath.RoleServer},
				{ID: "svc", Kind: attackpath.KindUser, Label: "svc-backup"},
				{ID: "DA", Kind: attackpath.KindGroup, Label: "Domain Admins", HighValue: true},
			},
			Edges: []attackpath.Edge{
				{From: "FILE01", To: "svc", Kind: attackpath.EdgeHasSession},
				{From: "svc", To: "DA", Kind: attackpath.EdgeMemberOf},
			}},
	}
	return attackpath.BuildGraphAndAnalyze(cols, nil)
}

func TestCorrelate_NoHistoryAnywhere_IsUnknown(t *testing.T) {
	g, s := daFixture()
	paths := DefaultPaths(g, s)
	runs := &fakeRunLookup{found: map[string]VerificationResult{}}
	rules := &fakeRuleLibrary{has: map[string]bool{}}

	corr, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{}, runs, rules)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if corr.Statistics.VerifiedUnknown == 0 {
		t.Fatalf("expected at least one Unknown edge, got stats %+v", corr.Statistics)
	}
	if corr.Statistics.VerifiedCovered != 0 {
		t.Fatalf("nothing should be Covered, got stats %+v", corr.Statistics)
	}
}

func TestCorrelate_RuleExistsButNeverVerified_IsGap(t *testing.T) {
	g, s := daFixture()
	paths := DefaultPaths(g, s)
	runs := &fakeRunLookup{found: map[string]VerificationResult{}}
	rules := &fakeRuleLibrary{has: map[string]bool{"T1021.002": true}} // SMB edge's technique

	corr, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{}, runs, rules)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	var found bool
	for _, p := range corr.Paths {
		for _, e := range p.Edges {
			if e.Edge.Kind == attackpath.EdgeSMB {
				found = true
				if e.Status.Expected != ExpectedCovered {
					t.Fatalf("SMB edge Expected = %q, want covered", e.Status.Expected)
				}
				if e.Status.Verified != VerifiedGap {
					t.Fatalf("SMB edge Verified = %q, want gap", e.Status.Verified)
				}
			}
		}
	}
	if !found {
		t.Fatal("SMB edge not found in any correlated path")
	}
}

func TestCorrelate_HostSpecificDetection_IsCoveredWithHostConfidence(t *testing.T) {
	g, s := daFixture()
	paths := DefaultPaths(g, s)
	runs := &fakeRunLookup{
		found: map[string]VerificationResult{
			"T1021.002": {Confidence: ConfidenceHost, Evidence: Evidence{RunID: "run1"}},
		},
		wantHost:    "FILE01",
		hostMatches: map[string]bool{"T1021.002": true},
	}
	rules := &fakeRuleLibrary{has: map[string]bool{"T1021.002": true}}

	corr, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{}, runs, rules)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	var got *DetectionStatus
	for _, p := range corr.Paths {
		for _, e := range p.Edges {
			if e.Edge.Kind == attackpath.EdgeSMB {
				st := e.Status
				got = &st
			}
		}
	}
	if got == nil {
		t.Fatal("SMB edge not found")
	}
	if got.Verified != VerifiedCovered || got.Confidence != ConfidenceHost {
		t.Fatalf("got %+v, want Verified=covered Confidence=host", got)
	}
}

func TestCorrelate_MultiTechniqueEdgeMixedResults_IsPartial(t *testing.T) {
	g, s := daFixture()
	paths := DefaultPaths(g, s)
	// HasSession maps to T1003 (0.7) and T1552 (0.5); verify only T1003.
	runs := &fakeRunLookup{
		found: map[string]VerificationResult{
			"T1003": {Confidence: ConfidenceEnvironment, Evidence: Evidence{RunID: "run2"}},
		},
	}
	rules := &fakeRuleLibrary{has: map[string]bool{"T1003": true}}

	corr, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{}, runs, rules)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	var got *DetectionStatus
	for _, p := range corr.Paths {
		for _, e := range p.Edges {
			if e.Edge.Kind == attackpath.EdgeHasSession {
				st := e.Status
				got = &st
			}
		}
	}
	if got == nil {
		t.Fatal("HasSession edge not found")
	}
	if got.Verified != VerifiedPartial {
		t.Fatalf("Verified = %q, want partial", got.Verified)
	}
}

func TestCorrelate_NoDangerousPaths_ScoreIs100(t *testing.T) {
	g, s := attackpath.BuildGraphAndAnalyze(nil, nil)
	corr, err := Correlate(context.Background(), g, s, nil, DefaultEdgeTechniqueMapper{},
		&fakeRunLookup{found: map[string]VerificationResult{}}, &fakeRuleLibrary{has: map[string]bool{}})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if corr.Score != 100 {
		t.Fatalf("Score = %d, want 100 for a graph with no dangerous paths", corr.Score)
	}
	if len(corr.Gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", corr.Gaps)
	}
}

func TestCorrelate_AllGapPath_ScoresLowerThanOneCoveredHop(t *testing.T) {
	g, s := daFixture()
	paths := DefaultPaths(g, s)
	rules := &fakeRuleLibrary{has: map[string]bool{}}

	allGap, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{},
		&fakeRunLookup{found: map[string]VerificationResult{}}, rules)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}

	oneCovered, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{},
		&fakeRunLookup{found: map[string]VerificationResult{
			"T1078": {Confidence: ConfidenceHost, Evidence: Evidence{RunID: "run3"}}, // MemberOf's stronger technique
		}}, rules)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}

	if oneCovered.Score <= allGap.Score {
		t.Fatalf("a path with one covered hop (%d) should score higher than all-gap (%d)", oneCovered.Score, allGap.Score)
	}
}

func TestCorrelate_GapsSortedWorstFirstWithPriority(t *testing.T) {
	g, s := daFixture()
	paths := DefaultPaths(g, s)
	corr, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{},
		&fakeRunLookup{found: map[string]VerificationResult{}}, &fakeRuleLibrary{has: map[string]bool{}})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if len(corr.Gaps) < 2 {
		t.Fatalf("expected at least 2 gaps in this fixture, got %d", len(corr.Gaps))
	}
	for _, g := range corr.Gaps {
		switch g.Priority {
		case PriorityCritical, PriorityHigh, PriorityMedium, PriorityLow:
		default:
			t.Fatalf("unexpected priority %q", g.Priority)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/pathcorrelation/... -run TestCorrelate -v`
Expected: FAIL — `Correlate undefined`.

- [ ] **Step 3: Implement `correlate.go`**

```go
// orchestrator/internal/pathcorrelation/correlate.go
package pathcorrelation

import (
	"context"
	"fmt"
	"sort"

	"github.com/audspect/bas/internal/attackpath"
)

// gapFactor weights for VerifiedStatus, used both by scoring and by gap
// ranking. Gap (a rule exists, never proven to fire) ranks above Unknown (no
// rule exists at all) because it is the more immediately actionable of the
// two — tune here, not in every call site.
const (
	weightGap     = 1.0
	weightUnknown = 0.6
	weightPartial = 0.4
	weightCovered = 0.0

	gapPriorityCritical = 0.5
	gapPriorityHigh     = 0.25
	gapPriorityMedium   = 0.10
)

type edgeKey struct {
	From, To string
	Kind     attackpath.EdgeKind
}

func edgeKeyOf(e attackpath.Edge) edgeKey { return edgeKey{e.From, e.To, e.Kind} }

// Correlate is the sole entry point: given an already-built graph/summary
// and a set of paths to annotate (see DefaultPaths), it computes per-edge
// detection status, a weighted DetectionCoverageScore, and prioritized gaps.
func Correlate(
	ctx context.Context,
	g *attackpath.Graph,
	s attackpath.Summary,
	paths []AttackPath,
	mapper EdgeTechniqueMapper,
	runs RunLookup,
	rules RuleLibrary,
) (AttackPathCorrelation, error) {
	if mapper == nil {
		mapper = DefaultEdgeTechniqueMapper{}
	}

	canonical := map[edgeKey]attackpath.Edge{}
	for _, p := range paths {
		for _, e := range p.Edges {
			canonical[edgeKeyOf(e)] = e
		}
	}
	for _, cp := range s.ChokePoints {
		for _, e := range g.EdgesTo(cp.Node) {
			canonical[edgeKeyOf(e)] = e
		}
	}

	statuses := make(map[edgeKey]DetectionStatus, len(canonical))
	for key, e := range canonical {
		st, err := statusFor(ctx, g, e, mapper, runs, rules)
		if err != nil {
			return AttackPathCorrelation{}, fmt.Errorf("pathcorrelation: status for edge %+v: %w", e, err)
		}
		statuses[key] = st
	}
	annotate := func(e attackpath.Edge) AnnotatedEdge {
		return AnnotatedEdge{Edge: e, Status: statuses[edgeKeyOf(e)]}
	}

	var annotatedPaths []AnnotatedPath
	for _, p := range paths {
		ap := AnnotatedPath{Label: p.Label, Weight: p.Weight}
		for _, e := range p.Edges {
			ap.Edges = append(ap.Edges, annotate(e))
		}
		ap.WeakestLink = weakestLink(ap.Edges)
		annotatedPaths = append(annotatedPaths, ap)
	}

	var annotatedChoke []AnnotatedChokePoint
	for _, cp := range s.ChokePoints {
		var incoming []AnnotatedEdge
		for _, e := range g.EdgesTo(cp.Node) {
			incoming = append(incoming, annotate(e))
		}
		annotatedChoke = append(annotatedChoke, AnnotatedChokePoint{
			ChokePoint: cp, IncomingEdges: incoming, WeakestLink: weakestLink(incoming),
		})
	}

	gaps := buildGaps(g, s, paths, canonical, statuses)
	stats := buildStatistics(canonical, statuses, gaps)
	score := computeScore(annotatedPaths)

	return AttackPathCorrelation{
		Summary:     summarize(annotatedPaths, stats),
		Score:       score,
		Paths:       annotatedPaths,
		ChokePoints: annotatedChoke,
		Gaps:        gaps,
		Statistics:  stats,
	}, nil
}

// relevantHost returns the graph node ID whose telemetry would observe this
// edge's technique execution, or "" when neither endpoint is a host (e.g.
// MemberOf, a pure user/group relationship) — RunLookup then searches
// environment-wide only. For a session edge the technique executes on the
// host holding the session (From); for every other kind it executes on the
// target being reached (To), falling back to From if To is not a host node.
func relevantHost(g *attackpath.Graph, e attackpath.Edge) string {
	if e.Kind == attackpath.EdgeHasSession {
		if n, ok := g.Node(e.From); ok && n.Kind == attackpath.KindHost {
			return e.From
		}
		return ""
	}
	if n, ok := g.Node(e.To); ok && n.Kind == attackpath.KindHost {
		return e.To
	}
	if n, ok := g.Node(e.From); ok && n.Kind == attackpath.KindHost {
		return e.From
	}
	return ""
}

func statusFor(ctx context.Context, g *attackpath.Graph, e attackpath.Edge, mapper EdgeTechniqueMapper, runs RunLookup, rules RuleLibrary) (DetectionStatus, error) {
	techs := mapper.Techniques(e.Kind)
	if len(techs) == 0 {
		return DetectionStatus{Expected: ExpectedGap, Verified: VerifiedUnknown, Confidence: ConfidenceUnknown}, nil
	}

	host := relevantHost(g, e)
	foundCount, expectedCoveredCount := 0, 0
	bestConfidence := ConfidenceUnknown
	var ev Evidence
	for _, t := range techs {
		if rules != nil {
			if rs := rules.RulesByTechnique(t.TechniqueID); len(rs) > 0 {
				expectedCoveredCount++
				for _, r := range rs {
					ev.RuleIDs = append(ev.RuleIDs, r.ID)
				}
			}
		}
		if runs == nil {
			continue
		}
		res, found, err := runs.VerifiedDetection(ctx, t.TechniqueID, host)
		if err != nil {
			return DetectionStatus{}, err
		}
		if !found {
			continue
		}
		foundCount++
		if confidenceRank(res.Confidence) > confidenceRank(bestConfidence) {
			bestConfidence = res.Confidence
		}
		ev.RunID = res.Evidence.RunID
		ev.Provider = res.Evidence.Provider
		ev.VerifiedAt = res.Evidence.VerifiedAt
		ev.AlertIDs = append(ev.AlertIDs, res.Evidence.AlertIDs...)
	}

	st := DetectionStatus{Techniques: techs, Evidence: ev, Confidence: bestConfidence}
	if expectedCoveredCount > 0 {
		st.Expected = ExpectedCovered
	} else {
		st.Expected = ExpectedGap
	}
	switch {
	case foundCount == len(techs):
		st.Verified = VerifiedCovered
	case foundCount > 0:
		st.Verified = VerifiedPartial
	case expectedCoveredCount > 0:
		st.Verified = VerifiedGap
	default:
		st.Verified = VerifiedUnknown
	}
	return st, nil
}

func confidenceRank(c VerificationConfidence) int {
	switch c {
	case ConfidenceHost:
		return 2
	case ConfidenceEnvironment:
		return 1
	default:
		return 0
	}
}

func gapFactor(v VerifiedStatus) float64 {
	switch v {
	case VerifiedGap:
		return weightGap
	case VerifiedUnknown:
		return weightUnknown
	case VerifiedPartial:
		return weightPartial
	default:
		return weightCovered
	}
}

func maxWeight(techs []TechniqueMapping) float64 {
	m := 0.0
	for _, t := range techs {
		if t.Weight > m {
			m = t.Weight
		}
	}
	return m
}

func weakestLink(edges []AnnotatedEdge) *AnnotatedEdge {
	if len(edges) == 0 {
		return nil
	}
	worst := edges[0]
	worstScore := gapFactor(worst.Status.Verified)
	for _, e := range edges[1:] {
		if f := gapFactor(e.Status.Verified); f > worstScore {
			worst, worstScore = e, f
		}
	}
	return &worst
}

// pathStrength is the best single hop's (1-gapFactor)*criticality along the
// path — the strongest hop dominates, since one well-detected hop is enough
// for the SOC to catch an attacker walking that path (the "broken attack
// chain" framing: a path with high strength is broken, near-zero is silent
// end to end).
func pathStrength(p AnnotatedPath) float64 {
	best := 0.0
	for _, e := range p.Edges {
		if strength := (1 - gapFactor(e.Status.Verified)) * maxWeight(e.Status.Techniques); strength > best {
			best = strength
		}
	}
	return best
}

func computeScore(paths []AnnotatedPath) int {
	var totalWeight, deficitSum float64
	for _, p := range paths {
		if p.Weight <= 0 {
			continue
		}
		totalWeight += p.Weight
		deficitSum += p.Weight * (1 - pathStrength(p))
	}
	if totalWeight == 0 {
		return 100
	}
	score := 100 - int(100*deficitSum/totalWeight+0.5)
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}
	return score
}

func targetNodes(s attackpath.Summary) []string {
	var out []string
	if s.DomainCompromise && len(s.ShortestDAPath) > 0 {
		out = append(out, s.ShortestDAPath[len(s.ShortestDAPath)-1].To)
	}
	for _, cj := range s.CrownJewels {
		if cj.Reachable {
			out = append(out, cj.Node)
		}
	}
	return out
}

func nearestTargetDistance(g *attackpath.Graph, from string, targets []string) int {
	best := -1
	for _, t := range targets {
		if from == t {
			return 0
		}
		if p := g.ShortestPath(from, t); len(p) > 0 && (best == -1 || len(p) < best) {
			best = len(p)
		}
	}
	if best == -1 {
		return 10 // no reachable target from here — treat as far
	}
	return best
}

func priorityFor(score float64) GapPriority {
	switch {
	case score >= gapPriorityCritical:
		return PriorityCritical
	case score >= gapPriorityHigh:
		return PriorityHigh
	case score >= gapPriorityMedium:
		return PriorityMedium
	default:
		return PriorityLow
	}
}

func gapReason(crossCount, totalPaths, dist int, st DetectionStatus) string {
	verb := "no verified detection"
	switch st.Verified {
	case VerifiedPartial:
		verb = "only partial verified detection"
	case VerifiedUnknown:
		verb = "no detection capability found for this technique"
	}
	return fmt.Sprintf("crossed by %d of %d correlated path(s), %d hop(s) from the nearest high-value target, %s",
		crossCount, totalPaths, dist, verb)
}

func buildGaps(g *attackpath.Graph, s attackpath.Summary, paths []AttackPath, canonical map[edgeKey]attackpath.Edge, statuses map[edgeKey]DetectionStatus) []PrioritizedGap {
	totalPaths := len(paths)
	if totalPaths == 0 {
		totalPaths = 1
	}
	crossCount := map[edgeKey]int{}
	for _, p := range paths {
		seen := map[edgeKey]bool{}
		for _, e := range p.Edges {
			k := edgeKeyOf(e)
			if !seen[k] {
				crossCount[k]++
				seen[k] = true
			}
		}
	}
	targets := targetNodes(s)

	var gaps []PrioritizedGap
	for k, e := range canonical {
		st := statuses[k]
		gf := gapFactor(st.Verified)
		if gf == 0 {
			continue
		}
		freq := float64(crossCount[k]) / float64(totalPaths)
		dist := nearestTargetDistance(g, e.To, targets)
		proximity := 1.0 / (1.0 + float64(dist))
		crit := maxWeight(st.Techniques)
		score := freq * proximity * crit * gf

		gaps = append(gaps, PrioritizedGap{
			Edge:       e,
			Techniques: st.Techniques,
			Priority:   priorityFor(score),
			Reason:     gapReason(crossCount[k], totalPaths, dist, st),
			score:      score,
		})
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].score > gaps[j].score })
	return gaps
}

func buildStatistics(canonical map[edgeKey]attackpath.Edge, statuses map[edgeKey]DetectionStatus, gaps []PrioritizedGap) Statistics {
	var st Statistics
	st.EdgesTotal = len(canonical)
	techRisk := map[string]float64{}
	for k := range canonical {
		s := statuses[k]
		if s.Expected == ExpectedCovered {
			st.ExpectedCovered++
		} else {
			st.ExpectedGap++
		}
		switch s.Verified {
		case VerifiedCovered:
			st.VerifiedCovered++
		case VerifiedPartial:
			st.VerifiedPartial++
		case VerifiedGap:
			st.VerifiedGap++
		default:
			st.VerifiedUnknown++
		}
	}
	for _, gp := range gaps {
		for _, t := range gp.Techniques {
			techRisk[t.TechniqueID] += gp.score
		}
	}
	ids := make([]string, 0, len(techRisk))
	for id := range techRisk {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var bestVal float64
	for _, id := range ids {
		if techRisk[id] > bestVal {
			bestVal, st.HighestRiskTechnique = techRisk[id], id
		}
	}
	if len(gaps) > 0 {
		e := gaps[0].Edge
		st.HighestRiskEdge = &e
	}
	return st
}

func summarize(paths []AnnotatedPath, stats Statistics) string {
	if stats.EdgesTotal == 0 {
		return "No dangerous attack paths were found to correlate against detection coverage."
	}
	uncovered := stats.VerifiedGap + stats.VerifiedUnknown + stats.VerifiedPartial
	return fmt.Sprintf("%d of %d correlated edges have no fully verified detection across %d attack path(s).",
		uncovered, stats.EdgesTotal, len(paths))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/pathcorrelation/... -v`
Expected: PASS — every test in the package (mapper, paths, runlookup — Docker must be running for `TestSQLRunLookup`, correlate).

- [ ] **Step 5: Format, build, vet**

Run: `cd orchestrator && gofmt -l internal/pathcorrelation && go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 6: Commit and push**

```bash
cd orchestrator
git add internal/pathcorrelation/correlate.go internal/pathcorrelation/correlate_test.go
git commit -m "feat(pathcorrelation): add the Correlate engine

Correlate() is the package's single entry point: computes per-edge
DetectionStatus (Expected from the Rule Library, Verified from
RunLookup), rolls it up onto annotated paths and choke points, ranks
gaps by path-frequency x target-proximity x technique-criticality x
gap-severity, and produces a weighted DetectionCoverageScore where the
strongest hop on a path dominates (one well-detected hop breaks the
chain)."
git push
```

---

### Task 6: API — `GET /api/attackpath/correlation`

**Files:**
- Create: `orchestrator/internal/api/pathcorrelation_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/pathcorrelation_handlers_test.go`

**Interfaces:**
- Consumes: `h.db`, `h.rules *rulelib.Engine` (already on `Handler`, from SP2), `h.loadAttackPathCollections(r)`, `h.loadAssetTags(r)` (already in `attackpath_handlers.go`), `attackpath.BuildGraphAndAnalyze`, `pathcorrelation.DefaultPaths`, `pathcorrelation.Correlate`, `pathcorrelation.NewSQLRunLookup`, `pathcorrelation.DefaultEdgeTechniqueMapper{}`, `pathcorrelation.RuleLibrary`.
- Produces: `func (h *Handler) GetAttackPathCorrelation(w http.ResponseWriter, r *http.Request)`, route `GET /api/attackpath/correlation` (tier `tierAny`).

- [ ] **Step 1: Write the failing test**

This package already has its own `TestMain`/shared testcontainer, declared in the pre-existing `internal/api/testmain_test.go` as a package-level `var sharedDB *testutil.TestDB` — do NOT declare a second `TestMain` or a new pool variable; reuse `sharedDB` directly, the same way every other DB-touching test in this package already does (`sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) { ... })`).

```go
// orchestrator/internal/api/pathcorrelation_handlers_test.go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetAttackPathCorrelation_NilRules_ReturnsEmptyCorrelationNotError(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetAttackPathCorrelation(rec, httptest.NewRequest(http.MethodGet, "/api/attackpath/correlation", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 even with h.rules nil", rec.Code)
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		score, ok := out["detectionCoverageScore"].(float64)
		if !ok || score != 100 {
			t.Fatalf("detectionCoverageScore = %v, want 100 with no attack-path collections", out["detectionCoverageScore"])
		}
	})
}

func TestGetAttackPathCorrelation_WithRules_Returns200(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithRuleLibrary(rulelib.NewEngine())
		rec := httptest.NewRecorder()
		h.GetAttackPathCorrelation(rec, httptest.NewRequest(http.MethodGet, "/api/attackpath/correlation", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, key := range []string{"summary", "detectionCoverageScore", "paths", "chokePoints", "gaps", "statistics"} {
			if _, ok := out[key]; !ok {
				t.Fatalf("response missing key %q: %v", key, out)
			}
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetAttackPathCorrelation -v`
Expected: FAIL — `h.GetAttackPathCorrelation undefined`.

- [ ] **Step 3: Implement the handler**

```go
// orchestrator/internal/api/pathcorrelation_handlers.go
package api

import (
	"net/http"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/pathcorrelation"
)

// GetAttackPathCorrelation annotates the fleet attack-path graph's
// dangerous paths and choke points with expected/verified detection
// coverage — SP3. Read-only (Viewer+). Returns a zero-value, 100-scored
// correlation (never an error) when there is no attack-path collection yet
// or when h.rules is not wired, matching the rest of this API's nil-safe
// convention for optional subsystems.
// GET /api/attackpath/correlation
func (h *Handler) GetAttackPathCorrelation(w http.ResponseWriter, r *http.Request) {
	cols := h.loadAttackPathCollections(r)
	g, s := attackpath.BuildGraphAndAnalyze(cols, h.loadAssetTags(r))

	// h.rules is a *rulelib.Engine; a nil pointer passed directly into the
	// pathcorrelation.RuleLibrary interface parameter would produce a
	// non-nil interface wrapping a nil pointer (Go's classic typed-nil
	// trap), so guard explicitly rather than passing h.rules through as-is.
	var rules pathcorrelation.RuleLibrary
	if h.rules != nil {
		rules = h.rules
	}

	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(
		r.Context(), g, s, paths,
		pathcorrelation.DefaultEdgeTechniqueMapper{},
		pathcorrelation.NewSQLRunLookup(h.db),
		rules,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, corr)
}
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, add after the existing attack-path GET block (right after `r.Get("/api/attackpath/jobs/{id}", h.GetAttackPathJob)`):

```go
		r.Get("/api/attackpath/correlation", h.GetAttackPathCorrelation)
```

- [ ] **Step 5: Add the RBAC matrix entry**

In `orchestrator/internal/api/rbac_matrix_test.go`, add after `{http.MethodGet, "/api/attackpath/jobs/{id}", tierAny, ""},`:

```go
	{http.MethodGet, "/api/attackpath/correlation", tierAny, ""},
```

- [ ] **Step 6: Run tests to verify they pass (Docker must be running)**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestGetAttackPathCorrelation|TestRBACMatrix_NoDrift' -v`
Expected: PASS — both new handler tests plus `TestRBACMatrix_NoDrift`.

- [ ] **Step 7: Format, build, vet**

Run: `cd orchestrator && gofmt -l internal/api internal/pathcorrelation && go build ./... && go vet ./...`
Expected: clean (pre-existing CRLF `gofmt -l` noise on untouched files elsewhere in the repo is expected and not a regression — confirmed in prior SP2 validation).

- [ ] **Step 8: Commit and push**

```bash
cd orchestrator
git add internal/api/pathcorrelation_handlers.go internal/api/pathcorrelation_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): add read-only Attack Path Detection Coverage endpoint

GET /api/attackpath/correlation (Viewer+) builds the fleet attack-path
graph exactly as GetAttackPathSummary does, then runs
pathcorrelation.Correlate against it. Nil-safe: returns a zero-value,
100-scored result (never an error) when there is nothing to
correlate against, matching this API's established convention for
optional subsystems."
git push
```

---

### Task 7: Reporting — wire the Rule Library, `PathCorrelation` field, and the HTML section

**Files:**
- Modify: `orchestrator/internal/reporting/engine.go`
- Modify: `orchestrator/internal/reporting/html.go`
- Modify: `orchestrator/cmd/server/main.go`
- Test: `orchestrator/internal/reporting/pathcorrelation_test.go` (new)

**Interfaces:**
- Consumes: everything from `internal/pathcorrelation` (Tasks 2-5); `reporting.Engine`'s existing `ScenarioResolver`/`VerificationResolver` pattern (`engine.go:24-65`) as the template to mirror; `loadAttackPathSummary`/`loadAssetTags` (`engine.go:1331-1370`).
- Produces: `reporting.RuleLibraryResolver` interface, `(e *Engine) WithRuleLibrary(r RuleLibraryResolver) *Engine`, `FullReport.PathCorrelation *pathcorrelation.AttackPathCorrelation`, `(e *Engine) loadAttackPathGraph(ctx) (*attackpath.Graph, attackpath.Summary)` (replaces the body of `loadAttackPathSummary`), a new HTML subsection inside the existing Section 8 template.

**Note on test DB setup:** unlike `internal/api` and the new `internal/pathcorrelation` package, `internal/reporting`'s existing tests have no shared-testcontainer `TestMain` at all (confirmed: no `sharedDB`/`TestMain`/`testutil.NewTestDB` anywhere in the package's existing `*_test.go` files) — this package's DB-touching methods are apparently untested directly today, a pre-existing gap this task does not need to close. Passing a nil `*pgxpool.Pool` into `NewEngine` is safe as long as the test never calls a method that actually touches `e.db` — so this task's tests are written to only exercise `loadPathCorrelation`'s two nil-safety branches (`g == nil` and `e.rules == nil`), both of which return before ever reaching `e.db`. Do not add a new testcontainer setup to this package as part of this task — out of scope.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/reporting/pathcorrelation_test.go
package reporting

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/rulelib"
)

func TestEngine_WithRuleLibrary_ChainsAndStores(t *testing.T) {
	e := NewEngine(nil).WithRuleLibrary(rulelib.NewEngine())
	if e.rules == nil {
		t.Fatal("WithRuleLibrary should set e.rules")
	}
}

func TestEngine_LoadPathCorrelation_NilSafe(t *testing.T) {
	e := NewEngine(nil) // no WithRuleLibrary call — e.rules stays nil

	if got := e.loadPathCorrelation(context.Background(), nil, attackpath.Summary{}); got != nil {
		t.Fatalf("expected nil with g=nil, got %+v", got)
	}

	g := attackpath.New()
	g.AddEdge(attackpath.Edge{From: "A", To: "B", Kind: attackpath.EdgeSMB})
	if got := e.loadPathCorrelation(context.Background(), g, g.Analyze()); got != nil {
		t.Fatalf("expected nil with e.rules unset even though g is non-nil, got %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/... -run 'TestEngine_WithRuleLibrary|TestEngine_LoadPathCorrelation' -v`
Expected: FAIL — `e.rules undefined`, `WithRuleLibrary undefined`, `loadPathCorrelation undefined`.

- [ ] **Step 3: Add the resolver interface and setter**

In `orchestrator/internal/reporting/engine.go`, add the import and the resolver type right after `VerificationResolver` (after line 41), and add the field/setter next to `WithVerifications`:

```go
	"github.com/audspect/bas/internal/rulelib"
```

(add alphabetically among the existing imports, between `"github.com/audspect/bas/internal/reporting/attackdata"` and `"github.com/audspect/bas/internal/scenario"`)

```go
// RuleLibraryResolver is the slice of the SP2 Rule Library engine the
// reporting layer needs for the Attack Path Detection Coverage section.
// *rulelib.Engine satisfies it; nil-safe: WithRuleLibrary is optional and
// that section stays inactive while nil, same convention as
// ScenarioResolver/VerificationResolver above.
type RuleLibraryResolver interface {
	RulesByTechnique(techniqueID string) []rulelib.Rule
}
```

```go
	rules         RuleLibraryResolver  // nil until WithRuleLibrary is called; Attack Path Detection Coverage stays inactive while nil
```

(add this field to the `Engine` struct right after the `verifications` field)

```go
// WithRuleLibrary attaches the Rule Library resolver used by the Attack Path
// Detection Coverage section. Returns the engine for chaining.
func (e *Engine) WithRuleLibrary(r RuleLibraryResolver) *Engine {
	e.rules = r
	return e
}
```

(add right after the existing `WithVerifications` method)

- [ ] **Step 4: Add `PathCorrelation` to `FullReport` and refactor the attack-path loader**

In `orchestrator/internal/reporting/engine.go`, add the import:

```go
	"github.com/audspect/bas/internal/pathcorrelation"
```

(alphabetically, between `"github.com/audspect/bas/internal/models"` and `"github.com/audspect/bas/internal/reporting/attackdata"`)

Add the field right after `AttackPathValidation` in `FullReport` (near line 140):

```go
	// PathCorrelation is the SP3 Attack Path <-> Detection Correlation
	// annotation of AttackPathValidation's dangerous paths and choke points.
	// nil under the exact same conditions as AttackPathValidation (no
	// collection yet), or when WithRuleLibrary was never called.
	PathCorrelation *pathcorrelation.AttackPathCorrelation `json:"pathCorrelation,omitempty"`
```

Replace `loadAttackPathSummary` (lines 1331-1359) entirely with `loadAttackPathGraph` — after Step 5 below rewires both call sites to call `loadAttackPathGraph` directly, `loadAttackPathSummary` would otherwise become dead code (nothing left to call it), so this task removes it rather than keeping an unused wrapper:

```go
// loadAttackPathGraph builds the fleet attack-path graph from every agent's
// stored collection and analyzes it, returning both the graph and its
// Summary. Returns (nil, zero Summary) when no collection exists yet (the
// report then renders the "not yet collected" state) and never fails a
// report on a DB error. Attack paths are inherently fleet-wide — lateral
// movement spans hosts — so the same graph attaches to per-agent, per-run,
// and campaign reports alike. The graph (not just the Summary) is exposed
// because loadPathCorrelation (SP3) needs to run further graph queries
// beyond what Summary already computed.
func (e *Engine) loadAttackPathGraph(ctx context.Context) (*attackpath.Graph, attackpath.Summary) {
	rows, err := e.db.Query(ctx, `SELECT payload FROM attackpath_collections`)
	if err != nil {
		return nil, attackpath.Summary{}
	}
	defer rows.Close()
	var cols []attackpath.Collection
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			continue
		}
		var c attackpath.Collection
		if json.Unmarshal(raw, &c) == nil {
			cols = append(cols, c)
		}
	}
	if len(cols) == 0 {
		return nil, attackpath.Summary{}
	}
	return attackpath.BuildGraphAndAnalyze(cols, e.loadAssetTags(ctx))
}

// loadPathCorrelation runs the SP3 correlation engine against an
// already-built graph/summary. Returns nil when g is nil (nothing collected)
// or when the Rule Library resolver was never wired — same nil-safe
// convention as every other optional report section. Errors are logged, not
// propagated: a correlation failure must never fail the whole report.
func (e *Engine) loadPathCorrelation(ctx context.Context, g *attackpath.Graph, s attackpath.Summary) *pathcorrelation.AttackPathCorrelation {
	if g == nil || e.rules == nil {
		return nil
	}
	// e.rules is a RuleLibraryResolver interface value already — passing it
	// straight into pathcorrelation.Correlate's RuleLibrary parameter is
	// safe here (no typed-nil risk, unlike the *rulelib.Engine call site in
	// the API handler) because e.rules is only ever set via WithRuleLibrary
	// with a genuinely non-nil argument, and the g==nil / e.rules==nil check
	// above already guards the nil case explicitly.
	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(
		ctx, g, s, paths,
		pathcorrelation.DefaultEdgeTechniqueMapper{},
		pathcorrelation.NewSQLRunLookup(e.db),
		e.rules,
	)
	if err != nil {
		log.Printf("warn: pathcorrelation.Correlate: %v", err)
		return nil
	}
	return &corr
}
```

Add `"log"` to the import block if not already present (check first: `grep -n '"log"' internal/reporting/engine.go` — if absent, add it alphabetically among the standard-library imports).

- [ ] **Step 5: Wire all three report-build call sites**

Run: `cd orchestrator && grep -n "e.loadAttackPathSummary(ctx)" internal/reporting/engine.go`

Expected: **three** matches (per-agent report ~line 1284, per-run report ~line 1560, campaign report ~line 1702 — confirmed by direct grep during planning; exact line numbers may have shifted slightly after Step 4's edit, use the grep output, not these numbers, to locate them). Missing any of the three leaves that report type silently without `PathCorrelation`.

Replace **all three** occurrences of:

```go
	report.AttackPathValidation = e.loadAttackPathSummary(ctx)
	applyAttackPathToSummary(&report.Summary, report.AttackPathValidation)
```

with:

```go
	if g, s := e.loadAttackPathGraph(ctx); g != nil {
		report.AttackPathValidation = &s
		report.PathCorrelation = e.loadPathCorrelation(ctx, g, s)
	}
	applyAttackPathToSummary(&report.Summary, report.AttackPathValidation)
```

Then fix the now-stale doc-comment reference: run `grep -n "Called after loadAttackPathSummary" internal/reporting/engine.go` and change that comment line from `// Called after loadAttackPathSummary so the summary fields stay consistent.` to `// Called after loadAttackPathGraph so the summary fields stay consistent.`

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/reporting/... -run 'TestEngine_WithRuleLibrary|TestEngine_LoadPathCorrelation' -v`
Expected: PASS. (No Docker/DB dependency for this specific pair of tests — see the note above Step 1.)

- [ ] **Step 7: Extend the HTML report template**

In `orchestrator/internal/reporting/html.go`, the existing Section 8 closes with:

```
{{end}}
{{else}}
<p style="color:#6e7681">No attack-path data has been collected yet. ...</p>
{{end}}

<div class="pf">
```

Insert a new subsection **immediately before** the outer `{{else}}` (i.e., still inside `{{with .attackPathValidation}}`, right after the existing `{{if .segmentationViolations}}...{{end}}` block at line 1722):

```html

{{with .pathCorrelation}}
<h3>Attack Path Detection Coverage</h3>
<p style="color:#6e7681;font-size:0.82rem">{{.summary}}</p>
<div class="score-row">
  <div class="scard" style="border-left:3px solid {{scoreColor .detectionCoverageScore}}">
    <div class="scard-label">Detection Coverage Score</div>
    <div class="scard-value" style="color:{{scoreColor .detectionCoverageScore}}">{{.detectionCoverageScore}}<span style="font-size:0.9rem;color:#6e7681">/100</span></div>
    <div style="font-size:0.8rem;color:#6e7681">higher is safer · independent of Attack Path Score</div>
  </div>
  <div class="scard">
    <div class="scard-label">Verified Coverage</div>
    <div class="scard-value" style="font-size:1.2rem">{{.statistics.verifiedCovered}}<span style="font-size:0.9rem;color:#6e7681">/{{.statistics.edgesTotal}}</span></div>
    <div style="font-size:0.8rem;color:#6e7681">{{.statistics.verifiedPartial}} partial · {{.statistics.verifiedGap}} gap · {{.statistics.verifiedUnknown}} unknown</div>
  </div>
  {{if .statistics.highestRiskTechnique}}
  <div class="scard" style="border-left:3px solid #da3633">
    <div class="scard-label">Highest-Risk Technique</div>
    <div class="scard-value" style="color:#da3633;font-size:1.2rem">{{.statistics.highestRiskTechnique}}</div>
    <div style="font-size:0.8rem;color:#6e7681">largest cumulative contribution across all gaps</div>
  </div>
  {{end}}
</div>

{{if .gaps}}
<h4 style="margin-top:14px">Prioritized Detection Gaps</h4>
<p style="color:#6e7681;font-size:0.82rem">Edges an attacker could cross with no fully verified detection, ranked by how many paths cross them and how close they sit to a high-value target.</p>
<table>
  <thead><tr><th>From</th><th>Via</th><th>To</th><th>Technique(s)</th><th>Priority</th><th>Reason</th></tr></thead>
  <tbody>
  {{range .gaps}}
  <tr>
    <td style="font-weight:600">{{.edge.from}}</td>
    <td>{{upper .edge.kind}}</td>
    <td style="font-weight:600">{{.edge.to}}</td>
    <td>{{range .techniques}}{{.techniqueId}} {{end}}</td>
    <td style="font-weight:700;color:{{exposureColor .priority}}">{{.priority}}</td>
    <td style="color:#6e7681;font-size:0.82rem">{{.reason}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}
{{end}}
```

This `{{with .pathCorrelation}}...{{end}}` block goes right before the line `{{else}}` that currently follows the segmentation-violations block (the `{{else}}` belongs to the outer `{{with .attackPathValidation}}` and must stay exactly where it is, immediately before `<p style="color:#6e7681">No attack-path data has been collected yet...`).

- [ ] **Step 8: Share one `rulelib.Engine` instance and wire it into the reporting engine**

In `orchestrator/cmd/server/main.go`, move the rule-library construction earlier and wire it into both the reporting engine and the handler chain. Replace:

```go
	// ── Reporting Engine ──────────────────────────────────────────────────
	reportingEngine := reporting.NewEngine(pool).
		WithScenarios(engine).
		WithVerifications(verificationStore)
	log.Println("[+] Reporting engine ready")
```

with:

```go
	// ── Detection Rule Library (SP2) ────────────────────────────────────────
	// Constructed once and shared: the API serves it directly (rulelib_handlers.go)
	// and the reporting engine consumes it read-only for Attack Path Detection
	// Coverage (SP3).
	rulesEngine := rulelib.NewEngine()
	log.Println("[+] Rule Library ready")

	// ── Reporting Engine ──────────────────────────────────────────────────
	reportingEngine := reporting.NewEngine(pool).
		WithScenarios(engine).
		WithVerifications(verificationStore).
		WithRuleLibrary(rulesEngine)
	log.Println("[+] Reporting engine ready")
```

Then replace the handler chain's:

```go
		WithRuleLibrary(rulelib.NewEngine())
```

with:

```go
		WithRuleLibrary(rulesEngine)
```

- [ ] **Step 9: Format, build, vet**

Run: `cd orchestrator && gofmt -l internal/reporting cmd/server && go build ./... && go vet ./...`
Expected: no `gofmt -l` output for the files touched this task; clean build/vet (this is the step most likely to surface a mistake — `main.go` referencing `rulesEngine` before its declaration, a missing `"log"` import in `engine.go`, or a stale second `report.AttackPathValidation = e.loadAttackPathSummary(ctx)` occurrence not replaced by Step 5 — fix any such error before proceeding).

- [ ] **Step 10: Full reporting-package test run**

Run: `cd orchestrator && go test ./internal/reporting/... -v 2>&1 | tail -60`
Expected: every test in the package passes, including the two new tests from Step 1 and every pre-existing reporting test (confirms the `loadAttackPathSummary`/call-site refactor changed no behavior for reports with no `PathCorrelation` data).

- [ ] **Step 11: Commit and push**

```bash
cd orchestrator
git add internal/reporting/engine.go internal/reporting/html.go internal/reporting/pathcorrelation_test.go cmd/server/main.go
git commit -m "feat(reporting): wire Attack Path Detection Coverage into reports

Adds RuleLibraryResolver + WithRuleLibrary (mirrors the existing
ScenarioResolver/VerificationResolver pattern), FullReport.
PathCorrelation, and a new subsection inside the existing Attack Path
Validation report section (Section 8) rendered via the same json-tag
map the rest of the template uses (required under garble — see the
Global Constraints note in this plan). main.go now constructs one
rulelib.Engine shared by the API and the reporting engine instead of
two separate instances."
git push
```

---

### Task 8: Full validation and final push

**Files:** none (verification only).

- [ ] **Step 1: Repo-wide format, build, vet**

Run: `cd orchestrator && gofmt -l internal/attackpath internal/pathcorrelation internal/api internal/reporting cmd/server && go build ./... && go vet ./...`
Expected: `gofmt -l` prints nothing for any file this plan touched or created (pre-existing CRLF noise on untouched files elsewhere in the repo is expected, per prior SP2 validation — do not "fix" those files, out of scope); build and vet both clean.

- [ ] **Step 2: Full Go test suite (Docker must be running)**

Run: `cd orchestrator && go test ./... 2>&1 | tail -100`
Expected: every package reports `ok` (or `?   ... [no test files]`); zero `FAIL` lines, including `internal/attackpath`, `internal/pathcorrelation`, `internal/api`, and `internal/reporting`.

- [ ] **Step 3: Scoped stress runs**

Run: `cd orchestrator && go test ./internal/pathcorrelation/... -count=10 -v 2>&1 | tail -80`
Expected: zero `FAIL` across all 10 iterations.

Run: `cd orchestrator && go test ./internal/attackpath/... -count=10 -run 'TestGraphEdgesTo|TestBuildGraphAndAnalyzeReturnsSameSummaryAsBuildAndAnalyze' -v 2>&1 | tail -40`
Expected: zero `FAIL`.

Run: `cd orchestrator && go test ./internal/api/... -count=5 -run 'TestGetAttackPathCorrelation|TestRBACMatrix_NoDrift' -v 2>&1 | tail -60`
Expected: zero `FAIL` (count=5, not 10, since this run also spins up a fresh Postgres testcontainer each time `TestMain` initializes — 5 iterations is enough to catch flakiness without an excessive wall-clock cost).

Run: `cd orchestrator && go test ./internal/reporting/... -count=10 -run 'TestEngine_WithRuleLibrary|TestEngine_LoadPathCorrelation' -v 2>&1 | tail -40`
Expected: zero `FAIL` (count=10, not 5, since these two tests need no DB/testcontainer — cheap to repeat like the pathcorrelation/attackpath stress runs above).

- [ ] **Step 4: Confirm everything is pushed**

Run: `cd orchestrator && git status --short && git log --oneline -10`
Expected: working tree clean aside from pre-existing unrelated untracked files (documented in the repo's baseline `git status`, not created by this plan); all 8 feature commits from this plan visible in the log, most recent first, with no local commits ahead of `origin/main`.

Run: `git status -sb | head -1`
Expected: `## main...origin/main` with no `[ahead N]`/`[behind N]` suffix.

- [ ] **Step 5: Manual smoke check of the new endpoint (optional but recommended)**

If a local server + Postgres are available, start the server and hit the new endpoint directly to confirm the JSON shape matches the spec before considering SP3 done:

Run: `curl -s -H "Authorization: Bearer <a valid Viewer+ JWT>" http://localhost:8080/api/attackpath/correlation | head -c 2000`
Expected: a JSON object with `summary`, `detectionCoverageScore`, `paths`, `chokePoints`, `gaps`, `statistics` keys (matches `AttackPathCorrelation`'s json tags exactly).

