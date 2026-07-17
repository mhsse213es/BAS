# Phase 6, Subsystem 2 — Recommendation Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rank executable ATT&CK techniques by how much value testing them next would add, and emit a runnable suggested scenario from the top N.

**Architecture:** A new pure-aggregator package `internal/recommend` scores each ART-testable technique as `0.50×ThreatPriority + 0.30×CoverageGap + 0.20×EnvironmentRisk`, reusing `reporting.ComputePriorityScore` (newly exported) for the threat term, fleet-wide `scenario_runs.results` for the coverage term, and the SP3 graph + SP6 criticality for the environment term. One new read-only endpoint and one new UI tab consume it.

**Tech Stack:** Go, PostgreSQL (pgx/v5, jsonb), chi router, vanilla JS (no build step, no external dependencies).

## Global Constraints

- No new DB tables — `internal/recommend` is a pure consumer, same as `internal/exposure` / `internal/pathcorrelation` / `internal/dashboard`.
- All `technique_cve_relationships` queries MUST be gated `status = 'Active' AND effective_confidence IN ('High','Medium')` — the Relationship Store's confidence contract. Never query bare `technique_cves`.
- Nil-safe throughout: an empty fleet / unseeded content / nil graph returns an empty result, never an error.
- `orchestrator/wwwroot/index.html` and `orchestrator/cmd/server/wwwroot/index.html` are the same file via an NTFS hardlink but tracked as two separate git paths — edit and `git add` both in every UI-touching commit.
- Read-only endpoints are Viewer+ (`tierAny`), and **every new route must also be added to `rbac_matrix_test.go`'s `routeMatrix`** — `TestRBACMatrix_NoDrift` fails the whole `internal/api` suite otherwise.
- Docker Desktop must be running for any test marked "Docker-backed" (`testutil.MustSharedTestDB()`).

## Deviation from the approved spec (flagged, not silent)

The spec's Architecture section proposed `func Build(ctx, pool, limit)` with pipeline step 5 building the graph internally via `attackpath.BuildGraphAndAnalyze`. **This plan changes the signature to take the graph as a parameter:**

```go
func Build(ctx context.Context, pool *pgxpool.Pool, g *attackpath.Graph, s attackpath.Summary, limit int) (Recommendations, error)
```

Reason: building the graph internally requires loading `attackpath_collections` and `attackpath_asset_tags`. `internal/api` already has both loaders (`h.loadAttackPathCollections`, `h.loadAssetTags`), and `internal/dashboard` duplicated them earlier today — doing it a third time here would triplicate ~40 lines. Taking the graph as a parameter matches `exposure.Build`'s established "caller builds it once" convention exactly (documented on `exposure.Build`), lets the API handler reuse its existing loaders, and makes the environment-scoring tests simpler (in-memory graph fixtures, no DB round-trip for that term). Everything else in the spec is implemented as written.

## File Structure

| File | Responsibility |
|---|---|
| `internal/attackpath/graph.go` (modify) | Add the `Edges()` accessor — `adj` is unexported, so no consumer can enumerate all edges today |
| `internal/reporting/insights.go` (modify) | Export `ComputePriorityScore` / `PriorityTierFor` (rename only) |
| `internal/recommend/types.go` (create) | The API-facing types |
| `internal/recommend/score.go` (create) | Pure scoring: `CoverageGap`, `CoverageStateFor`, `EnvironmentRisk`, `RecommendationScore`, `buildReasons` |
| `internal/recommend/recommend.go` (create) | `Build()` + the SQL loaders + the environment index |
| `internal/api/recommend_handlers.go` (create) | `GET /api/recommend/simulations` |
| `wwwroot/index.html` + `cmd/server/wwwroot/index.html` (modify) | The Recommendations tab |

---

### Task 1: `Graph.Edges()` accessor

**Files:**
- Modify: `orchestrator/internal/attackpath/graph.go:126` (insert after `EdgeCount`, before `EdgesTo`)
- Create: `orchestrator/internal/attackpath/graph_test.go` (no such file exists yet — the package's tests live in `assets_test.go`, `attackpath_test.go`, `build_test.go`, `graph_export_test.go`, `reconcile_test.go`, `sharphound_test.go`)

**Interfaces:**
- Produces: `func (g *Graph) Edges() []Edge` — every edge in the graph, order unspecified. Consumed by Task 4's environment index.

Additive export only, same precedent as SP3's `Graph.EdgesTo` / `BuildGraphAndAnalyze` additions (commit `72e9a00`).

Note the real API names: the constructor is `attackpath.New()` (not `NewGraph`), and the `NodeKind` constants are `KindHost` / `KindUser` / `KindGroup` (not `NodeHost`). `AddEdge` auto-creates any missing endpoint as a bare host node, so edge-only fixtures are valid.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/attackpath/graph_test.go`:

```go
package attackpath

import "testing"

// TestGraphEdges_ReturnsEveryEdge pins the Edges() accessor: internal/recommend
// needs to enumerate all edges to decide which ATT&CK techniques are relevant
// to this environment, and adj is unexported.
func TestGraphEdges_ReturnsEveryEdge(t *testing.T) {
	g := New()
	g.AddEdge(Edge{From: "A", To: "B", Kind: EdgeSMB})
	g.AddEdge(Edge{From: "B", To: "C", Kind: EdgeWinRM})
	g.AddEdge(Edge{From: "A", To: "C", Kind: EdgeRDP})

	got := g.Edges()
	if len(got) != 3 {
		t.Fatalf("Edges() returned %d edges, want 3", len(got))
	}
	if len(got) != g.EdgeCount() {
		t.Errorf("Edges() length %d disagrees with EdgeCount() %d", len(got), g.EdgeCount())
	}
	seen := map[EdgeKind]bool{}
	for _, e := range got {
		seen[e.Kind] = true
	}
	for _, want := range []EdgeKind{EdgeSMB, EdgeWinRM, EdgeRDP} {
		if !seen[want] {
			t.Errorf("Edges() missing an edge of kind %q", want)
		}
	}
}

func TestGraphEdges_EmptyGraphReturnsNothing(t *testing.T) {
	g := New()
	if got := g.Edges(); len(got) != 0 {
		t.Errorf("Edges() on an empty graph = %d edges, want 0", len(got))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/attackpath/ -run TestGraphEdges -v`
Expected: FAIL — `g.Edges undefined (type *Graph has no field or method Edges)`.

- [ ] **Step 3: Write the implementation**

In `orchestrator/internal/attackpath/graph.go`, find:

```go
// NodeCount / EdgeCount are sizes.
func (g *Graph) NodeCount() int { return len(g.nodes) }
func (g *Graph) EdgeCount() int {
	n := 0
	for _, es := range g.adj {
		n += len(es)
	}
	return n
}
```

Add immediately after it:

```go

// Edges returns every edge in the graph (order unspecified). Used by
// internal/recommend to decide which ATT&CK techniques are relevant to this
// environment — adj is unexported, so there is no other way to enumerate them.
func (g *Graph) Edges() []Edge {
	out := make([]Edge, 0, g.EdgeCount())
	for _, es := range g.adj {
		out = append(out, es...)
	}
	return out
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/attackpath/ -run TestGraphEdges -v`
Expected: PASS on both tests.

- [ ] **Step 5: Run the full package suite + static checks**

Run: `cd orchestrator && gofmt -l internal/attackpath/graph.go && go build ./... && go vet ./internal/attackpath/ && go test ./internal/attackpath/`
Expected: `gofmt -l` prints nothing; build/vet exit 0; `ok github.com/audspect/bas/internal/attackpath`.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/attackpath/graph.go internal/attackpath/graph_test.go
git commit -m "feat(attackpath): add Graph.Edges() accessor"
git push
```

---

### Task 2: Export the reporting scoring functions

**Files:**
- Modify: `orchestrator/internal/reporting/insights.go:647` and `:680`
- Modify: `orchestrator/internal/reporting/engine.go:3316` and `:3332`
- Modify: `orchestrator/internal/reporting/insights_test.go:148` and `:165`

**Interfaces:**
- Produces: `reporting.ComputePriorityScore(kev bool, epssPercentile float64, actors int, verdict string) int` and `reporting.PriorityTierFor(score int) string`. Consumed by Task 4.

Rename only — zero logic change. Same rename-to-reuse precedent as SP5's `mergeActors` → `MergeActors` earlier today.

- [ ] **Step 1: Rename the two functions**

In `orchestrator/internal/reporting/insights.go`, find:

```go
// computePriorityScore derives a 0–100 composite from threat signals.
// KEV: +40; EPSS percentile ≥90: +30, ≥70: +20, ≥50: +10, ≥30: +5;
// ThreatActors ≥5: +20, ≥2: +10, ≥1: +5; Verdict==fail: +10 bonus.
func computePriorityScore(kev bool, epssPercentile float64, actors int, verdict string) int {
```

Replace with:

```go
// ComputePriorityScore derives a 0–100 composite from threat signals.
// KEV: +40; EPSS percentile ≥90: +30, ≥70: +20, ≥50: +10, ≥30: +5;
// ThreatActors ≥5: +20, ≥2: +10, ≥1: +5; Verdict==fail: +10 bonus.
// Exported so internal/recommend can score never-tested techniques with the
// same weights the per-run report already uses.
func ComputePriorityScore(kev bool, epssPercentile float64, actors int, verdict string) int {
```

Then find:

```go
// priorityTierFor converts a 0–100 score to a display tier label.
func priorityTierFor(score int) string {
```

Replace with:

```go
// PriorityTierFor converts a 0–100 score to a display tier label. Exported
// alongside ComputePriorityScore so consumers get the same bands.
func PriorityTierFor(score int) string {
```

- [ ] **Step 2: Update the two call sites in `engine.go`**

In `orchestrator/internal/reporting/engine.go`, find:

```go
		score := computePriorityScore(kevCnt > 0, ep.pct, actors, verdict)
```

Replace with:

```go
		score := ComputePriorityScore(kevCnt > 0, ep.pct, actors, verdict)
```

Then find:

```go
			PriorityTier:      priorityTierFor(score),
```

Replace with:

```go
			PriorityTier:      PriorityTierFor(score),
```

- [ ] **Step 3: Update the two call sites in `insights_test.go`**

In `orchestrator/internal/reporting/insights_test.go`, find:

```go
			if got := computePriorityScore(c.kev, c.epssPercentile, c.actors, c.verdict); got != c.want {
				t.Errorf("computePriorityScore(kev=%v, epss=%.0f, actors=%d, verdict=%q) = %d, want %d",
```

Replace with:

```go
			if got := ComputePriorityScore(c.kev, c.epssPercentile, c.actors, c.verdict); got != c.want {
				t.Errorf("ComputePriorityScore(kev=%v, epss=%.0f, actors=%d, verdict=%q) = %d, want %d",
```

Then find:

```go
		if got := priorityTierFor(c.score); got != c.want {
			t.Errorf("priorityTierFor(%d) = %q, want %q", c.score, got, c.want)
```

Replace with:

```go
		if got := PriorityTierFor(c.score); got != c.want {
			t.Errorf("PriorityTierFor(%d) = %q, want %q", c.score, got, c.want)
```

- [ ] **Step 4: Verify no stale references remain**

Run: `cd orchestrator && grep -rn "computePriorityScore\|priorityTierFor" internal/ ; echo "exit=$?"`
Expected: no matches (grep exits 1). Any hit is a missed call site — fix it before continuing.

- [ ] **Step 5: Build and run the reporting suite**

Run: `cd orchestrator && gofmt -l internal/reporting/insights.go internal/reporting/engine.go internal/reporting/insights_test.go && go build ./... && go test ./internal/reporting/`
Expected: `gofmt -l` prints nothing; build exits 0; `ok github.com/audspect/bas/internal/reporting`. The existing assertions are unchanged — this is a rename, so a failure here means a real mistake.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/reporting/insights.go internal/reporting/engine.go internal/reporting/insights_test.go
git commit -m "refactor(reporting): export ComputePriorityScore and PriorityTierFor"
git push
```

---

### Task 3: `internal/recommend` types + pure scoring

**Files:**
- Create: `orchestrator/internal/recommend/types.go`
- Create: `orchestrator/internal/recommend/score.go`
- Create: `orchestrator/internal/recommend/score_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks (pure).
- Produces: `Recommendations`, `RecommendedTechnique`, `SuggestedScenario` types; `CoverageGap(lastTested *time.Time, now time.Time) int`; `CoverageStateFor(lastTested *time.Time, now time.Time) string`; `EnvironmentRisk(inGraph, onCriticalPath, targetsCritical bool) int`; `RecommendationScore(threatPriority, coverageGap, environmentRisk int) int`. All consumed by Task 4.

**Note:** these tests run WITHOUT Docker. Task 4 adds a package-level `TestMain` that gates the whole package behind a container — the same thing that surprised us in `internal/exposure` during SP6. Expected and accepted (it is the house pattern), but it means after Task 4 these pure tests also need Docker running.

- [ ] **Step 1: Write the types**

Create `orchestrator/internal/recommend/types.go`:

```go
// Package recommend is the Phase 6 recommendation engine: it ranks
// ART-testable ATT&CK techniques by how much value testing them next would
// add, combining threat priority (internal/reporting's shipped scoring), how
// long since the fleet last tested them (scenario_runs), and how relevant
// they are to this specific environment (the SP3 attack-path graph + SP6
// asset criticality). Pure consumer — owns no DB tables.
package recommend

import "time"

// SuggestedScenario mirrors the shape /api/ti/suggest-pack already emits, so
// the existing scenario-creation flow consumes it unchanged.
type SuggestedScenario struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	ARTTechniques []string `json:"artTechniques"`
}

// RecommendedTechnique is one ranked technique plus the evidence behind its
// rank. Score is the composite; the three term fields are exposed so an
// operator can see WHY something ranked where it did.
type RecommendedTechnique struct {
	TechniqueID string `json:"techniqueId"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`

	Score int    `json:"score"` // 0-100 composite
	Tier  string `json:"tier"`  // Critical | High | Medium | Low

	CoverageState string     `json:"coverageState"` // never-tested | stale | recent
	LastTestedAt  *time.Time `json:"lastTestedAt,omitempty"`
	LastVerdict   string     `json:"lastVerdict,omitempty"`

	ThreatPriority  int `json:"threatPriority"`
	CoverageGap     int `json:"coverageGap"`
	EnvironmentRisk int `json:"environmentRisk"`

	KEV            bool     `json:"kev"`
	EPSSPercentile float64  `json:"epssPercentile,omitempty"`
	ThreatActors   int      `json:"threatActors"`
	Reasons        []string `json:"reasons"`
}

// Recommendations is one Build() result. Techniques is always non-nil (an
// empty slice, not null) so the UI can iterate without a guard.
type Recommendations struct {
	Techniques        []RecommendedTechnique `json:"techniques"`
	SuggestedScenario SuggestedScenario      `json:"suggestedScenario"`
	HasData           bool                   `json:"hasData"`
}
```

- [ ] **Step 2: Write the failing scoring tests**

Create `orchestrator/internal/recommend/score_test.go`:

```go
package recommend

import (
	"testing"
	"time"
)

var scoreNow = time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

func daysAgo(d int) *time.Time {
	t := scoreNow.AddDate(0, 0, -d)
	return &t
}

func TestCoverageGap_Bands(t *testing.T) {
	cases := []struct {
		name       string
		lastTested *time.Time
		want       int
	}{
		{"never tested", nil, 100},
		{"120 days — stale", daysAgo(120), 60},
		{"91 days — just over the stale line", daysAgo(91), 60},
		{"60 days — mid band", daysAgo(60), 30},
		{"31 days — just over the recent line", daysAgo(31), 30},
		{"10 days — recent", daysAgo(10), 0},
		{"today", daysAgo(0), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CoverageGap(c.lastTested, scoreNow); got != c.want {
				t.Errorf("CoverageGap(%v) = %d, want %d", c.lastTested, got, c.want)
			}
		})
	}
}

func TestCoverageStateFor_Labels(t *testing.T) {
	cases := []struct {
		lastTested *time.Time
		want       string
	}{
		{nil, "never-tested"},
		{daysAgo(120), "stale"},
		{daysAgo(60), "recent"},
		{daysAgo(1), "recent"},
	}
	for _, c := range cases {
		if got := CoverageStateFor(c.lastTested, scoreNow); got != c.want {
			t.Errorf("CoverageStateFor(%v) = %q, want %q", c.lastTested, got, c.want)
		}
	}
}

func TestEnvironmentRisk_Tiers(t *testing.T) {
	cases := []struct {
		name                                  string
		inGraph, onCriticalPath, targetsCrit  bool
		want                                  int
	}{
		{"not in the graph at all", false, false, false, 0},
		{"not in graph — critical target is ignored", false, false, true, 0},
		{"in the graph, off the critical paths", true, false, false, 50},
		{"in the graph, targets a critical asset", true, false, true, 70},
		{"on a critical path", true, true, false, 100},
		{"on a critical path AND targets critical — clamps at 100", true, true, true, 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EnvironmentRisk(c.inGraph, c.onCriticalPath, c.targetsCrit); got != c.want {
				t.Errorf("EnvironmentRisk(inGraph=%v, path=%v, crit=%v) = %d, want %d",
					c.inGraph, c.onCriticalPath, c.targetsCrit, got, c.want)
			}
		})
	}
}

// TestRecommendationScore_Weights pins the 0.50/0.30/0.20 split from the spec.
func TestRecommendationScore_Weights(t *testing.T) {
	cases := []struct {
		name                     string
		threat, coverage, env    int
		want                     int
	}{
		{"all zero", 0, 0, 0, 0},
		{"all max", 100, 100, 100, 100},
		{"threat only", 100, 0, 0, 50},
		{"coverage only", 0, 100, 0, 30},
		{"environment only", 0, 0, 100, 20},
		{"never-tested KEV on a critical path", 70, 100, 100, 85}, // 35 + 30 + 20
		{"rounds to nearest", 33, 33, 33, 33},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RecommendationScore(c.threat, c.coverage, c.env); got != c.want {
				t.Errorf("RecommendationScore(%d, %d, %d) = %d, want %d",
					c.threat, c.coverage, c.env, got, c.want)
			}
		})
	}
}

// TestRecommendationScore_RecentFailingDoesNotDominate pins the spec's
// Decision 5: a recently-tested FAILING technique carries ComputePriorityScore's
// +10 fail bonus, but CoverageGap=0 must keep it below a never-tested technique
// with otherwise identical signals. You already know it fails — re-running it
// teaches nothing until it is remediated, and the ITSM revalidation loop
// re-tests on ticket-resolve. It is a remediation item, not a testing gap.
func TestRecommendationScore_RecentFailingDoesNotDominate(t *testing.T) {
	// Same underlying threat signals; the failing one even scores 10 higher on
	// threat priority thanks to the fail bonus.
	recentFailing := RecommendationScore(60, CoverageGap(daysAgo(5), scoreNow), 50)
	neverTested := RecommendationScore(50, CoverageGap(nil, scoreNow), 50)

	if neverTested <= recentFailing {
		t.Errorf("never-tested (%d) should outrank recently-tested-failing (%d)", neverTested, recentFailing)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/recommend/ -v`
Expected: FAIL — `undefined: CoverageGap`, `undefined: CoverageStateFor`, `undefined: EnvironmentRisk`, `undefined: RecommendationScore`.

- [ ] **Step 4: Write the scoring implementation**

Create `orchestrator/internal/recommend/score.go`:

```go
package recommend

import (
	"fmt"
	"math"
	"time"
)

// Coverage-age band boundaries. Evaluated top-down in CoverageGap so the
// boundaries are unambiguous (see the spec's Scoring section).
const (
	staleAfter  = 90 * 24 * time.Hour
	recentAfter = 30 * 24 * time.Hour
)

// Composite weights — must sum to 1.0. See the spec's Scoring section.
const (
	wThreat      = 0.50
	wCoverage    = 0.30
	wEnvironment = 0.20
)

func clamp100(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// CoverageGap scores 0-100 on how overdue a technique is for testing: never
// tested is the maximum gap, a test in the last 30 days is no gap at all.
func CoverageGap(lastTested *time.Time, now time.Time) int {
	if lastTested == nil {
		return 100
	}
	age := now.Sub(*lastTested)
	switch {
	case age > staleAfter:
		return 60
	case age > recentAfter:
		return 30
	default:
		return 0
	}
}

// CoverageStateFor is the display label matching CoverageGap's bands.
func CoverageStateFor(lastTested *time.Time, now time.Time) string {
	if lastTested == nil {
		return "never-tested"
	}
	if now.Sub(*lastTested) > staleAfter {
		return "stale"
	}
	return "recent"
}

// EnvironmentRisk scores 0-100 on how relevant a technique is to THIS
// environment: 0 when it maps to no edge in the collected graph (never
// fabricate relevance we have no signal for), 50 when it traverses some real
// edge, 100 when that edge sits on a domain-compromise or crown-jewel path,
// +20 when the edge's target carries a critical/high SP6 criticality tier.
func EnvironmentRisk(inGraph, onCriticalPath, targetsCritical bool) int {
	if !inGraph && !onCriticalPath {
		return 0
	}
	risk := 50
	if onCriticalPath {
		risk = 100
	}
	if targetsCritical {
		risk += 20
	}
	return clamp100(risk)
}

// RecommendationScore is the composite: 0.50×threat + 0.30×coverage + 0.20×env.
func RecommendationScore(threatPriority, coverageGap, environmentRisk int) int {
	s := wThreat*float64(clamp100(threatPriority)) +
		wCoverage*float64(clamp100(coverageGap)) +
		wEnvironment*float64(clamp100(environmentRisk))
	return clamp100(int(math.Round(s)))
}

// buildReasons explains a rank in plain language, strongest signal first.
// Never invents a reason it has no data for.
func buildReasons(t RecommendedTechnique, now time.Time) []string {
	var out []string
	switch t.CoverageState {
	case "never-tested":
		out = append(out, "Never tested on this fleet")
	case "stale":
		if t.LastTestedAt != nil {
			out = append(out, fmt.Sprintf("Last tested %d days ago", int(now.Sub(*t.LastTestedAt).Hours()/24)))
		}
	}
	if t.KEV {
		out = append(out, "Linked to a CISA KEV catalog CVE")
	}
	if t.EPSSPercentile >= 90 {
		out = append(out, fmt.Sprintf("EPSS percentile %.0f — top-decile exploitation likelihood", t.EPSSPercentile))
	} else if t.EPSSPercentile >= 70 {
		out = append(out, fmt.Sprintf("EPSS percentile %.0f", t.EPSSPercentile))
	}
	if t.ThreatActors >= 5 {
		out = append(out, fmt.Sprintf("Attributed to %d ATT&CK groups", t.ThreatActors))
	} else if t.ThreatActors >= 1 {
		out = append(out, fmt.Sprintf("Attributed to %d ATT&CK group(s)", t.ThreatActors))
	}
	switch {
	case t.EnvironmentRisk >= 100:
		out = append(out, "Traverses an edge on a domain-compromise or crown-jewel path in your environment")
	case t.EnvironmentRisk >= 70:
		out = append(out, "Traverses an edge targeting a high-criticality asset in your environment")
	case t.EnvironmentRisk > 0:
		out = append(out, "Traverses a real edge in your collected attack-path graph")
	}
	if t.LastVerdict == "fail" {
		out = append(out, "Previously failed — remediate before re-testing")
	}
	return out
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/recommend/ -v`
Expected: PASS on all 5 tests (no Docker needed yet).

- [ ] **Step 6: Static checks**

Run: `cd orchestrator && gofmt -l internal/recommend/ && go build ./... && go vet ./internal/recommend/`
Expected: `gofmt -l` prints nothing; build/vet exit 0.

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/recommend/
git commit -m "feat(recommend): add recommendation types and pure scoring"
git push
```

---

### Task 4: `internal/recommend.Build` + SQL loaders

**Files:**
- Create: `orchestrator/internal/recommend/recommend.go`
- Create: `orchestrator/internal/recommend/recommend_test.go`

**Interfaces:**
- Consumes: `attackpath.Graph.Edges()` (Task 1); `reporting.ComputePriorityScore` / `reporting.PriorityTierFor` (Task 2); the types and scoring from Task 3; `attackpath.BuildGraphAndAnalyze(cols, tags) (*Graph, Summary)`; `pathcorrelation.DefaultPaths(g, s) []AttackPath` (field `.Edges []attackpath.Edge`); `pathcorrelation.DefaultEdgeTechniqueMapper{}.Techniques(kind) []TechniqueMapping` (field `.TechniqueID`); `attackdata.GroupTechniqueIndex() map[string][]string`.
- Produces: `func Build(ctx context.Context, pool *pgxpool.Pool, g *attackpath.Graph, s attackpath.Summary, limit int) (Recommendations, error)`. Consumed by Task 5.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/recommend/recommend_test.go`:

```go
package recommend

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
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

// seedTechnique inserts a technique plus one ART atomic test for it, making it
// part of the executable universe Build() ranks over.
func seedTechnique(t *testing.T, pool *pgxpool.Pool, id, name, tactic string) {
	t.Helper()
	mustExec(t, pool, `INSERT INTO techniques (technique_id, name, tactic) VALUES ($1, $2, $3)`, id, name, tactic)
	mustExec(t, pool, `
		INSERT INTO art_atomic_tests (technique_id, test_index, name, executor, command)
		VALUES ($1, 1, 'atomic', 'powershell', 'whoami')`, id)
}

// seedKEV links a technique to a KEV-listed CVE through the Relationship Store,
// at the Active/High confidence the engine's queries require.
// relationship_type is NOT NULL with no default — 'Commonly Associated' is the
// value content_import.go's own migration uses.
func seedKEV(t *testing.T, pool *pgxpool.Pool, techID, cveID string) {
	t.Helper()
	mustExec(t, pool, `INSERT INTO cves (cve_id, cvss, source) VALUES ($1, 9.8, 'cisa-kev')`, cveID)
	mustExec(t, pool, `
		INSERT INTO technique_cve_relationships
			(technique_id, cve_id, relationship_type, status, effective_confidence)
		VALUES ($1, $2, 'Commonly Associated', 'Active', 'High')`, techID, cveID)
}

func findTech(recs Recommendations, id string) (RecommendedTechnique, bool) {
	for _, t := range recs.Techniques {
		if t.TechniqueID == id {
			return t, true
		}
	}
	return RecommendedTechnique{}, false
}

func rankOf(recs Recommendations, id string) int {
	for i, t := range recs.Techniques {
		if t.TechniqueID == id {
			return i
		}
	}
	return -1
}

func TestBuild_EmptyUniverse_ReturnsEmptyNotError(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 20)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if len(recs.Techniques) != 0 {
			t.Errorf("Techniques = %d, want 0 with no seeded content", len(recs.Techniques))
		}
		if recs.Techniques == nil {
			t.Error("Techniques must be an empty slice, not nil — the UI iterates it without a guard")
		}
		if recs.HasData {
			t.Error("HasData = true, want false with no seeded content")
		}
	})
}

// TestBuild_OnlyARTTestableTechniquesAreRanked pins the executable filter:
// recommending a technique with no atomic test to run is noise.
func TestBuild_OnlyARTTestableTechniquesAreRanked(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechnique(t, pool, "T1059.001", "PowerShell", "execution")
		// Seeded technique with NO art_atomic_tests row — must not be ranked.
		mustExec(t, pool, `INSERT INTO techniques (technique_id, name, tactic) VALUES ('T1136.001', 'Local Account', 'persistence')`)

		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 20)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if _, ok := findTech(recs, "T1059.001"); !ok {
			t.Error("expected the ART-testable technique to be ranked")
		}
		if _, ok := findTech(recs, "T1136.001"); ok {
			t.Error("technique with no ART atomic test must not be ranked")
		}
	})
}

// TestBuild_KEVOutranksNoSignal: two never-tested techniques, identical except
// one is KEV-listed. The KEV one must rank first.
func TestBuild_KEVOutranksNoSignal(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechnique(t, pool, "T1003.001", "LSASS Memory", "credential-access")
		seedTechnique(t, pool, "T1217", "Browser Bookmark Discovery", "discovery")
		seedKEV(t, pool, "T1003.001", "CVE-2024-0001")

		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 20)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		kevRank, plainRank := rankOf(recs, "T1003.001"), rankOf(recs, "T1217")
		if kevRank == -1 || plainRank == -1 {
			t.Fatalf("both techniques should be ranked; got kev=%d plain=%d", kevRank, plainRank)
		}
		if kevRank >= plainRank {
			t.Errorf("KEV-listed technique ranked %d, should outrank the no-signal one at %d", kevRank, plainRank)
		}
		kev, _ := findTech(recs, "T1003.001")
		if !kev.KEV {
			t.Error("KEV flag not surfaced on the recommendation")
		}
	})
}

// TestBuild_NeverTestedOutranksRecentlyTested: identical threat signals, but one
// was tested today. The untested one must rank first.
func TestBuild_NeverTestedOutranksRecentlyTested(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechnique(t, pool, "T1003.001", "LSASS Memory", "credential-access")
		seedTechnique(t, pool, "T1055", "Process Injection", "defense-evasion")
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, results, completed_at)
			VALUES ('s1', 'a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1055","name":"Process Injection","tactic":"defense-evasion"},
			   "result":"pass","executedAt":"2026-07-17T10:00:00Z"}]`)

		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 20)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if rankOf(recs, "T1003.001") >= rankOf(recs, "T1055") {
			t.Errorf("never-tested T1003.001 (rank %d) should outrank recently-tested T1055 (rank %d)",
				rankOf(recs, "T1003.001"), rankOf(recs, "T1055"))
		}
		tested, _ := findTech(recs, "T1055")
		if tested.CoverageState != "recent" {
			t.Errorf("CoverageState = %q, want %q", tested.CoverageState, "recent")
		}
		if tested.LastTestedAt == nil {
			t.Error("LastTestedAt should be populated for a tested technique")
		}
		if tested.LastVerdict != "pass" {
			t.Errorf("LastVerdict = %q, want %q", tested.LastVerdict, "pass")
		}
	})
}

// TestBuild_ErroredRunsCountAsNeverTested pins the 4-verdict taxonomy: an
// ERROR means the BAS could not execute the technique, so it tells us nothing
// about coverage and must not suppress the recommendation.
func TestBuild_ErroredRunsCountAsNeverTested(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechnique(t, pool, "T1055", "Process Injection", "defense-evasion")
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, results, completed_at)
			VALUES ('s1', 'a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1055","name":"Process Injection","tactic":"defense-evasion"},
			   "result":"error","executedAt":"2026-07-17T10:00:00Z"}]`)

		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 20)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		got, ok := findTech(recs, "T1055")
		if !ok {
			t.Fatal("errored technique should still be ranked")
		}
		if got.CoverageState != "never-tested" {
			t.Errorf("CoverageState = %q, want never-tested (an ERROR is not a real test)", got.CoverageState)
		}
	})
}

// TestBuild_EnvironmentRelevanceRaisesRank: identical never-tested techniques
// with no threat signal, but T1021.002 (SMB) traverses a real edge in the
// collected graph. It must outrank the environment-irrelevant one.
func TestBuild_EnvironmentRelevanceRaisesRank(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechnique(t, pool, "T1021.002", "SMB/Windows Admin Shares", "lateral-movement")
		seedTechnique(t, pool, "T1217", "Browser Bookmark Discovery", "discovery")

		// A two-host graph with a real SMB edge. DefaultEdgeTechniqueMapper maps
		// EdgeSMB -> T1021.002, so only that technique gets environment signal.
		// AddEdge auto-creates both endpoints as bare host nodes.
		g := attackpath.New()
		g.AddEdge(attackpath.Edge{From: "HOST-A", To: "HOST-B", Kind: attackpath.EdgeSMB})

		recs, err := Build(context.Background(), pool, g, attackpath.Summary{}, 20)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if rankOf(recs, "T1021.002") >= rankOf(recs, "T1217") {
			t.Errorf("environment-relevant T1021.002 (rank %d) should outrank irrelevant T1217 (rank %d)",
				rankOf(recs, "T1021.002"), rankOf(recs, "T1217"))
		}
		smb, _ := findTech(recs, "T1021.002")
		if smb.EnvironmentRisk == 0 {
			t.Error("EnvironmentRisk should be non-zero for a technique traversing a real graph edge")
		}
		other, _ := findTech(recs, "T1217")
		if other.EnvironmentRisk != 0 {
			t.Errorf("EnvironmentRisk = %d for a technique with no graph edge, want 0 (never fabricate relevance)", other.EnvironmentRisk)
		}
	})
}

// TestBuild_SuggestedScenarioCarriesTopN pins the runnable-output contract.
func TestBuild_SuggestedScenarioCarriesTopN(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechnique(t, pool, "T1003.001", "LSASS Memory", "credential-access")
		seedTechnique(t, pool, "T1055", "Process Injection", "defense-evasion")
		seedTechnique(t, pool, "T1217", "Browser Bookmark Discovery", "discovery")
		seedKEV(t, pool, "T1003.001", "CVE-2024-0001")

		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 2)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if len(recs.Techniques) != 2 {
			t.Fatalf("limit=2 returned %d techniques, want 2", len(recs.Techniques))
		}
		if len(recs.SuggestedScenario.ARTTechniques) != 2 {
			t.Fatalf("SuggestedScenario has %d techniques, want 2", len(recs.SuggestedScenario.ARTTechniques))
		}
		for i, want := range []string{recs.Techniques[0].TechniqueID, recs.Techniques[1].TechniqueID} {
			if recs.SuggestedScenario.ARTTechniques[i] != want {
				t.Errorf("SuggestedScenario.ARTTechniques[%d] = %q, want %q (must mirror the ranked order)",
					i, recs.SuggestedScenario.ARTTechniques[i], want)
			}
		}
		if recs.SuggestedScenario.ID == "" || recs.SuggestedScenario.Name == "" {
			t.Error("SuggestedScenario needs an ID and Name for the scenario-creation flow")
		}
		if !recs.HasData {
			t.Error("HasData = false with seeded content, want true")
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/recommend/ -run TestBuild -v`
Expected: FAIL — `undefined: Build`.

- [ ] **Step 3: Write the implementation**

Create `orchestrator/internal/recommend/recommend.go`:

```go
package recommend

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

const defaultLimit = 20

// techRow is one entry in the executable universe.
type techRow struct {
	id     string
	name   string
	tactic string
}

// coverageRow is the fleet's most recent real test of a technique.
type coverageRow struct {
	lastTested time.Time
	verdict    string
}

// Build ranks the ART-testable ATT&CK techniques by how much value testing
// them next would add, and emits a runnable SuggestedScenario from the top N.
//
// The caller builds the graph (same "caller builds it once" convention as
// exposure.Build) — pass a nil graph when no attack-path collection has run
// and every technique simply scores 0 on environment relevance, rather than
// having relevance fabricated for it.
//
// Nil-safe: unseeded content returns an empty Recommendations, never an error.
func Build(ctx context.Context, pool *pgxpool.Pool, g *attackpath.Graph, s attackpath.Summary, limit int) (Recommendations, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	empty := Recommendations{Techniques: []RecommendedTechnique{}}

	universe, err := loadExecutableTechniques(ctx, pool)
	if err != nil {
		return Recommendations{}, err
	}
	if len(universe) == 0 {
		return empty, nil
	}

	coverage, err := loadCoverage(ctx, pool)
	if err != nil {
		return Recommendations{}, err
	}
	kev, err := loadKEVTechniques(ctx, pool)
	if err != nil {
		return Recommendations{}, err
	}
	epss, err := loadEPSSPercentiles(ctx, pool)
	if err != nil {
		return Recommendations{}, err
	}
	actors := actorCounts()
	env := buildEnvIndex(g, s, pathcorrelation.DefaultEdgeTechniqueMapper{})

	now := time.Now().UTC()
	out := make([]RecommendedTechnique, 0, len(universe))
	for _, u := range universe {
		key := strings.ToUpper(u.id)

		var lastTested *time.Time
		verdict := ""
		if c, ok := coverage[key]; ok {
			lt := c.lastTested
			lastTested = &lt
			verdict = c.verdict
		}

		t := RecommendedTechnique{
			TechniqueID:    u.id,
			Name:           u.name,
			Tactic:         u.tactic,
			CoverageState:  CoverageStateFor(lastTested, now),
			LastTestedAt:   lastTested,
			LastVerdict:    verdict,
			KEV:            kev[key],
			EPSSPercentile: epss[key],
			ThreatActors:   actors[key],
		}
		t.ThreatPriority = reporting.ComputePriorityScore(t.KEV, t.EPSSPercentile, t.ThreatActors, verdict)
		t.CoverageGap = CoverageGap(lastTested, now)
		t.EnvironmentRisk = EnvironmentRisk(env.inGraph[key], env.onCriticalPath[key], env.targetsCritical[key])
		t.Score = RecommendationScore(t.ThreatPriority, t.CoverageGap, t.EnvironmentRisk)
		t.Tier = reporting.PriorityTierFor(t.Score)
		t.Reasons = buildReasons(t, now)
		out = append(out, t)
	}

	// Score desc, then technique ID asc so the ranking is deterministic.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].TechniqueID < out[j].TechniqueID
	})
	if len(out) > limit {
		out = out[:limit]
	}

	ids := make([]string, len(out))
	for i, t := range out {
		ids[i] = t.TechniqueID
	}
	day := now.Format("2006-01-02")
	return Recommendations{
		Techniques: out,
		HasData:    len(out) > 0,
		SuggestedScenario: SuggestedScenario{
			ID:            "recommended-" + now.Format("20060102"),
			Name:          fmt.Sprintf("Recommended Next Simulations — %s", day),
			Description:   "Auto-ranked by threat priority, coverage gap, and environment relevance.",
			ARTTechniques: ids,
		},
	}, nil
}

// loadExecutableTechniques is the universe: every seeded technique that has at
// least one ART atomic test to actually run. Recommending something with no
// test attached would be noise.
func loadExecutableTechniques(ctx context.Context, pool *pgxpool.Pool) ([]techRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT t.technique_id, t.name, t.tactic
		FROM techniques t
		WHERE EXISTS (SELECT 1 FROM art_atomic_tests a WHERE a.technique_id = t.technique_id)
		ORDER BY t.technique_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []techRow
	for rows.Next() {
		var r techRow
		if rows.Scan(&r.id, &r.name, &r.tactic) == nil {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// loadCoverage returns each technique's most recent REAL test across the whole
// fleet. ERROR and SKIPPED are excluded deliberately: per the project's
// 4-verdict taxonomy they mean the BAS could not execute the technique, so
// they say nothing about coverage and must not suppress a recommendation.
func loadCoverage(ctx context.Context, pool *pgxpool.Pool) (map[string]coverageRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (UPPER(r->'technique'->>'id'))
		       UPPER(r->'technique'->>'id')      AS tid,
		       (r->>'executedAt')::timestamptz   AS last_tested,
		       r->>'result'                      AS verdict
		FROM scenario_runs sr, jsonb_array_elements(sr.results) r
		WHERE sr.status IN ('completed', 'partial')
		  AND r->'technique'->>'id' IS NOT NULL
		  AND r->'technique'->>'id' <> ''
		  AND r->>'executedAt' IS NOT NULL
		  AND r->>'result' NOT IN ('error', 'skipped')
		ORDER BY UPPER(r->'technique'->>'id'), (r->>'executedAt')::timestamptz DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]coverageRow{}
	for rows.Next() {
		var tid string
		var c coverageRow
		if rows.Scan(&tid, &c.lastTested, &c.verdict) == nil {
			out[tid] = c
		}
	}
	return out, rows.Err()
}

// loadKEVTechniques marks techniques linked to a CISA KEV CVE. Gated on the
// Relationship Store's Active + High/Medium confidence contract — the same
// gating reporting.populatePriorityScores uses. Never reads bare technique_cves.
func loadKEVTechniques(ctx context.Context, pool *pgxpool.Pool) (map[string]bool, error) {
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT tc.technique_id
		FROM technique_cve_relationships tc
		JOIN cves c ON c.cve_id = tc.cve_id AND c.source = 'cisa-kev'
		WHERE tc.status = 'Active' AND tc.effective_confidence IN ('High', 'Medium')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var tid string
		if rows.Scan(&tid) == nil {
			out[strings.ToUpper(tid)] = true
		}
	}
	return out, rows.Err()
}

// loadEPSSPercentiles returns the highest EPSS percentile (0-100) among each
// technique's scored CVE relationships. Same ×100 convention as
// reporting.populatePriorityScores.
func loadEPSSPercentiles(ctx context.Context, pool *pgxpool.Pool) (map[string]float64, error) {
	rows, err := pool.Query(ctx, `
		SELECT tc.technique_id, MAX(ce.percentile)
		FROM technique_cve_relationships tc
		JOIN cve_epss ce ON ce.cve_id = tc.cve_id
		WHERE tc.status = 'Active' AND tc.effective_confidence IN ('High', 'Medium')
		GROUP BY tc.technique_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var tid string
		var pct float64
		if rows.Scan(&tid, &pct) == nil {
			out[strings.ToUpper(tid)] = pct * 100
		}
	}
	return out, rows.Err()
}

// actorCounts inverts the bundled ATT&CK STIX group index into
// technique -> number of attributed groups. Always available (embedded), so
// threat priority degrades to this alone when the Relationship Store is empty.
func actorCounts() map[string]int {
	out := map[string]int{}
	for _, techIDs := range attackdata.GroupTechniqueIndex() {
		for _, tid := range techIDs {
			out[strings.ToUpper(tid)]++
		}
	}
	return out
}

// envIndex answers, per technique: does it traverse a real edge, is that edge
// on a domain-compromise/crown-jewel path, and does it target a high-criticality
// asset.
type envIndex struct {
	inGraph         map[string]bool
	onCriticalPath  map[string]bool
	targetsCritical map[string]bool
}

func buildEnvIndex(g *attackpath.Graph, s attackpath.Summary, mapper pathcorrelation.EdgeTechniqueMapper) envIndex {
	idx := envIndex{
		inGraph:         map[string]bool{},
		onCriticalPath:  map[string]bool{},
		targetsCritical: map[string]bool{},
	}
	if g == nil {
		return idx
	}
	mark := func(e attackpath.Edge, critical bool) {
		targetsCrit := false
		if n, ok := g.Node(e.To); ok {
			targetsCrit = n.CriticalityTier == "critical" || n.CriticalityTier == "high"
		}
		for _, tm := range mapper.Techniques(e.Kind) {
			tid := strings.ToUpper(tm.TechniqueID)
			idx.inGraph[tid] = true
			if critical {
				idx.onCriticalPath[tid] = true
			}
			if targetsCrit {
				idx.targetsCritical[tid] = true
			}
		}
	}
	for _, e := range g.Edges() {
		mark(e, false)
	}
	for _, p := range pathcorrelation.DefaultPaths(g, s) {
		for _, e := range p.Edges {
			mark(e, true)
		}
	}
	return idx
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/recommend/ -v`
Expected: PASS on all tests (the 5 pure ones from Task 3 plus the 7 new Docker-backed ones). Requires Docker Desktop running.

- [ ] **Step 5: Static checks**

Run: `cd orchestrator && gofmt -l internal/recommend/ && go build ./... && go vet ./internal/recommend/`
Expected: `gofmt -l` prints nothing; build/vet exit 0.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/recommend/
git commit -m "feat(recommend): add Build with coverage, threat, and environment scoring"
git push
```

---

### Task 5: API endpoint

**Files:**
- Create: `orchestrator/internal/api/recommend_handlers.go`
- Create: `orchestrator/internal/api/recommend_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go:184` (after the dashboard routes)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:102` (after the dashboard entries)

**Interfaces:**
- Consumes: `recommend.Build(ctx, pool, g, s, limit)` (Task 4); the Handler's existing `h.loadAttackPathCollections(r)` and `h.loadAssetTags(r)` (`attackpath_handlers.go:135,156`); `attackpath.BuildGraphAndAnalyze`; `respond` / `jsonError` (`handlers.go:2168,2208`).
- Produces: `GET /api/recommend/simulations?limit=N`, Viewer+.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/recommend_handlers_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func recommendHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

type recommendResp struct {
	Techniques []struct {
		TechniqueID   string `json:"techniqueId"`
		Score         int    `json:"score"`
		CoverageState string `json:"coverageState"`
	} `json:"techniques"`
	SuggestedScenario struct {
		ID            string   `json:"id"`
		ARTTechniques []string `json:"artTechniques"`
	} `json:"suggestedScenario"`
	HasData bool `json:"hasData"`
}

func TestGetRecommendedSimulations_EmptyContent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := recommendHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetRecommendedSimulations(rec, httptest.NewRequest(http.MethodGet, "/api/recommend/simulations", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out recommendResp
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(out.Techniques) != 0 || out.HasData {
			t.Errorf("out = %+v, want no techniques and hasData=false on unseeded content", out)
		}
	})
}

func TestGetRecommendedSimulations_RanksAndClampsLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		for _, tech := range [][3]string{
			{"T1003.001", "LSASS Memory", "credential-access"},
			{"T1055", "Process Injection", "defense-evasion"},
			{"T1217", "Browser Bookmark Discovery", "discovery"},
		} {
			mustExecAPI(t, pool, `INSERT INTO techniques (technique_id, name, tactic) VALUES ($1, $2, $3)`,
				tech[0], tech[1], tech[2])
			mustExecAPI(t, pool, `
				INSERT INTO art_atomic_tests (technique_id, test_index, name, executor, command)
				VALUES ($1, 1, 'atomic', 'powershell', 'whoami')`, tech[0])
		}

		h := recommendHandler(t, pool)

		// limit=2 is respected.
		rec := httptest.NewRecorder()
		h.GetRecommendedSimulations(rec, httptest.NewRequest(http.MethodGet, "/api/recommend/simulations?limit=2", nil))
		var out recommendResp
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Techniques) != 2 {
			t.Fatalf("limit=2 returned %d techniques, want 2", len(out.Techniques))
		}
		if len(out.SuggestedScenario.ARTTechniques) != 2 {
			t.Errorf("suggestedScenario carried %d techniques, want 2", len(out.SuggestedScenario.ARTTechniques))
		}
		if !out.HasData {
			t.Error("hasData = false with seeded content, want true")
		}

		// An out-of-range limit falls back to the default rather than erroring.
		rec2 := httptest.NewRecorder()
		h.GetRecommendedSimulations(rec2, httptest.NewRequest(http.MethodGet, "/api/recommend/simulations?limit=99999", nil))
		if rec2.Code != http.StatusOK {
			t.Fatalf("limit=99999: status = %d, want 200", rec2.Code)
		}
		var out2 recommendResp
		json.Unmarshal(rec2.Body.Bytes(), &out2)
		if len(out2.Techniques) != 3 {
			t.Errorf("limit=99999 returned %d techniques, want all 3 (clamped, not errored)", len(out2.Techniques))
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/ -run TestGetRecommendedSimulations -v`
Expected: FAIL — `h.GetRecommendedSimulations undefined`.

- [ ] **Step 3: Write the handler**

Create `orchestrator/internal/api/recommend_handlers.go`:

```go
package api

import (
	"net/http"
	"strconv"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/recommend"
)

// GetRecommendedSimulations ranks the ART-testable ATT&CK techniques by how
// much value testing them next would add — Phase 6. Read-only (Viewer+).
// Query params: limit (default 20, clamped to [1,100]).
// GET /api/recommend/simulations
func (h *Handler) GetRecommendedSimulations(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 100 {
			limit = n
		}
	}

	// Same "caller builds the graph once" convention as the exposure handlers —
	// reuses the Handler's existing loaders rather than duplicating them inside
	// internal/recommend. A fleet with no collections yields an empty graph, and
	// every technique simply scores 0 on environment relevance.
	cols := h.loadAttackPathCollections(r)
	g, s := attackpath.BuildGraphAndAnalyze(cols, h.loadAssetTags(r))

	recs, err := recommend.Build(r.Context(), h.db, g, s, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, recs)
}
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, find:

```go
		// Executive Dashboard — Phase 6. Fleet-wide risk/exposure/detection
		// trends, read-only (Viewer+).
		r.Get("/api/dashboard/current", h.GetDashboardCurrent)
		r.Get("/api/dashboard/trends", h.GetDashboardTrends)
```

Replace with:

```go
		// Executive Dashboard — Phase 6. Fleet-wide risk/exposure/detection
		// trends, read-only (Viewer+).
		r.Get("/api/dashboard/current", h.GetDashboardCurrent)
		r.Get("/api/dashboard/trends", h.GetDashboardTrends)

		// Recommendation Engine — Phase 6. Best-next-simulation ranking,
		// read-only (Viewer+).
		r.Get("/api/recommend/simulations", h.GetRecommendedSimulations)
```

- [ ] **Step 5: Register the route in the RBAC drift matrix**

This is not optional — `TestRBACMatrix_NoDrift` fails the entire `internal/api` suite for any route missing here. It caught exactly this omission during the Executive Dashboards slice.

In `orchestrator/internal/api/rbac_matrix_test.go`, find:

```go
	{http.MethodGet, "/api/dashboard/current", tierAny, ""},
	{http.MethodGet, "/api/dashboard/trends", tierAny, ""},
```

Replace with:

```go
	{http.MethodGet, "/api/dashboard/current", tierAny, ""},
	{http.MethodGet, "/api/dashboard/trends", tierAny, ""},
	{http.MethodGet, "/api/recommend/simulations", tierAny, ""},
```

- [ ] **Step 6: Run the new tests plus the drift check**

Run: `cd orchestrator && go test ./internal/api/ -run 'TestGetRecommendedSimulations|TestRBACMatrix_NoDrift' -v`
Expected: PASS on all three.

- [ ] **Step 7: Full `internal/api` regression + static checks**

Run: `cd orchestrator && gofmt -l internal/api/recommend_handlers.go internal/api/recommend_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go && go build ./... && go vet ./... && go test ./internal/api/ ./internal/recommend/ ./internal/reporting/ ./internal/attackpath/`
Expected: `gofmt -l` prints nothing; build/vet exit 0; all four packages `ok`. The full `internal/api` suite takes ~220s.

- [ ] **Step 8: Commit**

```bash
cd orchestrator
git add internal/api/recommend_handlers.go internal/api/recommend_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(recommend): add GET /api/recommend/simulations endpoint"
git push
```

---

### Task 6: Recommendations UI tab

**Files:**
- Modify: `orchestrator/wwwroot/index.html`
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (hardlinked twin — verify, do not assume)

**Interfaces:**
- Consumes: `GET /api/recommend/simulations?limit=N` → `{techniques:[{techniqueId, name, tactic, score, tier, coverageState, lastTestedAt, lastVerdict, threatPriority, coverageGap, environmentRisk, kev, epssPercentile, threatActors, reasons[]}], suggestedScenario:{id, name, description, artTechniques[]}, hasData}`; existing `apicall(url)`, `x()` HTML-escaper, `showToast(msg, kind)`, `apColor(score)`, `.kpi-row` / `.tbl-wrap` / `.badge` / `.empty` conventions.
- Produces: nav item + tab `recommendations`; JS `loadRecommendations()`, `renderRecommendations(data)`, `recTierColor(tier)`, `recCoverageBadge(state)`, `copyRecommendedScenario()`.

The two `wwwroot/index.html` paths are one file on disk (NTFS hardlink) but two git-tracked paths whose histories have drifted before. Editing one updates both — **verify with `diff`, never assume**, and `git add` both.

- [ ] **Step 1: Confirm the two files are in sync before editing**

Run: `cd orchestrator && diff wwwroot/index.html cmd/server/wwwroot/index.html && echo IDENTICAL`
Expected: `IDENTICAL`. If they differ, stop — reconcile before editing.

- [ ] **Step 2: Add the nav item**

In `orchestrator/wwwroot/index.html`, find:

```html
        <div class="nav-item" data-tab="exec-dashboard" onclick="showTab('exec-dashboard')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M2 13.5h12M4 13.5V8M8 13.5V4M12 13.5v-6"/>
          </svg>
          Executive Dashboard
        </div>
```

Add immediately after it:

```html
        <div class="nav-item" data-tab="recommendations" onclick="showTab('recommendations')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M8 1.5l1.8 4.1 4.2.4-3.2 2.8 1 4.2L8 10.8 4.2 13l1-4.2L2 6l4.2-.4z"/>
          </svg>
          Recommendations
        </div>
```

- [ ] **Step 3: Add the tab container**

In `orchestrator/wwwroot/index.html`, find the Executive Dashboard tab's closing markup:

```html
        <div class="kpi-row" id="ed-kpi-row"><div class="empty">Loading…</div></div>
      </div>

      <!-- Findings -->
```

Replace with:

```html
        <div class="kpi-row" id="ed-kpi-row"><div class="empty">Loading…</div></div>
      </div>

      <!-- Recommendations -->
      <div id="tab-recommendations" style="display:none">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1rem;flex-wrap:wrap">
          <div>
            <h1 style="font-family:var(--font-display);font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 0.3rem;color:var(--text)">Recommendations</h1>
            <div style="font-size:0.8rem;color:var(--muted)">What to simulate next, ranked by threat priority, how overdue the technique is for testing, and whether it traverses a real path in your environment.</div>
          </div>
          <div style="display:flex;gap:0.5rem;align-items:center">
            <select id="rec-limit" onchange="loadRecommendations()" style="padding:0.35rem 0.6rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.78rem">
              <option value="10">Top 10</option>
              <option value="20" selected>Top 20</option>
              <option value="50">Top 50</option>
            </select>
            <button class="btn btn-outline btn-sm" onclick="copyRecommendedScenario()">Copy scenario techniques</button>
            <button class="btn btn-outline btn-sm" onclick="loadRecommendations()">Refresh</button>
          </div>
        </div>
        <div class="tbl-wrap">
          <table>
            <thead>
              <tr>
                <th>Technique</th><th>Tactic</th><th>Score</th><th>Coverage</th>
                <th>Threat</th><th>Environment</th><th>Why</th>
              </tr>
            </thead>
            <tbody id="rec-table-body"><tr><td colspan="7" class="empty">Loading…</td></tr></tbody>
          </table>
        </div>
      </div>

      <!-- Findings -->
```

- [ ] **Step 4: Wire the tab into `TAB_TITLES`, `activateTab`, and `showTab`**

Find:

```js
var TAB_TITLES = { dashboard:'Dashboard', agents:'Agents', scenarios:'Scenarios', runs:'Live Runs', campaigns:'Campaigns', coverage:'ATT&CK Coverage', findings:'Findings', remediation:'Remediation', reports:'Reports', verification:'Detection Verification', users:'Users', compliance:'Compliance', settings:'Settings', variants:'Variant Executor', em:'Endpoint Mastery', exposure:'Exposure Explorer', 'exec-dashboard':'Executive Dashboard', openaev:'OpenAEV Connector', exercises:'Exercises' };
```

Replace with:

```js
var TAB_TITLES = { dashboard:'Dashboard', agents:'Agents', scenarios:'Scenarios', runs:'Live Runs', campaigns:'Campaigns', coverage:'ATT&CK Coverage', findings:'Findings', remediation:'Remediation', reports:'Reports', verification:'Detection Verification', users:'Users', compliance:'Compliance', settings:'Settings', variants:'Variant Executor', em:'Endpoint Mastery', exposure:'Exposure Explorer', 'exec-dashboard':'Executive Dashboard', recommendations:'Recommendations', openaev:'OpenAEV Connector', exercises:'Exercises' };
```

Find:

```js
  ['dashboard','agents','scenarios','runs','campaigns','coverage','findings','remediation','reports','verification','compliance','settings','variants','em','attackpath','exposure','exec-dashboard','integrations','openaev','exercises'].forEach(function(t) {
```

Replace with:

```js
  ['dashboard','agents','scenarios','runs','campaigns','coverage','findings','remediation','reports','verification','compliance','settings','variants','em','attackpath','exposure','exec-dashboard','recommendations','integrations','openaev','exercises'].forEach(function(t) {
```

Find:

```js
  if (name === 'exec-dashboard') loadExecDashboard();
```

Replace with:

```js
  if (name === 'exec-dashboard') loadExecDashboard();
  if (name === 'recommendations') loadRecommendations();
```

- [ ] **Step 5: Add the JS**

Find the `renderExecDashboard` function's closing brace, which reads:

```js
  el.innerHTML =
    edKpiCard('Risk Score', current.avgRiskScore, risk) +
    edKpiCard('Exposure Score', current.exposureScore, exp) +
    edKpiCard('Detection Coverage', current.detectionCoverage, det) +
    edKpiCard('Fleet Assets', current.assetCount, cnt);
}
```

Add immediately after it:

```js

var REC_SCENARIO = null;

function recTierColor(tier) {
  return tier === 'Critical' ? 'var(--danger)'
       : tier === 'High'     ? '#f0883e'
       : tier === 'Medium'   ? 'var(--warning)'
       : 'var(--muted)';
}

function recCoverageBadge(state) {
  if (state === 'never-tested') return '<span class="badge" style="color:var(--danger);border-color:var(--danger)">Never tested</span>';
  if (state === 'stale')        return '<span class="badge" style="color:var(--warning);border-color:var(--warning)">Stale</span>';
  return '<span class="badge" style="color:var(--muted)">Recent</span>';
}

function loadRecommendations() {
  var limEl = document.getElementById('rec-limit');
  var limit = limEl ? limEl.value : '20';
  var body = document.getElementById('rec-table-body');
  body.innerHTML = '<tr><td colspan="7" class="empty">Loading…</td></tr>';
  apicall('/api/recommend/simulations?limit=' + encodeURIComponent(limit))
    .then(function(data) { renderRecommendations(data); })
    .catch(function(e) {
      body.innerHTML = '<tr><td colspan="7" class="empty" style="color:var(--danger)">Failed to load: ' + x(e.message) + '</td></tr>';
    });
}

function renderRecommendations(data) {
  var body = document.getElementById('rec-table-body');
  REC_SCENARIO = data.suggestedScenario || null;
  var list = (data && data.techniques) || [];
  if (!list.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No recommendations yet — seed ATT&CK/ART content to rank techniques.</td></tr>';
    return;
  }
  body.innerHTML = list.map(function(t) {
    var threat = [];
    if (t.kev) threat.push('<span class="badge" style="color:var(--danger);border-color:var(--danger)">KEV</span>');
    if (t.epssPercentile) threat.push('<span class="badge">EPSS ' + Math.round(t.epssPercentile) + '</span>');
    if (t.threatActors) threat.push('<span class="badge">' + t.threatActors + ' group' + (t.threatActors === 1 ? '' : 's') + '</span>');
    return '<tr>' +
      '<td><div style="font-weight:600">' + x(t.techniqueId) + '</div>' +
        '<div class="tiny muted">' + x(t.name) + '</div></td>' +
      '<td class="tiny">' + x(t.tactic) + '</td>' +
      '<td><span style="color:' + recTierColor(t.tier) + ';font-weight:700">' + t.score + '</span>' +
        '<div class="tiny" style="color:' + recTierColor(t.tier) + '">' + x(t.tier) + '</div></td>' +
      '<td>' + recCoverageBadge(t.coverageState) + '</td>' +
      '<td>' + (threat.join(' ') || '<span class="tiny muted">—</span>') + '</td>' +
      '<td>' + (t.environmentRisk ? '<span class="badge" style="color:var(--accent);border-color:var(--accent)">' + t.environmentRisk + '</span>'
                                  : '<span class="tiny muted">—</span>') + '</td>' +
      '<td class="tiny muted">' + x((t.reasons || []).join(' · ')) + '</td>' +
      '</tr>';
  }).join('');
}

function copyRecommendedScenario() {
  if (!REC_SCENARIO || !REC_SCENARIO.artTechniques || !REC_SCENARIO.artTechniques.length) {
    showToast('Nothing to copy yet — load recommendations first.', 'err');
    return;
  }
  var text = REC_SCENARIO.artTechniques.join(', ');
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function() {
      showToast('Copied ' + REC_SCENARIO.artTechniques.length + ' technique IDs — paste into the scenario builder.');
    }).catch(function() { showToast(text); });
  } else {
    showToast(text);
  }
}
```

- [ ] **Step 6: Syntax-check the inline scripts in BOTH files**

Run:

```bash
cd orchestrator
for f in wwwroot/index.html cmd/server/wwwroot/index.html; do
node -e "
const fs = require('fs');
const html = fs.readFileSync('$f', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
scripts.forEach((s, i) => { try { new Function(s); } catch (e) { console.error('$f script block', i, ':', e.message); process.exitCode = 1; } });
console.log('$f: ' + scripts.length + ' inline script block(s) checked');
"
done
```

Expected: one `… 1 inline script block(s) checked` line per file, no error lines, exit 0.

- [ ] **Step 7: Confirm the two files are still byte-identical**

Run: `cd orchestrator && diff wwwroot/index.html cmd/server/wwwroot/index.html && echo BYTE_IDENTICAL`
Expected: `BYTE_IDENTICAL`.

- [ ] **Step 8: Commit**

```bash
cd orchestrator
git add wwwroot/index.html cmd/server/wwwroot/index.html
git commit -m "feat(recommend): add Recommendations tab"
git push
```

**Known gap, report to the user:** no browser tool is available in this environment, so the tab's rendering, the tier colouring, the limit selector, and the copy-to-clipboard action are unverified beyond static syntax-checking and the passing API tests. Same honest gap SP4, SP6, and Executive Dashboards all carry. Recommend a manual browser spot-check: open Recommendations, confirm the table renders with ranked rows, switch the Top 10/20/50 selector, and click "Copy scenario techniques".

---

## Self-review notes (plan author — not a task to execute)

**Spec coverage.** Every spec section maps to a task: executable filter + universe → Task 4 `loadExecutableTechniques`; coverage state → Task 4 `loadCoverage` + Task 3 `CoverageGap`/`CoverageStateFor`; threat priority via the Relationship Store → Task 2 exports + Task 4 `loadKEVTechniques`/`loadEPSSPercentiles`/`actorCounts`; environment relevance → Task 1 `Graph.Edges()` + Task 4 `buildEnvIndex` + Task 3 `EnvironmentRisk`; scoring 0.50/0.30/0.20 → Task 3 `RecommendationScore`; `SuggestedScenario` → Task 4; API + RBAC matrix → Task 5; UI → Task 6. All five spec error-handling cases are covered by tests: unseeded content (Task 4 test 1), cold start (every technique never-tested — Task 4 tests 2/3), no collections (nil graph — Tasks 4 tests 1-5 all pass a nil or edge-free graph), empty Relationship Store (no KEV/EPSS seeded in most Task 4 tests, so threat priority runs on actor counts alone), nil-safety throughout.

**Deviations from the spec, both flagged above rather than silent:**
1. `Build` takes the graph as a parameter instead of loading it internally (see the "Deviation" section) — avoids triplicating the collection/tag loaders and matches `exposure.Build`'s convention.
2. The spec's pipeline step 1 said "Universe — `attackdata.All()`", step 2 "filter to executable". The implementation collapses these into one SQL join (`techniques ⋈ art_atomic_tests`). The resulting set is identical — `art_atomic_tests.technique_id` has a foreign key to `techniques`, so anything with an ART test is necessarily in `techniques` — and it matches both `kevPackTechs`' existing predicate and the project's "Postgres is the runtime source of truth for ART content" rule. `attackdata` is still used, for `GroupTechniqueIndex()` actor counts.

**Four defects caught by grounding the plan's own test code against the real API before committing** (all fixed above; recorded because each would have been a compile or runtime failure at execution time):
1. `attackpath.NewGraph()` does not exist — the constructor is `attackpath.New()`.
2. `attackpath.NodeHost` does not exist — the `NodeKind` constants are `KindHost` / `KindUser` / `KindGroup`.
3. `internal/attackpath/graph_test.go` does not exist — Task 1 creates it rather than appending to it.
4. `technique_cve_relationships.relationship_type` is `NOT NULL` with **no default**, so the original `seedKEV` INSERT would have failed at runtime. Now passes `'Commonly Associated'`, the value `content_import.go`'s own migration uses.

**Placeholder scan:** clean — no TBD/TODO, every code step carries complete code, every command has expected output.

**Type consistency:** `RecommendedTechnique`'s JSON tags (`techniqueId`, `score`, `tier`, `coverageState`, `threatPriority`, `coverageGap`, `environmentRisk`, `kev`, `epssPercentile`, `threatActors`, `reasons`) are consistent across Task 3 (struct), Task 5 (test decode), and Task 6 (JS reads). `SuggestedScenario.ARTTechniques` → `artTechniques` likewise. `Build`'s signature is identical in Task 4's definition, Task 4's tests, and Task 5's call site.

**One judgment call worth re-flagging at execution time:** `TestRecommendationScore_RecentFailingDoesNotDominate` (Task 3) and the spec's Decision 5 encode a real product opinion — that a known-failing technique is a remediation item, not a testing gap. If the manual review disagrees, that test is the single place to change, and the fix is to drop the fail bonus from the threat term rather than to reweight the composite.
