# AD-M11 Adaptive Attack-Path Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give AD-M11 ("Adaptive Attack-Path Engine") its two missing capabilities on top of AD-M05's `adchain` planner: (1) scoring a plan by total risk so multiple candidate plans can be compared, and (2) re-routing — re-planning around a set of blocked/excluded primitives — so a caller can adapt when the preferred path is unavailable. Then a small engine that combines them into a ranked list of alternative plans. Pure algorithm over the already-built `adchain`/`adprimitive` types; no new security content, no DB, no environment-graph integration.

**Architecture:** All additions live in the existing `orchestrator/internal/adchain` package (they build directly on `satisfied`/`Plan`/`containsCapability`, already there). `PathRisk([]adprimitive.Primitive) int` sums a per-`RiskClass` weight (the field AD-M07 added) over a plan — the cost metric the codebase's existing `attackpath` graph lacks (its edges are unweighted). `PlanExcluding(catalog, held, target, resolver, excluded map[string]bool) ([]Primitive, bool)` is `Plan` with a skip-set of primitive IDs — the concrete "adaptive re-route" mechanism the codebase has nowhere else (all existing retry logic is same-approach-again). `RankedPlans(catalog, held, target, resolver) []Plan` computes the primary plan plus one alternative per primitive in it (each via `PlanExcluding` avoiding that primitive), dedups, and sorts ascending by `PathRisk` with a deterministic tie-break — reusing the repo's established "score, sort, deterministic tie-break" idiom (`recommend/recommend.go:110`).

**Tech Stack:** Go (stdlib `sort` only; no new dependencies). No DB — these are pure in-memory functions over typed values, tested without any container (unlike M09/M10).

**Spec:** No separate written spec document — bounded, conversationally-approved task, following the user-approved wave process. Source: `orchestrator/internal/adchain/{search.go,satisfied.go}` (M05, read directly) and `adprimitive.RiskClass` (M07).

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- Additions go in the EXISTING `adchain` package; `adchain` keeps its one-way dependency on `adprimitive` only (no `adenv`/`attackpath`/DB).
- No change to the existing `Plan`/`Reachable`/`satisfied`/`ConditionResolver` signatures or behavior. The new functions are additive.
- `PathRisk`'s per-class weights are: `RiskNonDestructive`=1, `RiskPotentiallyDestructive`=3, `RiskDestructive`=9, and any unrecognized/empty class = the fail-closed maximum (9) — an unclassified primitive must never score as cheaper than a known-destructive one, mirroring `scenario/execclass.go`'s own fail-closed-to-destructive default.
- No narrative about what any path lets an attacker do — this is cost arithmetic and set exclusion over opaque primitive IDs.

## Review Focus

- `PathRisk` of an empty plan must be 0 (a zero-length path has no cost), and a plan containing a primitive with an empty/unrecognized `RiskClass` must score it at the fail-closed maximum, not 0 — scoring an unclassified primitive as free would make a dangerous path look cheapest and win the ranking. Tested in Task 1, Step 1.
- `PlanExcluding` with a given primitive in the excluded set must return a path that does NOT contain that primitive — and if excluding it makes the target unreachable, must return `ok=false`, not a path that silently ignores the exclusion. Tested in Task 1, Step 1.
- `RankedPlans` must return plans sorted by ascending `PathRisk` (lowest-risk first) with a fully deterministic order for equal-risk plans — a non-deterministic sort would make the "best adaptive path" vary run-to-run for identical input. Tested in Task 2, Step 1.
- `RankedPlans` must not return duplicate plans (two excluded-primitive re-routes can converge on the same alternative path) — a caller iterating "try next alternative" must not be handed the same path twice. Tested in Task 2, Step 1.

---

### Task 1: `PathRisk` and `PlanExcluding`

**Files:**
- Create: `orchestrator/internal/adchain/adaptive.go`
- Test: `orchestrator/internal/adchain/adaptive_test.go`

**Interfaces:**
- Consumes: `satisfied`, `containsCapability` (both already in the package), `adprimitive.Primitive`/`Capability`/`RiskClass` + its constants.
- Produces: `PathRisk(path []adprimitive.Primitive) int`, `PlanExcluding(catalog []adprimitive.Primitive, held []adprimitive.Capability, target adprimitive.Capability, resolver ConditionResolver, excluded map[string]bool) ([]adprimitive.Primitive, bool)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adchain/adaptive_test.go
package adchain

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestPathRisk_EmptyPathIsZero(t *testing.T) {
	if got := PathRisk(nil); got != 0 {
		t.Errorf("expected 0 for empty path, got %d", got)
	}
}

func TestPathRisk_SumsPerClassWeights(t *testing.T) {
	path := []adprimitive.Primitive{
		{ID: "a", RiskClass: adprimitive.RiskNonDestructive},         // 1
		{ID: "b", RiskClass: adprimitive.RiskPotentiallyDestructive}, // 3
		{ID: "c", RiskClass: adprimitive.RiskDestructive},            // 9
	}
	if got := PathRisk(path); got != 13 {
		t.Errorf("expected 1+3+9=13, got %d", got)
	}
}

func TestPathRisk_UnclassifiedScoresFailClosedMax(t *testing.T) {
	path := []adprimitive.Primitive{{ID: "x", RiskClass: ""}}
	if got := PathRisk(path); got != 9 {
		t.Errorf("expected unclassified primitive to score the fail-closed max 9, got %d", got)
	}
}

func adaptiveCatalog() []adprimitive.Primitive {
	// Two independent routes from CapDomainUser to CapLocalAdmin:
	//   cheap-a -> cheap-b  (both potentially_destructive)
	//   risky-direct        (one destructive step)
	return []adprimitive.Primitive{
		{
			ID: "cheap-a", RiskClass: adprimitive.RiskPotentiallyDestructive,
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapGroupMember}},
		},
		{
			ID: "cheap-b", RiskClass: adprimitive.RiskPotentiallyDestructive,
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapGroupMember}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapLocalAdmin}},
		},
		{
			ID: "risky-direct", RiskClass: adprimitive.RiskDestructive,
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapLocalAdmin}},
		},
	}
}

func TestPlanExcluding_AvoidsExcludedPrimitiveAndReroutes(t *testing.T) {
	held := []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}
	target := adprimitive.Capability{Kind: adprimitive.CapLocalAdmin}

	// Exclude the direct risky step -> must re-route via cheap-a/cheap-b.
	path, ok := PlanExcluding(adaptiveCatalog(), held, target, MapResolver{}, map[string]bool{"risky-direct": true})
	if !ok {
		t.Fatal("expected a re-route to exist avoiding risky-direct")
	}
	for _, p := range path {
		if p.ID == "risky-direct" {
			t.Fatalf("excluded primitive risky-direct appeared in the path: %+v", path)
		}
	}
}

func TestPlanExcluding_UnreachableWhenAllRoutesExcluded(t *testing.T) {
	held := []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}
	target := adprimitive.Capability{Kind: adprimitive.CapLocalAdmin}

	// Excluding cheap-b AND risky-direct leaves no route to CapLocalAdmin.
	_, ok := PlanExcluding(adaptiveCatalog(), held, target, MapResolver{}, map[string]bool{"cheap-b": true, "risky-direct": true})
	if ok {
		t.Fatal("expected ok=false: every route to the target is excluded")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adchain/... -run "TestPathRisk|TestPlanExcluding" -v`
Expected: FAIL — `undefined: PathRisk` / `undefined: PlanExcluding`.

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adchain/adaptive.go
package adchain

import "github.com/audspect/bas/internal/adprimitive"

// riskWeight maps a primitive's RiskClass to a numeric cost. An
// unrecognized or empty class scores the maximum (fail-closed, mirroring
// scenario/execclass.go's unclassified=destructive default): an
// unclassified primitive must never look cheaper than a known-destructive
// one.
func riskWeight(c adprimitive.RiskClass) int {
	switch c {
	case adprimitive.RiskNonDestructive:
		return 1
	case adprimitive.RiskPotentiallyDestructive:
		return 3
	case adprimitive.RiskDestructive:
		return 9
	default:
		return 9
	}
}

// PathRisk is the summed risk weight of every primitive in path. An empty
// path has zero risk.
func PathRisk(path []adprimitive.Primitive) int {
	total := 0
	for _, p := range path {
		total += riskWeight(p.RiskClass)
	}
	return total
}

// PlanExcluding is Plan, but it never applies a primitive whose ID is in
// excluded -- the adaptive re-route primitive: when a primitive is
// blocked (failed, too risky, already detected), re-plan around it.
// Returns ok=false if the target is unreachable without the excluded
// primitives.
func PlanExcluding(catalog []adprimitive.Primitive, held []adprimitive.Capability, target adprimitive.Capability, resolver ConditionResolver, excluded map[string]bool) ([]adprimitive.Primitive, bool) {
	var path []adprimitive.Primitive
	if containsCapability(held, target) {
		return path, true
	}
	for {
		applied := false
		for _, p := range catalog {
			if excluded[p.ID] {
				continue
			}
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
			if containsCapability(p.Postconditions, target) {
				return path, true
			}
		}
		if !applied {
			return nil, false
		}
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adchain/... -run "TestPathRisk|TestPlanExcluding" -v`
Expected: PASS — all 5 new tests.

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adchain/ && go vet ./internal/adchain/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adchain/adaptive.go orchestrator/internal/adchain/adaptive_test.go
git commit -m "$(cat <<'EOF'
feat(adchain): add PathRisk scoring and PlanExcluding re-route (AD-M11 task 1 of 2)

PathRisk sums a per-RiskClass weight (1/3/9, unclassified=9 fail-closed)
over a plan -- the cost metric attackpath's unweighted graph lacks.
PlanExcluding is Plan with a skip-set of primitive IDs: the adaptive
re-route mechanism the codebase has nowhere else (all existing retry
logic is same-approach-again). Pure algorithm over adprimitive types,
no DB, no new security content.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `RankedPlans` engine

**Files:**
- Modify: `orchestrator/internal/adchain/adaptive.go` (add `Plan` result type + `RankedPlans`)
- Test: `orchestrator/internal/adchain/adaptive_test.go` (add ranking tests)

**Interfaces:**
- Consumes: `Plan` (existing), `PlanExcluding`/`PathRisk` (Task 1).
- Produces: `RankedPlan` struct (`Steps []adprimitive.Primitive`, `Risk int`), `RankedPlans(catalog []adprimitive.Primitive, held []adprimitive.Capability, target adprimitive.Capability, resolver ConditionResolver) []RankedPlan`.

- [ ] **Step 1: Write the failing tests**

```go
// Append to orchestrator/internal/adchain/adaptive_test.go

func planIDs(p RankedPlan) string {
	s := ""
	for _, step := range p.Steps {
		s += step.ID + ","
	}
	return s
}

func TestRankedPlans_SortedByAscendingRiskAndDeduped(t *testing.T) {
	held := []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}
	target := adprimitive.Capability{Kind: adprimitive.CapLocalAdmin}

	ranked := RankedPlans(adaptiveCatalog(), held, target, MapResolver{})
	if len(ranked) < 2 {
		t.Fatalf("expected at least 2 distinct candidate plans, got %d: %+v", len(ranked), ranked)
	}
	// Ascending risk: the cheap-a/cheap-b route (1+... = 3+3=6) must rank
	// before the risky-direct route (9).
	for i := 1; i < len(ranked); i++ {
		if ranked[i-1].Risk > ranked[i].Risk {
			t.Fatalf("plans not sorted ascending by risk: %d before %d", ranked[i-1].Risk, ranked[i].Risk)
		}
	}
	if ranked[0].Risk != 6 {
		t.Errorf("expected the lowest-risk plan to be the 2-step route (risk 6), got %d", ranked[0].Risk)
	}
	// No duplicate plans.
	seen := map[string]bool{}
	for _, p := range ranked {
		id := planIDs(p)
		if seen[id] {
			t.Fatalf("duplicate plan in ranked output: %s", id)
		}
		seen[id] = true
	}
}

func TestRankedPlans_EmptyWhenTargetUnreachable(t *testing.T) {
	held := []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}
	unreachable := adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial}
	ranked := RankedPlans(adaptiveCatalog(), held, unreachable, MapResolver{})
	if len(ranked) != 0 {
		t.Fatalf("expected no plans for an unreachable target, got %+v", ranked)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adchain/... -run "TestRankedPlans" -v`
Expected: FAIL — `undefined: RankedPlan` / `undefined: RankedPlans`.

- [ ] **Step 3: Write the minimal implementation**

```go
// Add to orchestrator/internal/adchain/adaptive.go (and add "sort" to the import block)

// RankedPlan is one candidate plan to a target, with its total PathRisk.
type RankedPlan struct {
	Steps []adprimitive.Primitive
	Risk  int
}

// RankedPlans returns candidate plans from held to target, lowest-risk
// first. It computes the primary plan, then one alternative per primitive
// in it (re-routing around that primitive via PlanExcluding), dedups
// identical plans, and sorts ascending by PathRisk with a deterministic
// tie-break on the plans' primitive-ID sequences. Empty if the target is
// unreachable at all.
func RankedPlans(catalog []adprimitive.Primitive, held []adprimitive.Capability, target adprimitive.Capability, resolver ConditionResolver) []RankedPlan {
	primary, ok := Plan(catalog, held, target, resolver)
	if !ok {
		return nil
	}

	candidates := [][]adprimitive.Primitive{primary}
	for _, step := range primary {
		if alt, ok := PlanExcluding(catalog, held, target, resolver, map[string]bool{step.ID: true}); ok {
			candidates = append(candidates, alt)
		}
	}

	seen := map[string]bool{}
	var out []RankedPlan
	for _, c := range candidates {
		key := planKey(c)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, RankedPlan{Steps: c, Risk: PathRisk(c)})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk < out[j].Risk
		}
		return planKey(out[i].Steps) < planKey(out[j].Steps)
	})
	return out
}

func planKey(path []adprimitive.Primitive) string {
	s := ""
	for _, p := range path {
		s += p.ID + "\x00"
	}
	return s
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adchain/... -v`
Expected: PASS — all tests in the package (9 from M05, 5 from Task 1, 2 new).

- [ ] **Step 5: Run gofmt, go vet, and the full build**

Run: `cd orchestrator && gofmt -l internal/adchain/ && go vet ./internal/adchain/... && go build ./...`
Expected: gofmt/vet print nothing, build succeeds.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adchain/adaptive.go orchestrator/internal/adchain/adaptive_test.go
git commit -m "$(cat <<'EOF'
feat(adchain): add RankedPlans adaptive-path engine (AD-M11 task 2 of 2)

RankedPlans computes the primary plan plus one re-route per primitive
in it (via PlanExcluding), dedups, and sorts ascending by PathRisk
with a deterministic tie-break on primitive-ID sequence -- reusing the
repo's established score/sort/tie-break idiom. Empty for an unreachable
target. Closes AD-M11: the adaptive (re-route) + ranking (lowest-risk-
first) capabilities the pre-existing unweighted attackpath BFS lacked.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** 2 small, sequential tasks extending the existing `adchain` package with pure functions; proceeding directly to execution via `superpowers:executing-plans`.
