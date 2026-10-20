# Intra-Cloud Multi-Hop Reachability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add multi-hop attack-path search (`CloudReachable`, `CloudPlan`) over `cloudgraph`'s existing single-hop `CloudPermission` evaluation, so the engine can answer "can identity A reach resource C through a chain of role assumptions," not just "does this one edge allow this action."

**Architecture:** Two pure functions in a new file, mirroring `adchain.Reachable`/`adchain.Plan`'s proven fixpoint-closure shape exactly, but native to `cloudgraph`'s own `CloudIdentity`/`CloudResource`/`CloudPermission` graph types instead of `adchain`'s capability-based types. A `reachedAsSource`/`reachedAsTarget` map split (not a single set) gates which reached nodes may legitimately continue a chain, validated against an explicit allowlist of identity-bearing `CloudResource.Kind` values.

**Tech Stack:** Go (matches the rest of `orchestrator/internal/cloudgraph/`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-13-intracloud-multihop-reachability-design.md` (base spec + same-day amendment — read both; the amendment supersedes the base spec's Algorithm section wherever they differ).

## Global Constraints

- Sonnet only for any subagent work on this plan — never Opus.
- Narrow verification first per edit (run just the new test file as you go); a full `go test ./internal/cloudgraph/...` gate at the very end of the plan, not after every step.
- TDD throughout: watch every test fail for the right reason before writing the implementation that makes it pass.
- Minimal changes only — this plan touches exactly two new files (`cloud_reachability.go`, `cloud_reachability_test.go`). Nothing else in `orchestrator/internal/cloudgraph/` is modified.
- `git push` immediately after every commit.
- Inline execution has been this session's established pattern for every prior increment in this package (Phases 1-5, the Azure discovery milestone) — see Execution Handoff below.

## Review Focus

- **`CloudPermission.Source`/`.Target` are concretely typed** (`*CloudIdentity`/`*CloudResource`, confirmed by reading `types.go` — not interfaces), so there is no type-switch ambiguity to get wrong; confirm no task accidentally adds one.
- **`maxHops <= 0` is exercised directly**, not just `maxHops=2` on a longer chain — Task 3's `TestCloudReachable_MaxHopsZeroReturnsHeldUnchanged` is the one place this is pinned; confirm it actually runs with `maxHops=0` literally, not `1`.
- **The duplicate-edge iteration-order dependency is asserted as "deterministic for this fixed input," never as "this edge should always win."** Task 2's `TestCloudPlan_DuplicateViableEdgesDeterministic` must not be read as prescribing which `SourceType` wins in general — only that today's input order is honored consistently.
- **`worstState`'s `Blocked`-vs-`Unknown` tie-break** (both present in the same hop list) has its own dedicated test in Task 1 (`TestWorstState_BlockedBeatsUnknownWhenBothPresent`) — distinct from the "any Blocked" and "any Unknown, no Blocked" cases, since a reviewer could approve those two without noticing the combined case was never checked.
- **A dead-end non-viable edge evaluated during the same pass as a successful path must never leak into `CloudPath.Hops` or degrade `OverallState`.** Task 2's `TestCloudPlan_DeadEndEdgeDoesNotLeakIntoSuccessfulPath` pins this directly — confirm it asserts on `OverallState` as well as hop count, not just hop count alone.

---

## Task 1: Foundational types and helpers

**Files:**
- Create: `orchestrator/internal/cloudgraph/cloud_reachability.go` (this task's portion only: `CloudHop`, `CloudPath`, `isViable`, `assumableIdentityKinds`, `worstState`)
- Create: `orchestrator/internal/cloudgraph/cloud_reachability_test.go` (this task's portion only: `worstState` unit tests)

**Interfaces:**
- Consumes: `PathState` and its six constants (`Candidate`, `ConditionallyReachable`, `PolicySupported`, `Observed`, `Blocked`, `Unknown`), `EvaluationResult`, `CloudPermission` — all from `types.go`, unmodified.
- Produces: `type CloudHop struct { Edge *CloudPermission; Result *EvaluationResult }`, `type CloudPath struct { Hops []*CloudHop; OverallState PathState }`, `func isViable(state PathState) bool`, `var assumableIdentityKinds map[string]bool`, `func worstState(states []PathState) PathState` — all consumed by Tasks 2 and 3.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/cloudgraph/cloud_reachability_test.go`:

```go
package cloudgraph

import "testing"

func TestWorstState_AllPolicySupported(t *testing.T) {
	got := worstState([]PathState{PolicySupported, PolicySupported})
	if got != PolicySupported {
		t.Errorf("Expected PolicySupported, got %s", got)
	}
}

func TestWorstState_AnyBlockedWins(t *testing.T) {
	got := worstState([]PathState{PolicySupported, Blocked, Observed})
	if got != Blocked {
		t.Errorf("Expected Blocked, got %s", got)
	}
}

func TestWorstState_UnknownWithoutBlocked(t *testing.T) {
	got := worstState([]PathState{PolicySupported, Unknown})
	if got != Unknown {
		t.Errorf("Expected Unknown, got %s", got)
	}
}

func TestWorstState_BlockedBeatsUnknownWhenBothPresent(t *testing.T) {
	got := worstState([]PathState{Unknown, Blocked})
	if got != Blocked {
		t.Errorf("Expected Blocked to beat Unknown, got %s", got)
	}
}

func TestWorstState_AllObserved(t *testing.T) {
	got := worstState([]PathState{Observed, Observed})
	if got != Observed {
		t.Errorf("Expected Observed, got %s", got)
	}
}

func TestWorstState_EmptySliceDefaultsToPolicySupported(t *testing.T) {
	got := worstState(nil)
	if got != PolicySupported {
		t.Errorf("Expected PolicySupported for empty input, got %s", got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cloudgraph/... -run TestWorstState -v` (from `orchestrator/`)
Expected: FAIL — `undefined: worstState` (compile error; `cloud_reachability.go` doesn't exist yet). This is a valid RED state: the function doesn't exist.

- [ ] **Step 3: Write the minimal implementation**

Create `orchestrator/internal/cloudgraph/cloud_reachability.go`:

```go
package cloudgraph

// CloudHop is one edge traversed in a path, paired with its evaluation result.
type CloudHop struct {
	Edge   *CloudPermission
	Result *EvaluationResult
}

// CloudPath is one ordered sequence of hops from a starting identity to a
// target, plus the weakest-link verdict across all hops.
type CloudPath struct {
	Hops         []*CloudHop
	OverallState PathState
}

// isViable reports whether a hop's evaluation result is strong enough
// evidence to trust propagating reachability through it. Only
// PolicySupported (a policy predicts this edge works) and Observed
// (evidence confirms it actually did) qualify. Blocked, Unknown, Candidate,
// and ConditionallyReachable are all treated identically: none of them let
// a hop continue, since none of them are confirmed. Surfacing a tentative
// path through a Candidate/ConditionallyReachable edge is explicitly
// deferred -- see spec amendment point 1.
func isViable(state PathState) bool {
	return state == PolicySupported || state == Observed
}

// assumableIdentityKinds are CloudResource.Kind values that represent a
// resource which, once reached, can legitimately act as a CloudIdentity for
// further traversal (e.g. an IAM role or service principal, once assumed,
// becomes a principal in its own right). A resource outside this set (e.g.
// an s3-bucket) is recorded as reached for reporting/targeting purposes but
// is never treated as a usable Source for a later hop, even if some other
// edge's Source.CanonicalID happens to collide with its CanonicalID. See
// spec amendment point 3.
var assumableIdentityKinds = map[string]bool{
	"iam-role":          true,
	"service-principal": true,
	"managed-identity":  true,
}

// worstState returns the overall PathState for a set of per-hop states,
// always preferring the weakest (least trustworthy) evidence present.
// Strength order, weakest to strongest: Blocked < Unknown < PolicySupported
// < Observed. An empty slice returns PolicySupported, matching the "target
// already held, no hop to doubt" default used by CloudPlan's early-return
// case. CloudPlan/CloudReachable never set State themselves -- this
// function only ever propagates whatever the supplied evaluator returned,
// so a path can never report stronger evidence than its weakest hop
// actually has (see spec amendment point 2).
func worstState(states []PathState) PathState {
	if len(states) == 0 {
		return PolicySupported
	}
	sawUnknown := false
	sawPolicySupported := false
	for _, s := range states {
		switch s {
		case Blocked:
			return Blocked
		case Unknown:
			sawUnknown = true
		case PolicySupported:
			sawPolicySupported = true
		}
	}
	if sawUnknown {
		return Unknown
	}
	if sawPolicySupported {
		return PolicySupported
	}
	return Observed
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/cloudgraph/... -run TestWorstState -v`
Expected: PASS — all 6 tests green.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/cloudgraph/cloud_reachability.go orchestrator/internal/cloudgraph/cloud_reachability_test.go
git commit -m "feat(cloudgraph): foundational types for intra-cloud multi-hop reachability

CloudHop/CloudPath types, isViable, worstState, and the
assumableIdentityKinds allowlist. CloudReachable/CloudPlan (next commits)
will consume these."
git push
```

---

## Task 2: CloudPlan

**Files:**
- Modify: `orchestrator/internal/cloudgraph/cloud_reachability.go` (append `CloudPlan`, `hopStates`)
- Modify: `orchestrator/internal/cloudgraph/cloud_reachability_test.go` (append this task's tests)

**Interfaces:**
- Consumes: `CloudHop`, `CloudPath`, `isViable`, `assumableIdentityKinds`, `worstState` (Task 1); `AuthorizationEvaluator`, `RequestContext` (`evaluator.go`); `AWSEvaluator` (`aws_evaluator.go`, used only in tests).
- Produces: `func CloudPlan(edges []*CloudPermission, held []string, target string, evaluator AuthorizationEvaluator, ctx *RequestContext, maxHops int) (*CloudPath, bool)`, `func hopStates(hops []*CloudHop) []PathState` — consumed by Task 3's tests (not by `CloudReachable` itself, which has its own loop).

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/cloudgraph/cloud_reachability_test.go`:

```go
func TestCloudPlan_TwoHopHappyPath(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/attacker",
		Kind:        "iam-user",
	}
	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/data-processor",
		Kind:        "iam-role",
	}
	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::sensitive-data",
		Kind:        "s3-bucket",
	}
	roleAsIdentity := &CloudIdentity{
		CanonicalID: role.CanonicalID,
		Kind:        "iam-role",
	}

	edges := []*CloudPermission{
		{
			Source:     user,
			Target:     role,
			Action:     "sts:AssumeRole",
			SourceType: "role-trust",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/attacker"},"Action":"sts:AssumeRole"}]}`,
			},
		},
		{
			Source:     roleAsIdentity,
			Target:     bucket,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::sensitive-data/*"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	path, ok := CloudPlan(edges, []string{user.CanonicalID}, bucket.CanonicalID, evaluator, &RequestContext{}, 10)

	if !ok {
		t.Fatal("Expected path to be found")
	}
	if len(path.Hops) != 2 {
		t.Fatalf("Expected 2 hops, got %d", len(path.Hops))
	}
	if path.Hops[0].Edge.Target.CanonicalID != role.CanonicalID {
		t.Errorf("Expected first hop to reach role, got %s", path.Hops[0].Edge.Target.CanonicalID)
	}
	if path.Hops[1].Edge.Target.CanonicalID != bucket.CanonicalID {
		t.Errorf("Expected second hop to reach bucket, got %s", path.Hops[1].Edge.Target.CanonicalID)
	}
	if path.OverallState != PolicySupported {
		t.Errorf("Expected OverallState PolicySupported, got %s", path.OverallState)
	}
}

func TestCloudPlan_BlockedHopStopsChain(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/limited-user",
		Kind:        "iam-user",
	}
	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/admin-role",
		Kind:        "iam-role",
	}
	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::sensitive-data",
		Kind:        "s3-bucket",
	}
	roleAsIdentity := &CloudIdentity{CanonicalID: role.CanonicalID, Kind: "iam-role"}

	edges := []*CloudPermission{
		{
			Source:     user,
			Target:     role,
			Action:     "sts:AssumeRole",
			SourceType: "role-trust",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/someone-else"},"Action":"sts:AssumeRole"}]}`,
			},
		},
		{
			Source:     roleAsIdentity,
			Target:     bucket,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::sensitive-data/*"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	path, ok := CloudPlan(edges, []string{user.CanonicalID}, bucket.CanonicalID, evaluator, &RequestContext{}, 10)

	if ok {
		t.Fatal("Expected no path to be found (first hop is Blocked)")
	}
	if path != nil {
		t.Errorf("Expected nil path on failure, got %+v", path)
	}
}

func TestCloudPlan_TargetAlreadyHeld(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker", Kind: "iam-user"}
	evaluator := &AWSEvaluator{}

	path, ok := CloudPlan(nil, []string{user.CanonicalID}, user.CanonicalID, evaluator, &RequestContext{}, 10)

	if !ok {
		t.Fatal("Expected ok=true when target is already held")
	}
	if len(path.Hops) != 0 {
		t.Errorf("Expected zero hops, got %d", len(path.Hops))
	}
	if path.OverallState != PolicySupported {
		t.Errorf("Expected OverallState PolicySupported, got %s", path.OverallState)
	}
}

func TestCloudPlan_DeadEndEdgeDoesNotLeakIntoSuccessfulPath(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker", Kind: "iam-user"}
	goodBucket := &CloudResource{CanonicalID: "arn:aws:s3:::good-bucket", Kind: "s3-bucket"}
	deadEndRole := &CloudResource{CanonicalID: "arn:aws:iam::123456789012:role/unreachable-role", Kind: "iam-role"}

	// The dead-end edge is listed FIRST deliberately. CloudPlan returns the
	// instant it finds the target, so if the successful edge were first,
	// the dead-end edge would never even be evaluated -- proving nothing
	// about leakage, only short-circuiting. Listing the dead end first
	// forces it to actually be evaluated (and correctly skipped) within
	// the same pass, before the successful hop is found second.
	edges := []*CloudPermission{
		{
			Source:     user,
			Target:     deadEndRole,
			Action:     "sts:AssumeRole",
			SourceType: "role-trust",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/someone-else"},"Action":"sts:AssumeRole"}]}`,
			},
		},
		{
			Source:     user,
			Target:     goodBucket,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::good-bucket/*"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	path, ok := CloudPlan(edges, []string{user.CanonicalID}, goodBucket.CanonicalID, evaluator, &RequestContext{}, 10)

	if !ok {
		t.Fatal("Expected path to be found via the viable edge")
	}
	if len(path.Hops) != 1 {
		t.Fatalf("Expected exactly 1 hop (the viable edge only), got %d", len(path.Hops))
	}
	if path.Hops[0].Edge.Target.CanonicalID != goodBucket.CanonicalID {
		t.Errorf("Expected the single hop to be the good-bucket edge, got %s", path.Hops[0].Edge.Target.CanonicalID)
	}
	if path.OverallState != PolicySupported {
		t.Errorf("Expected OverallState PolicySupported (dead-end Blocked edge must not affect it), got %s", path.OverallState)
	}
}

// fakeMixedStrengthEvaluator is a test-only AuthorizationEvaluator that
// returns a fixed, per-target canned State. Used to construct a path with a
// mix of Observed and PolicySupported strength -- something no real
// evaluator (AWSEvaluator/AzureEvaluator/GCPEvaluator) currently produces,
// since none of them ever set State: Observed (confirmed by inspection --
// that value is reserved for a future evidence-correlation-aware
// evaluator; see spec amendment point 2). An unrecognized target is a test
// bug, not a silent default, so it panics rather than guessing.
type fakeMixedStrengthEvaluator struct {
	stateByTarget map[string]PathState
}

func (f *fakeMixedStrengthEvaluator) EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult {
	state, ok := f.stateByTarget[edge.Target.CanonicalID]
	if !ok {
		panic("fakeMixedStrengthEvaluator: no canned state for target " + edge.Target.CanonicalID)
	}
	return &EvaluationResult{State: state}
}

func TestCloudPlan_MixedStrengthHopsComputeWeakestOverallState(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "test:user", Kind: "iam-user"}
	role := &CloudResource{CanonicalID: "test:role", Kind: "iam-role"}
	bucket := &CloudResource{CanonicalID: "test:bucket", Kind: "s3-bucket"}
	roleAsIdentity := &CloudIdentity{CanonicalID: role.CanonicalID, Kind: "iam-role"}

	edges := []*CloudPermission{
		{Source: user, Target: role, Action: "sts:AssumeRole"},
		{Source: roleAsIdentity, Target: bucket, Action: "s3:GetObject"},
	}

	evaluator := &fakeMixedStrengthEvaluator{
		stateByTarget: map[string]PathState{
			role.CanonicalID:   Observed,
			bucket.CanonicalID: PolicySupported,
		},
	}

	path, ok := CloudPlan(edges, []string{user.CanonicalID}, bucket.CanonicalID, evaluator, &RequestContext{}, 10)

	if !ok {
		t.Fatal("Expected path to be found")
	}
	if len(path.Hops) != 2 {
		t.Fatalf("Expected 2 hops, got %d", len(path.Hops))
	}
	if path.OverallState != PolicySupported {
		t.Errorf("Expected weakest-link OverallState PolicySupported (weaker than Observed), got %s", path.OverallState)
	}
}

func TestCloudPlan_DuplicateViableEdgesDeterministic(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker", Kind: "iam-user"}
	bucket := &CloudResource{CanonicalID: "arn:aws:s3:::sensitive-data", Kind: "s3-bucket"}

	edgeA := &CloudPermission{
		Source:     user,
		Target:     bucket,
		Action:     "s3:GetObject",
		SourceType: "identity-policy",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::sensitive-data/*"}]}`,
		},
	}
	edgeB := &CloudPermission{
		Source:     user,
		Target:     bucket,
		Action:     "s3:GetObject",
		SourceType: "resource-policy",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::sensitive-data/*"}]}`,
		},
	}
	edges := []*CloudPermission{edgeA, edgeB}

	evaluator := &AWSEvaluator{}
	path, ok := CloudPlan(edges, []string{user.CanonicalID}, bucket.CanonicalID, evaluator, &RequestContext{}, 10)

	if !ok {
		t.Fatal("Expected path to be found")
	}
	if len(path.Hops) != 1 {
		t.Fatalf("Expected exactly 1 hop (target reached once, even with 2 viable edges), got %d", len(path.Hops))
	}
	// Documents deterministic-for-this-fixed-input-order behavior, per the
	// spec's explicit acceptance of iteration-order dependency when ties
	// exist -- this is NOT a claim that identity-policy "should" win in
	// general over resource-policy.
	if path.Hops[0].Edge.SourceType != "identity-policy" {
		t.Errorf("Expected the first edge in input order (identity-policy) to be recorded, got %s", path.Hops[0].Edge.SourceType)
	}
}

func TestCloudPlan_StructurallyUnreachableTarget(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker", Kind: "iam-user"}
	unrelatedBucket := &CloudResource{CanonicalID: "arn:aws:s3:::unrelated-bucket", Kind: "s3-bucket"}
	isolatedTarget := &CloudResource{CanonicalID: "arn:aws:s3:::isolated-bucket", Kind: "s3-bucket"}

	edges := []*CloudPermission{
		{
			Source:     user,
			Target:     unrelatedBucket,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::unrelated-bucket/*"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	path, ok := CloudPlan(edges, []string{user.CanonicalID}, isolatedTarget.CanonicalID, evaluator, &RequestContext{}, 10)

	if ok {
		t.Fatal("Expected no path to be found -- isolatedTarget has no edge pointing to it at all")
	}
	if path != nil {
		t.Errorf("Expected nil path, got %+v", path)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cloudgraph/... -run TestCloudPlan -v`
Expected: FAIL — `undefined: CloudPlan` (compile error).

- [ ] **Step 3: Write the minimal implementation**

Append to `orchestrator/internal/cloudgraph/cloud_reachability.go`:

```go
// CloudPlan searches for one ordered path from held to target, returning
// ok=false if target cannot be confirmed reachable within maxHops passes.
// ok=false means "no path could be confirmed from available evidence," not
// "no real-world path exists" -- a search that dead-ends at an Unknown edge
// has hit the limit of what the available evidence can confirm, not proven
// the edge is actually closed (see spec amendment point 2). Mirrors
// adchain.Plan's exact shape, substituting the reachedAsSource/
// reachedAsTarget CanonicalID tracking described in spec amendment point 3
// for capability equality.
func CloudPlan(edges []*CloudPermission, held []string, target string, evaluator AuthorizationEvaluator, ctx *RequestContext, maxHops int) (*CloudPath, bool) {
	reachedAsTarget := make(map[string]bool, len(held))
	reachedAsSource := make(map[string]bool, len(held))
	for _, id := range held {
		reachedAsTarget[id] = true
		reachedAsSource[id] = true
	}
	if reachedAsTarget[target] {
		return &CloudPath{Hops: nil, OverallState: PolicySupported}, true
	}

	var hops []*CloudHop
	for pass := 0; pass < maxHops; pass++ {
		added := false
		for _, edge := range edges {
			if !reachedAsSource[edge.Source.CanonicalID] {
				continue
			}
			if reachedAsTarget[edge.Target.CanonicalID] {
				continue
			}
			result := evaluator.EvaluatePermission(edge, ctx)
			if !isViable(result.State) {
				continue
			}
			reachedAsTarget[edge.Target.CanonicalID] = true
			if assumableIdentityKinds[edge.Target.Kind] {
				reachedAsSource[edge.Target.CanonicalID] = true
			}
			hops = append(hops, &CloudHop{Edge: edge, Result: result})
			added = true
			if edge.Target.CanonicalID == target {
				return &CloudPath{Hops: hops, OverallState: worstState(hopStates(hops))}, true
			}
		}
		if !added {
			break
		}
	}
	return nil, false
}

// hopStates extracts the per-hop PathState values from an ordered hop list,
// for feeding into worstState.
func hopStates(hops []*CloudHop) []PathState {
	states := make([]PathState, len(hops))
	for i, h := range hops {
		states[i] = h.Result.State
	}
	return states
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/cloudgraph/... -run TestCloudPlan -v`
Expected: PASS — all 7 tests green. If any fails, that's a real gap in the implementation above (not the test) — use systematic-debugging, fix `CloudPlan`, and re-run until all 7 pass before moving on.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/cloudgraph/cloud_reachability.go orchestrator/internal/cloudgraph/cloud_reachability_test.go
git commit -m "feat(cloudgraph): CloudPlan -- multi-hop attack-path search

Searches for one ordered path from a starting identity to a target through
a set of CloudPermission edges, validated hop-by-hop against the
AuthorizationEvaluator already in place for each provider. Gated by the
reachedAsSource/reachedAsTarget Kind-validation split (spec amendment
point 3): a reached resource only continues the chain if its Kind is a
recognized identity-bearing kind (iam-role, service-principal,
managed-identity)."
git push
```

---

## Task 3: CloudReachable

**Files:**
- Modify: `orchestrator/internal/cloudgraph/cloud_reachability.go` (append `CloudReachable`)
- Modify: `orchestrator/internal/cloudgraph/cloud_reachability_test.go` (append this task's tests)

**Interfaces:**
- Consumes: everything from Tasks 1 and 2 (`isViable`, `assumableIdentityKinds`, `worstState`, `CloudHop`, `CloudPath`); `AWSEvaluator`.
- Produces: `func CloudReachable(edges []*CloudPermission, held []string, evaluator AuthorizationEvaluator, ctx *RequestContext, maxHops int) []string` — the final deliverable of this plan. Nothing downstream in this plan consumes it further.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/cloudgraph/cloud_reachability_test.go`:

```go
func TestCloudReachable_MutualTrustCycleTerminates(t *testing.T) {
	roleA := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:role/role-a", Kind: "iam-role"}
	roleAAsResource := &CloudResource{CanonicalID: roleA.CanonicalID, Kind: "iam-role"}
	roleB := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:role/role-b", Kind: "iam-role"}
	roleBAsResource := &CloudResource{CanonicalID: roleB.CanonicalID, Kind: "iam-role"}

	edges := []*CloudPermission{
		{
			Source:     roleA,
			Target:     roleBAsResource,
			Action:     "sts:AssumeRole",
			SourceType: "role-trust",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/role-a"},"Action":"sts:AssumeRole"}]}`,
			},
		},
		{
			Source:     roleB,
			Target:     roleAAsResource,
			Action:     "sts:AssumeRole",
			SourceType: "role-trust",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/role-b"},"Action":"sts:AssumeRole"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	reached := CloudReachable(edges, []string{roleA.CanonicalID}, evaluator, &RequestContext{}, 10)

	if len(reached) != 2 {
		t.Fatalf("Expected 2 reached nodes (role A and role B), got %d: %v", len(reached), reached)
	}
	foundA, foundB := false, false
	for _, id := range reached {
		if id == roleA.CanonicalID {
			foundA = true
		}
		if id == roleB.CanonicalID {
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Errorf("Expected both role A and role B reached, got %v", reached)
	}
}

func TestCloudReachable_MaxHopsCapCutsOffLongChain(t *testing.T) {
	start := &CloudIdentity{CanonicalID: "test:n0", Kind: "iam-user"}
	n1 := &CloudResource{CanonicalID: "test:n1", Kind: "iam-role"}
	n1AsIdentity := &CloudIdentity{CanonicalID: n1.CanonicalID, Kind: "iam-role"}
	n2 := &CloudResource{CanonicalID: "test:n2", Kind: "iam-role"}
	n2AsIdentity := &CloudIdentity{CanonicalID: n2.CanonicalID, Kind: "iam-role"}
	n3 := &CloudResource{CanonicalID: "test:n3", Kind: "iam-role"}
	n3AsIdentity := &CloudIdentity{CanonicalID: n3.CanonicalID, Kind: "iam-role"}
	n4 := &CloudResource{CanonicalID: "test:n4", Kind: "iam-role"}
	n4AsIdentity := &CloudIdentity{CanonicalID: n4.CanonicalID, Kind: "iam-role"}
	n5 := &CloudResource{CanonicalID: "test:n5", Kind: "iam-role"}

	allow := map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`}
	// Edges are listed in REVERSED dependency order deliberately. Both
	// CloudReachable and adchain.Reachable (the pattern it mirrors) mutate
	// the reached set while iterating a single pass, so if these were
	// listed in forward order (start->n1, n1->n2, ...), all 5 hops would
	// cascade through in pass 0 alone -- n1 would be marked reached, and
	// the very next edge in the same pass would already see it. Listing
	// them backwards means each edge's enabling predecessor is later in
	// the slice, so it isn't satisfied until the NEXT pass, giving exactly
	// one new hop per pass -- the only way this test can exercise maxHops
	// meaningfully instead of finishing in one pass regardless of the cap.
	edges := []*CloudPermission{
		{Source: n4AsIdentity, Target: n5, Action: "sts:AssumeRole", SourceType: "identity-policy", Attributes: allow},
		{Source: n3AsIdentity, Target: n4, Action: "sts:AssumeRole", SourceType: "identity-policy", Attributes: allow},
		{Source: n2AsIdentity, Target: n3, Action: "sts:AssumeRole", SourceType: "identity-policy", Attributes: allow},
		{Source: n1AsIdentity, Target: n2, Action: "sts:AssumeRole", SourceType: "identity-policy", Attributes: allow},
		{Source: start, Target: n1, Action: "sts:AssumeRole", SourceType: "identity-policy", Attributes: allow},
	}

	evaluator := &AWSEvaluator{}

	// With maxHops=2 (passes 0 and 1), this reversed ordering advances the
	// frontier by exactly one new node per pass: pass 0 reaches only n1
	// (the start->n1 edge is last in the slice but is the only one whose
	// Source is already reached); pass 1 reaches only n2 (n1->n2 is now
	// satisfied, but n2->n3 still isn't, since it comes before n1->n2 in
	// the slice and n2 wasn't reached until partway through pass 1). So 2
	// passes reach n1 and n2 but never n3/n4/n5.
	reached := CloudReachable(edges, []string{start.CanonicalID}, evaluator, &RequestContext{}, 2)
	if len(reached) != 3 { // start, n1, n2
		t.Fatalf("Expected 3 reached nodes (start, n1, n2) with maxHops=2, got %d: %v", len(reached), reached)
	}

	path, ok := CloudPlan(edges, []string{start.CanonicalID}, n5.CanonicalID, evaluator, &RequestContext{}, 2)
	if ok {
		t.Fatalf("Expected CloudPlan to fail to confirm n5 within maxHops=2, got path %+v", path)
	}
}

func TestCloudReachable_MaxHopsZeroReturnsHeldUnchanged(t *testing.T) {
	start := &CloudIdentity{CanonicalID: "test:n0", Kind: "iam-user"}
	n1 := &CloudResource{CanonicalID: "test:n1", Kind: "iam-role"}
	edges := []*CloudPermission{
		{
			Source:     start,
			Target:     n1,
			Action:     "sts:AssumeRole",
			SourceType: "identity-policy",
			Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`},
		},
	}
	evaluator := &AWSEvaluator{}

	reached := CloudReachable(edges, []string{start.CanonicalID}, evaluator, &RequestContext{}, 0)
	if len(reached) != 1 || reached[0] != start.CanonicalID {
		t.Fatalf("Expected held unchanged with maxHops=0, got %v", reached)
	}

	_, ok := CloudPlan(edges, []string{start.CanonicalID}, n1.CanonicalID, evaluator, &RequestContext{}, 0)
	if ok {
		t.Fatal("Expected CloudPlan to return ok=false with maxHops=0 and target not already held")
	}
}

func TestCloudReachable_NonAssumableResourceNeverUnlocksMismatchedEdge(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker", Kind: "iam-user"}
	bucket := &CloudResource{CanonicalID: "arn:aws:s3:::reused-id-bucket", Kind: "s3-bucket"}

	// mismatchedSource deliberately reuses the bucket's CanonicalID as an
	// *identity* -- a nonsensical construction (buckets cannot act as
	// principals), simulating a data bug or adversarial edge. Reaching the
	// bucket must never make this edge traversable.
	mismatchedSource := &CloudIdentity{CanonicalID: bucket.CanonicalID, Kind: "iam-role"}
	otherTarget := &CloudResource{CanonicalID: "arn:aws:s3:::other-bucket", Kind: "s3-bucket"}

	edges := []*CloudPermission{
		{
			Source:     user,
			Target:     bucket,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reused-id-bucket/*"}]}`,
			},
		},
		{
			Source:     mismatchedSource,
			Target:     otherTarget,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::other-bucket/*"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	reached := CloudReachable(edges, []string{user.CanonicalID}, evaluator, &RequestContext{}, 10)

	for _, id := range reached {
		if id == otherTarget.CanonicalID {
			t.Fatalf("otherTarget must NOT be reachable -- the bucket's CanonicalID must never be treated as a valid Source just because it was reached as a Target, got reached=%v", reached)
		}
	}
	foundBucket := false
	for _, id := range reached {
		if id == bucket.CanonicalID {
			foundBucket = true
		}
	}
	if !foundBucket {
		t.Error("Expected the bucket itself to still be reachable (it's a legitimate dead-end target)")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cloudgraph/... -run TestCloudReachable -v`
Expected: FAIL — `undefined: CloudReachable` (compile error).

- [ ] **Step 3: Write the minimal implementation**

Append to `orchestrator/internal/cloudgraph/cloud_reachability.go`:

```go
// CloudReachable computes the closure of every CanonicalID reachable from
// held by repeatedly walking edges whose Source is already a legitimate
// traversal source and whose evaluation is viable, until a pass adds
// nothing new (fixpoint) or maxHops passes have run. Mirrors
// adchain.Reachable's exact shape, substituting the reachedAsSource/
// reachedAsTarget CanonicalID tracking described in spec amendment point 3
// for capability equality.
func CloudReachable(edges []*CloudPermission, held []string, evaluator AuthorizationEvaluator, ctx *RequestContext, maxHops int) []string {
	reached := append([]string{}, held...)
	reachedAsTarget := make(map[string]bool, len(reached))
	reachedAsSource := make(map[string]bool, len(reached))
	for _, id := range reached {
		reachedAsTarget[id] = true
		reachedAsSource[id] = true
	}

	for pass := 0; pass < maxHops; pass++ {
		added := false
		for _, edge := range edges {
			if !reachedAsSource[edge.Source.CanonicalID] {
				continue
			}
			if reachedAsTarget[edge.Target.CanonicalID] {
				continue
			}
			result := evaluator.EvaluatePermission(edge, ctx)
			if !isViable(result.State) {
				continue
			}
			reached = append(reached, edge.Target.CanonicalID)
			reachedAsTarget[edge.Target.CanonicalID] = true
			if assumableIdentityKinds[edge.Target.Kind] {
				reachedAsSource[edge.Target.CanonicalID] = true
			}
			added = true
		}
		if !added {
			break
		}
	}
	return reached
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/cloudgraph/... -run TestCloudReachable -v`
Expected: PASS — all 4 tests green. If any fails, use systematic-debugging; do not patch a test to match wrong behavior.

- [ ] **Step 5: Run the full package test suite (the plan's completion gate)**

Run: `go test ./internal/cloudgraph/... -v`
Expected: PASS — every test in the package green, including all pre-existing Phase 1-5 and Azure discovery tests (confirms this plan's additions caused zero regressions anywhere else in `cloudgraph`).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/cloudgraph/cloud_reachability.go orchestrator/internal/cloudgraph/cloud_reachability_test.go
git commit -m "feat(cloudgraph): CloudReachable -- closure of every CanonicalID reachable from a starting identity

Completes the intra-cloud multi-hop reachability capability (spec
docs/superpowers/specs/2026-10-13-intracloud-multihop-reachability-design.md
+ same-day amendment). CloudReachable and CloudPlan are standalone,
synthetic-fixture-tested functions -- not yet wired into live scenario
dispatch, campaigns, or hybrid_composition.go, matching the current state
of every other standalone cloudgraph capability built this initiative."
git push
```

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-13-intracloud-multihop-reachability.md`. Please review the plan. Does it capture what you want?

I recommend **Native/inline execution**: the three tasks are tightly sequential within one file (Task 2 and 3 both depend directly on Task 1's types, and nothing outside this plan depends on any of these interfaces yet), there are only three tasks total, and every prior increment in `orchestrator/internal/cloudgraph/` this initiative (Phases 1-5, the Azure discovery milestone) was executed the same way.

**If Native:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
