# Intra-Cloud Multi-Hop Reachability — Design

**Date:** 2026-10-13
**Package:** `orchestrator/internal/cloudgraph/`
**New file:** `cloud_reachability.go` (+ `cloud_reachability_test.go`)

## Context and motivation

`orchestrator/internal/cloudgraph/` (built 2026-10-12, Cloud BAS Mastery Phases 1-5, all synthetic-fixture-tested) already lets each of `AWSEvaluator`/`AzureEvaluator`/`GCPEvaluator` answer, for a **single** `CloudPermission` edge, "does this one edge's policy allow this action" (`EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult`, returning one of the six `PathState` values: `Candidate`/`ConditionallyReachable`/`PolicySupported`/`Observed`/`Blocked`/`Unknown`).

What's missing — confirmed via the reconciliation addendum added to `CLOUD_BAS_MASTERY_GAP_ANALYSIS.md` (commit `409b6f41`) — is a **multi-hop** layer: given a set of edges, can identity A reach resource C through a chain (A assumes role B, which can access C)? `orchestrator/internal/adchain/search.go` already solves the equivalent problem for on-prem AD (`Reachable`/`Plan` over `adprimitive.Capability`/`Primitive`), and this design mirrors its proven shape natively for `cloudgraph`'s own graph types, rather than reusing `adchain`'s capability-based types (Phase 1's reuse assessment, `docs/cloud-bas-reuse-assessment.md`, already found AD mastery is capability-based, not graph-based, and `cloudgraph` deliberately built its own `CloudResource`/`CloudIdentity`/`CloudPermission` graph types for this reason).

This closes the one piece of `CLOUD_BAS_MASTERY_GAP_ANALYSIS.md`'s "Component 2: IAM/Permission Graph Builder" that's still genuinely open after the addendum (intra-cloud multi-hop search; `hybrid_composition.go`'s `ComposeHybridPath` already solves the narrower AD-side-reachability-crosses-one-federation-edge case and is untouched by this work). It is purely an algorithm over synthetic fixtures — no real cloud tenant is needed, unlike the separately-tracked, currently-blocked Azure real-discovery work.

Business framing (not binding on the implementation, context only): `cloud.txt` §1 ("Cloud identity and privilege escalation": *"can an ordinary identity obtain access to a privileged cloud role"*) and §7's architecture layer 03 (*"Represent permissions, trust relationships, reachability, resource dependencies and potential privilege transitions"*) both describe exactly this capability as part of the target cloud attack-path graph.

## Scope

- **In scope:** a native, single-provider, fixpoint-closure graph search over `[]*CloudPermission` edges, two functions (`CloudReachable`, `CloudPlan`), their result types, and synthetic-fixture tests.
- **Out of scope (explicitly deferred, not silently dropped):**
  - Cross-provider paths in one search (e.g. AWS→Azure in a single `CloudPlan` call). `AuthorizationEvaluator` is one-per-provider by Phase 5's architectural decision; a cross-provider path would need to pick the right evaluator per hop, which is a distinct, more careful design (akin to `hybrid_composition.go`'s fresh-federation-evidence requirement) and not folded into this generic search.
  - A "show the path even though it's blocked" reporting mode. This design's `CloudPlan` only ever returns a path of *viable* hops; a non-viable hop is a dead end, not a reported partial path. Flagged as a known trade-off, deferred by explicit choice during brainstorming.
  - Wiring either function into live scenario dispatch, campaigns, or the orchestrator API. Both functions are standalone and callable, matching the current state of `RunMultiAccount`, `ComposeHybridPath`, and `ExecuteCloudRansomwareScenario` — all built, tested, and not yet called from production code. Wiring is future work.

## Types

```go
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
```

- `CloudHop` pairs the edge with the per-hop `*EvaluationResult` the evaluator already produces — nothing new is computed, just retained for the caller.
- `CloudPath.OverallState` is computed by an unexported `worstState(states []PathState) PathState`: `Blocked` beats everything; `Unknown` beats every "supported" state; `PolicySupported`/`Observed` only win when every hop is one of those two. This names and makes reusable the precedence `ransomware_scenario.go`'s chain-stops-at-first-block pattern already assumes informally.
  - In practice, because `CloudPlan` only ever records *viable* hops (see below), `OverallState` on a returned path will only ever be `PolicySupported` or `Observed` — `worstState` is written generally, but a `CloudPath` as constructed by this file never actually exercises its `Blocked`/`Unknown` branches. Those branches exist for `worstState`'s own direct unit tests and for any future caller that assembles a `CloudPath` by hand from a mix of viable and non-viable hops.

## Algorithm

```go
// isViable reports whether a hop's evaluation result is strong enough
// evidence to trust propagating reachability through it. Only
// PolicySupported (a policy predicts this edge works) and Observed (evidence
// confirms it actually did) qualify -- Blocked, Unknown, Candidate, and
// ConditionallyReachable all stop the chain at that edge rather than risk
// inferring a path that isn't real.
func isViable(state PathState) bool {
    return state == PolicySupported || state == Observed
}

// CloudReachable computes the closure of every CanonicalID reachable from
// held by repeatedly walking edges whose Source is already reached and
// whose evaluation is viable, until a pass adds nothing new (fixpoint) or
// maxHops passes have run. Mirrors adchain.Reachable's exact shape,
// substituting CanonicalID-set membership for capability equality.
func CloudReachable(edges []*CloudPermission, held []string, evaluator AuthorizationEvaluator, ctx *RequestContext, maxHops int) []string

// CloudPlan searches for one ordered path from held to target, returning
// ok=false if target is never reached within maxHops passes. Mirrors
// adchain.Plan's exact shape.
func CloudPlan(edges []*CloudPermission, held []string, target string, evaluator AuthorizationEvaluator, ctx *RequestContext, maxHops int) (*CloudPath, bool)
```

Design decisions, each confirmed during brainstorming:

1. **Single provider per call.** The caller supplies one `AuthorizationEvaluator`; every edge passed to a given call is assumed to belong to that provider. Cross-provider paths are out of scope (see above).
2. **`held`/`target` are plain `CanonicalID` strings, not identity/resource objects.** This sidesteps ever needing to classify whether a reached node is "really" an identity or a resource. Critically, it also means **no kind-based "which resource kinds can become identities" logic is needed at all**: the existing `e2e_test.go` precedent already shows the *caller* constructing a second edge with a `CloudIdentity` whose `CanonicalID` matches the first edge's role-resource target (`roleAsAssumedIdentity := &CloudIdentity{CanonicalID: role.CanonicalID, ...}`) to continue a chain manually. This search algorithm simply matches `CanonicalID` strings across the reached frontier against each edge's `Source.CanonicalID` — the caller's edge set already encodes any role-promotion the way `e2e_test.go` does it by hand.
3. **Fixpoint closure, bounded by an explicit `maxHops` safety cap.** Per pass: for each edge, skip if `edge.Source.CanonicalID` isn't already reached, or `edge.Target.CanonicalID` already is (the `adchain.Plan`-style re-add guard). Otherwise evaluate; if `isViable`, mark `edge.Target.CanonicalID` reached. Stop a pass-loop when a pass adds nothing new (natural fixpoint — this is what actually terminates a cycle, e.g. role A and role B mutually trusting each other) or when `maxHops` passes have run (defensive cap against a pathological fixture or future bug in the closure logic). `CloudReachable` returns whatever closure it has if `maxHops` is exhausted before a fixpoint — a partial closure, not an error, matching the six-state model's "never silently claim more than the evidence supports" spirit. `CloudPlan` returns `ok=false` if `target` isn't reached within the cap.
4. **`CloudPlan` records only the hops that contributed a newly-reached node, in application order** — exactly `adchain.Plan`'s `path = append(path, p)` pattern — stopping the instant `target` becomes reached. `OverallState` is computed via `worstState` over only those recorded hops.
5. **File placement:** a new file, not an extension of `hybrid_composition.go`. That file's job is specifically AD→cloud crossing (real `adchain.Reachable`, one federation edge, one cloud edge) — a narrow, special-purpose composition that stays completely untouched. A future version of `hybrid_composition.go` could replace its single "evaluate one cloud edge" step with a call to `CloudPlan`, but that wiring is not part of this design.

## Error handling and edge cases

- `AuthorizationEvaluator.EvaluatePermission` is synchronous policy evaluation with no I/O and returns no error (confirmed in `evaluator.go`), so neither function needs an error return. `CloudPlan`'s `bool` mirrors `adchain.Plan`'s `ok` exactly.
- A `held` entry matching no edge's `Source.CanonicalID` is not an error — it simply contributes no new reachability, the same as `adchain.Reachable` given a primitive whose postconditions are already all held.
- **`target` already in `held` at call time:** `CloudPlan` returns `(&CloudPath{Hops: nil, OverallState: PolicySupported}, true)` immediately. `PolicySupported` is the explicit default for "trivially already there, no edge to doubt" since there's no hop to derive a state from.
- **`maxHops <= 0`:** falls out of the loop bound naturally — `CloudReachable` returns `held` unchanged; `CloudPlan` returns `ok=false` unless `target` was already in `held` (previous bullet). No explicit guard or panic is added for this case.
- **Multiple viable edges between the same `Source`/`Target` pair** (e.g. one `role-trust` edge and one `identity-policy` edge happening to share endpoints): whichever is evaluated first in iteration order marks the target reached; later edges to the already-reached target are skipped by the re-add guard. The specific edge recorded in a path is therefore iteration-order-dependent when ties exist — accepted as-is, mirroring `adchain.Plan`'s own catalog-order dependency, rather than adding unrequested tie-breaking logic.

## Testing plan

All tests in `cloud_reachability_test.go`, synthetic fixtures only (no real cloud access), following `aws_evaluator_test.go`/`e2e_test.go`'s existing style (hand-built `CloudIdentity`/`CloudResource`/`CloudPermission` literals, `AWSEvaluator{}`).

1. **Two-hop happy path** — rebuild `e2e_test.go`'s exact scenario (user → assume role → read bucket) through `CloudPlan`; assert both hops are found in order and `OverallState == PolicySupported`. Directly proves the new search reproduces what the hand-written e2e test already proved by hand.
2. **Blocked hop stops the chain** — a role-trust edge evaluating to `Blocked` (principal mismatch, mirroring `aws_evaluator_test.go`'s existing deny fixture): `CloudPlan` to a target past that edge returns `ok=false`; `CloudReachable` doesn't include anything past it.
3. **Target already held** — `CloudPlan` with `target` already in `held` returns immediately with no hops and `OverallState == PolicySupported`.
4. **Cycle terminates via fixpoint** — role A trusts role B and role B trusts role A (mutual `sts:AssumeRole`, both `PolicySupported`): `CloudReachable` includes both exactly once and returns promptly, proving the fixpoint logic itself — not just the `maxHops` cap — is what stops it.
5. **`maxHops` cap cuts off a long chain** — a 5-edge linear chain with `maxHops=2`: `CloudPlan` to the far end returns `ok=false`; `CloudReachable` returns only the first 2 hops' worth of nodes. Proves the cap is load-bearing, independent of the cycle test above.
6. **Mixed-strength hops compute worst-state correctly end-to-end** — a path where hop 1 evaluates `Observed` and hop 2 evaluates `PolicySupported`: `OverallState == PolicySupported` (the weaker of the two), proving `worstState` is actually consulted through the full search, not just unit-tested in isolation.
7. **`worstState` unit tests directly** — table-driven: all-`PolicySupported` → `PolicySupported`; any-`Blocked` present → `Blocked`; any-`Unknown` present with no `Blocked` → `Unknown`. Isolated from the search so a future change to the precedence rule has a fast, focused test to fail.

This gives direct coverage of every type, algorithm decision, and edge case in this spec.
