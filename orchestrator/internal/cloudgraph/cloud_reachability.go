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
