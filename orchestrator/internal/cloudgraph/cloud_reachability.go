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
