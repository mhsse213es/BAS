package cloudgraph

// edgeKey builds the lookup key for a permission edge's evaluation state.
// Shared between DiscoveredGraph.Evaluations writers and readers.
func edgeKey(edge *CloudPermission) string {
	return edge.Source.CanonicalID + "->" + edge.Action + "->" + edge.Target.CanonicalID
}

// GateDecision is the step gate's verdict on whether a step may be dispatched.
type GateDecision struct {
	Allowed bool
	Reason  string
}

// StepGate prevents dispatch of a step whose permission edge is known-Blocked
// or known-Unknown. This is a dispatch-time safety check distinct from the
// PrerequisiteResolver's pre-flight filter: the resolver runs once before the
// scenario starts, the gate runs before each individual step.
type StepGate struct{}

// ShouldDispatch blocks dispatch only on a KNOWN-bad evaluation (Blocked or
// Unknown). An edge with no evaluation entry at all is allowed through here —
// absence of evaluation is the resolver's concern (it reports UNKNOWN as a
// prerequisite), not grounds for the gate to halt an already-approved scenario.
func (g *StepGate) ShouldDispatch(edge *CloudPermission, graph *DiscoveredGraph) *GateDecision {
	state, evaluated := graph.Evaluations[edgeKey(edge)]
	if !evaluated {
		return &GateDecision{Allowed: true}
	}

	switch state {
	case Blocked:
		return &GateDecision{Allowed: false, Reason: "edge evaluates to Blocked; dispatch would not reflect a real attack path"}
	case Unknown:
		return &GateDecision{Allowed: false, Reason: "edge evaluation is Unknown; dispatching would risk an unverified claim"}
	default:
		return &GateDecision{Allowed: true}
	}
}
