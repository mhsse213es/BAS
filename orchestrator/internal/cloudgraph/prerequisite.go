package cloudgraph

// DiscoveredGraph holds everything discovered for one account scope: the raw
// inventory (identities, resources, permissions) plus any evaluation/audit
// results already computed for that inventory. Evaluations is keyed by
// "source->action->target" (same key shape a scenario step uses to name an edge).
type DiscoveredGraph struct {
	Identities        []*CloudIdentity
	Resources         []*CloudResource
	Permissions       []*CloudPermission
	Evaluations       map[string]PathState // edge key -> evaluated state
	AuditAvailability map[string]string    // audit source name -> "available"/"unavailable"
}

// CloudPrerequisite declares what a scenario needs before it is worth attempting.
type CloudPrerequisite struct {
	Kind   string // "cloud_identity", "cloud_resource", "cloud_permission", "audit_availability"
	Target string // CanonicalID, or "source->action->target" edge key, or audit source name
}

// PrerequisiteResult is the resolver's verdict for one prerequisite.
// Status is NOT an authorization decision — it is a pre-flight filter:
// OK means "worth attempting," never "permitted."
type PrerequisiteResult struct {
	Prerequisite *CloudPrerequisite
	Status       string // "OK", "MISSING", "DEGRADED", "UNKNOWN"
	Detail       string
}

// PrerequisiteResolver checks declared prerequisites against a discovered graph.
type PrerequisiteResolver struct{}

// Resolve evaluates each prerequisite against the graph. A prerequisite kind
// the resolver does not recognize resolves UNKNOWN (never silently OK or MISSING):
// an unrecognized kind means the resolver cannot tell, not that the thing is absent.
func (r *PrerequisiteResolver) Resolve(prereqs []*CloudPrerequisite, graph *DiscoveredGraph) []*PrerequisiteResult {
	results := make([]*PrerequisiteResult, 0, len(prereqs))

	for _, p := range prereqs {
		results = append(results, r.resolveOne(p, graph))
	}

	return results
}

func (r *PrerequisiteResolver) resolveOne(p *CloudPrerequisite, graph *DiscoveredGraph) *PrerequisiteResult {
	switch p.Kind {
	case "cloud_identity":
		for _, id := range graph.Identities {
			if id.CanonicalID == p.Target {
				return &PrerequisiteResult{Prerequisite: p, Status: "OK"}
			}
		}
		return &PrerequisiteResult{Prerequisite: p, Status: "MISSING", Detail: "identity not found in discovery"}

	case "cloud_resource":
		for _, res := range graph.Resources {
			if res.CanonicalID == p.Target {
				return &PrerequisiteResult{Prerequisite: p, Status: "OK"}
			}
		}
		return &PrerequisiteResult{Prerequisite: p, Status: "MISSING", Detail: "resource not found in discovery"}

	case "cloud_permission":
		state, evaluated := graph.Evaluations[p.Target]
		if !evaluated {
			return &PrerequisiteResult{Prerequisite: p, Status: "UNKNOWN", Detail: "edge not yet evaluated"}
		}
		switch state {
		case Blocked:
			return &PrerequisiteResult{Prerequisite: p, Status: "DEGRADED", Detail: "edge exists but evaluates to Blocked"}
		case Unknown:
			return &PrerequisiteResult{Prerequisite: p, Status: "UNKNOWN", Detail: "edge evaluation inconclusive"}
		default:
			return &PrerequisiteResult{Prerequisite: p, Status: "OK"}
		}

	case "audit_availability":
		status, known := graph.AuditAvailability[p.Target]
		if !known {
			return &PrerequisiteResult{Prerequisite: p, Status: "UNKNOWN", Detail: "audit source status not checked"}
		}
		if status == "unavailable" {
			return &PrerequisiteResult{Prerequisite: p, Status: "UNKNOWN", Detail: "audit source reported unavailable"}
		}
		return &PrerequisiteResult{Prerequisite: p, Status: "OK"}

	default:
		return &PrerequisiteResult{Prerequisite: p, Status: "UNKNOWN", Detail: "unrecognized prerequisite kind: " + p.Kind}
	}
}
