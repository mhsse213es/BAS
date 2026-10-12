package cloudgraph

// RansomwareStep is one step in a cloud ransomware kill chain: a permission
// edge to evaluate, tagged with the MITRE ATT&CK technique it represents.
type RansomwareStep struct {
	Name         string
	TechniqueTag string
	Edge         *CloudPermission
}

// CloudRansomwareScenario is an ordered kill chain evaluated against a single
// provider evaluator. Real multi-cloud kill chains would need per-step
// evaluators (a step touching AWS then a step touching Azure); Phase 5 scopes
// this to one evaluator per scenario, matching the single-account kill chains
// already shipped for on-prem AD ransomware families.
type CloudRansomwareScenario struct {
	Steps     []*RansomwareStep
	Evaluator AuthorizationEvaluator
}

// RansomwareExecutionResult collects one outcome per executed step and an
// overall verdict. Steps after the first Blocked step are never executed --
// mirrors how StepGate halts dispatch on a known-bad edge.
type RansomwareExecutionResult struct {
	StepOutcomes   []*CloudControlOutcome
	OverallVerdict string // "fully-blocked", "partially-blocked", "fully-open"
}

// ExecuteCloudRansomwareScenario evaluates each step in order using the
// scenario's own edge (never a cached or prior step's state), stopping at the
// first Blocked step. The chain includes the blocking step's own outcome,
// then halts -- it never evaluates steps after a block.
func ExecuteCloudRansomwareScenario(scenario *CloudRansomwareScenario, graph *DiscoveredGraph) *RansomwareExecutionResult {
	result := &RansomwareExecutionResult{}

	anyBlocked := false
	anySucceeded := false

	for _, step := range scenario.Steps {
		eval := scenario.Evaluator.EvaluatePermission(step.Edge, &RequestContext{})

		outcome := &CloudControlOutcome{
			PrerequisiteState: eval.State,
			ControlName:       step.Name,
		}
		if eval.State == PolicySupported {
			outcome.ExecutionOutcome = "Allowed"
			anySucceeded = true
		} else {
			outcome.ExecutionOutcome = "Blocked"
			anyBlocked = true
		}

		result.StepOutcomes = append(result.StepOutcomes, outcome)

		if eval.State != PolicySupported {
			break // stop the chain at the first block
		}
	}

	switch {
	case anyBlocked && !anySucceeded:
		result.OverallVerdict = "fully-blocked"
	case anyBlocked && anySucceeded:
		result.OverallVerdict = "partially-blocked"
	default:
		result.OverallVerdict = "fully-open"
	}

	return result
}
