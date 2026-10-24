package reporting

// AttackFlowGroup is one technique in the kill-chain table, with every step
// that ran it listed inside. Primary and counterpart runs of the same technique
// sit side by side in the flow, so they render as one row instead of two.
// Nothing is dropped: each step keeps its own name, verdict and control.
type AttackFlowGroup struct {
	TechniqueID   string           `json:"techniqueId"`
	TechniqueName string           `json:"techniqueName"`
	Tactic        string           `json:"tactic"`
	TacticLabel   string           `json:"tacticLabel"`
	Severity      string           `json:"severity"`
	DurationMs    int64            `json:"durationMs"`
	Steps         []AttackFlowNode `json:"steps"`
}

// groupAttackFlow merges only ADJACENT nodes that share a technique and tactic.
// A repeat of a technique after a different one is a new point in the kill
// chain, so it is kept as its own group rather than folded backwards.
func groupAttackFlow(nodes []AttackFlowNode) []AttackFlowGroup {
	var out []AttackFlowGroup
	for _, n := range nodes {
		last := len(out) - 1
		if last >= 0 && out[last].TechniqueID == n.TechniqueID && out[last].Tactic == n.Tactic {
			out[last].Steps = append(out[last].Steps, n)
			out[last].DurationMs += n.DurationMs
			continue
		}
		out = append(out, AttackFlowGroup{
			TechniqueID:   n.TechniqueID,
			TechniqueName: n.TechniqueName,
			Tactic:        n.Tactic,
			TacticLabel:   n.TacticLabel,
			Severity:      n.Severity,
			DurationMs:    n.DurationMs,
			Steps:         []AttackFlowNode{n},
		})
	}
	return out
}
