package reporting

// TechniqueMatrixGroup is one technique in the Detection Validation matrix,
// with each step that ran it listed inside. Steps keep their own verdicts,
// alerts and cleanup results; the group only shares the technique, tactic and
// severity cells, so the matrix shows one block per technique.
type TechniqueMatrixGroup struct {
	TechniqueID   string         `json:"techniqueId"`
	TechniqueName string         `json:"techniqueName"`
	Tactic        string         `json:"tactic"`
	Severity      string         `json:"severity"`
	Steps         []TechniqueRow `json:"steps"`
}

// groupTechniqueMatrix merges only ADJACENT rows that share a technique and
// tactic, so the order of the kill chain is kept.
func groupTechniqueMatrix(rows []TechniqueRow) []TechniqueMatrixGroup {
	var out []TechniqueMatrixGroup
	for _, r := range rows {
		last := len(out) - 1
		if last >= 0 && out[last].TechniqueID == r.TechniqueID && out[last].Tactic == r.Tactic {
			out[last].Steps = append(out[last].Steps, r)
			continue
		}
		out = append(out, TechniqueMatrixGroup{
			TechniqueID:   r.TechniqueID,
			TechniqueName: r.TechniqueName,
			Tactic:        r.Tactic,
			Severity:      r.Severity,
			Steps:         []TechniqueRow{r},
		})
	}
	return out
}
