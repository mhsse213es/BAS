package rulelib

// buildIndexes constructs the lookup maps used by RuleByID/RulesByTechnique/
// Search. Called once from loadFromBytes so every read afterward is O(1)
// map access, never a linear scan.
type indexes struct {
	byID        map[string]Rule
	byTechnique map[string][]Rule
	byBackend   map[string][]Rule
	byStatus    map[string][]Rule
	bySeverity  map[string][]Rule
}

func buildIndexes(rules []Rule) indexes {
	idx := indexes{
		byID:        make(map[string]Rule, len(rules)),
		byTechnique: map[string][]Rule{},
		byBackend:   map[string][]Rule{},
		byStatus:    map[string][]Rule{},
		bySeverity:  map[string][]Rule{},
	}
	for _, r := range rules {
		idx.byID[r.ID] = r
		for _, t := range r.TechniqueIDs {
			idx.byTechnique[t] = append(idx.byTechnique[t], r)
		}
		for _, tr := range r.Translations {
			idx.byBackend[tr.Backend] = append(idx.byBackend[tr.Backend], r)
		}
		idx.byStatus[r.Status] = append(idx.byStatus[r.Status], r)
		idx.bySeverity[r.Severity] = append(idx.bySeverity[r.Severity], r)
	}
	return idx
}

func (e *Engine) RuleByID(id string) (Rule, bool) {
	r, ok := e.idx.byID[id]
	return r, ok
}

func (e *Engine) RulesByTechnique(techniqueID string) []Rule {
	return e.idx.byTechnique[techniqueID]
}
