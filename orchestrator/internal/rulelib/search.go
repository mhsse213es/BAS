package rulelib

import "strings"

// SearchFilter combines any number of dimensions; an empty field means "no
// filter on that dimension". All non-empty fields are ANDed together.
type SearchFilter struct {
	Technique string
	Backend   string
	Status    string
	Severity  string
	LogSource string
	Query     string // free-text, matched case-insensitively against Title
}

// Search returns every rule matching every non-empty filter field.
func (e *Engine) Search(f SearchFilter) []Rule {
	candidates := e.rules
	if f.Technique != "" {
		candidates = e.idx.byTechnique[f.Technique]
	}

	var out []Rule
	for _, r := range candidates {
		if f.Backend != "" && !hasBackend(r, f.Backend) {
			continue
		}
		if f.Status != "" && r.Status != f.Status {
			continue
		}
		if f.Severity != "" && r.Severity != f.Severity {
			continue
		}
		if f.LogSource != "" && r.LogSource.Category != f.LogSource {
			continue
		}
		if f.Query != "" && !strings.Contains(strings.ToLower(r.Title), strings.ToLower(f.Query)) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func hasBackend(r Rule, backend string) bool {
	for _, t := range r.Translations {
		if t.Backend == backend {
			return true
		}
	}
	return false
}
