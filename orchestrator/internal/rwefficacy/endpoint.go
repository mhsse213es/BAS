package rwefficacy

import (
	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
)

// EndpointStep is one step's endpoint verdict from the run's results. It is
// not capability evidence: it says what the step's own check reported, not
// whether a control prevented, detected, or contained the behavior.
type EndpointStep struct {
	TechniqueID string `json:"techniqueId"`
	StepName    string `json:"stepName"`
	Result      string `json:"result"`
	Details     string `json:"details,omitempty"`
}

// EndpointOnly returns the steps whose technique was not graded by any
// capability observer. A technique counts as graded only when at least one of
// its rows is a real PASS or FAIL. Rows that are SKIPPED, ERROR or
// not_applicable are not grading, so their steps stay here. The overall
// statement does not use this list.
func EndpointOnly(rows []db.RWAttemptRow, steps []EndpointStep) []EndpointStep {
	graded := map[string]bool{}
	for _, r := range rows {
		if r.Verdict == controlval.VerdictPass || r.Verdict == controlval.VerdictFail {
			graded[r.TechniqueID] = true
		}
	}
	out := []EndpointStep{}
	for _, s := range steps {
		if !graded[s.TechniqueID] {
			out = append(out, s)
		}
	}
	return out
}
