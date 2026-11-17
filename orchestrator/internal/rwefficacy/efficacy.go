// Package rwefficacy turns a run's per-attempt capability evidence into an
// honest run-level answer: was the ransomware behavior prevented, detected,
// contained and recoverable, and what is not proven. Pure computation (no
// DB, no HTTP). It never infers across dimensions and never reads a skipped
// or errored attempt as protection.
package rwefficacy

import (
	"sort"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
)

// Status is one dimension's run-level standing.
type Status string

const (
	StatusProven        Status = "proven"         // every applicable attempt PASSed
	StatusPartial       Status = "partial"        // some PASS, others skipped or errored
	StatusUnproven      Status = "unproven"       // no evidence, or only skips/errors
	StatusGap           Status = "gap"            // at least one FAIL
	StatusNotApplicable Status = "not_applicable" // every attempt was not_applicable
)

// Overall is the run-level statement.
type Overall string

const (
	OverallGapsFound Overall = "gaps_found" // a control failed
	OverallUnproven  Overall = "unproven"   // nothing failed but detection/containment/recovery is not fully proven
	OverallEvidenced Overall = "evidenced"  // all three required dimensions proven, no gaps anywhere
)

// DimensionSummary carries every count, not just the status.
type DimensionSummary struct {
	Status        Status `json:"status"`
	Attempts      int    `json:"attempts"` // excludes not_applicable
	Pass          int    `json:"pass"`
	Fail          int    `json:"fail"`
	Error         int    `json:"error"`
	Skipped       int    `json:"skipped"`
	NotApplicable int    `json:"notApplicable"`
}

// Attempt is one (technique, action) with its worst-case verdict per
// capability, so a later FAIL is never hidden behind an earlier PASS.
type Attempt struct {
	TechniqueID string                        `json:"techniqueId"`
	Action      string                        `json:"action"`
	Verdicts    map[string]controlval.Verdict `json:"verdicts"`
}

// Report is the full result for one run.
type Report struct {
	Overall    Overall                     `json:"overall"`
	Dimensions map[string]DimensionSummary `json:"dimensions"`
	Attempts   []Attempt                   `json:"attempts"`
}

var allDimensions = []string{"prevention", "detection", "containment", "recovery", "data_protection"}
var required = []string{"detection", "containment", "recovery"}

func severity(v controlval.Verdict, sr controlval.SkipReason) int {
	switch {
	case v == controlval.VerdictFail:
		return 4
	case v == controlval.VerdictError:
		return 3
	case v == controlval.VerdictSkipped && sr != controlval.SkipNotApplicable:
		return 2
	case v == controlval.VerdictPass:
		return 1
	}
	return 0 // not_applicable
}

// Build computes the report from every attempt row of one run.
func Build(rows []db.RWAttemptRow) Report {
	sums := map[string]*DimensionSummary{}
	for _, d := range allDimensions {
		sums[d] = &DimensionSummary{}
	}
	type key struct{ t, a string }
	worst := map[key]map[string]db.RWAttemptRow{}
	for _, r := range rows {
		s, ok := sums[r.Capability]
		if !ok {
			continue
		}
		switch {
		case r.Verdict == controlval.VerdictSkipped && r.SkipReason == controlval.SkipNotApplicable:
			s.NotApplicable++
		case r.Verdict == controlval.VerdictPass:
			s.Pass++
		case r.Verdict == controlval.VerdictFail:
			s.Fail++
		case r.Verdict == controlval.VerdictError:
			s.Error++
		default:
			s.Skipped++
		}
		k := key{r.TechniqueID, r.Action}
		if worst[k] == nil {
			worst[k] = map[string]db.RWAttemptRow{}
		}
		if cur, seen := worst[k][r.Capability]; !seen || severity(r.Verdict, r.SkipReason) > severity(cur.Verdict, cur.SkipReason) {
			worst[k][r.Capability] = r
		}
	}
	rep := Report{Dimensions: map[string]DimensionSummary{}, Attempts: []Attempt{}}
	for d, s := range sums {
		s.Attempts = s.Pass + s.Fail + s.Error + s.Skipped
		switch {
		case s.Fail > 0:
			s.Status = StatusGap
		case s.Attempts == 0 && s.NotApplicable > 0:
			s.Status = StatusNotApplicable
		case s.Attempts == 0:
			s.Status = StatusUnproven
		case s.Pass == s.Attempts:
			s.Status = StatusProven
		case s.Pass > 0:
			s.Status = StatusPartial
		default:
			s.Status = StatusUnproven
		}
		rep.Dimensions[d] = *s
	}
	for k, caps := range worst {
		a := Attempt{TechniqueID: k.t, Action: k.a, Verdicts: map[string]controlval.Verdict{}}
		for c, r := range caps {
			a.Verdicts[c] = r.Verdict
		}
		rep.Attempts = append(rep.Attempts, a)
	}
	sort.Slice(rep.Attempts, func(i, j int) bool {
		if rep.Attempts[i].TechniqueID != rep.Attempts[j].TechniqueID {
			return rep.Attempts[i].TechniqueID < rep.Attempts[j].TechniqueID
		}
		return rep.Attempts[i].Action < rep.Attempts[j].Action
	})
	rep.Overall = OverallEvidenced
	for _, d := range allDimensions {
		if rep.Dimensions[d].Status == StatusGap {
			rep.Overall = OverallGapsFound
			return rep
		}
	}
	for _, d := range required {
		if rep.Dimensions[d].Status != StatusProven {
			rep.Overall = OverallUnproven
		}
	}
	return rep
}
