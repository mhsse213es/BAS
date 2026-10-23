// Package bench is the held-out evaluation harness for Aleef Milestone 1. It
// scores a campaign's results against ground-truth labels that only the owner
// holds. It is deliberately ignorant of the benchmark bank: the caller supplies
// a run callback that executes one build and returns a RunOutcome, so this
// package imports neither the bank, its sealed policies nor the campaign.
// cmd/aleef-bench is the only place that wires those in.
//
// A flaw counts as detected only when a VERIFIED finding on the vulnerable
// build targets the label's operation, reproduced at least three times, with
// the owner control and negative control passing and a saved regression. A
// candidate never counts. A verified finding that matches no label is flagged
// for human review and is not scored. Any verified finding on the fixed build
// fails the milestone.
package bench

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/aleef/store"
)

// Build names passed to the run callback.
const (
	BuildFixed      = "fixed"
	BuildVulnerable = "vulnerable"
)

// MinReproductions is the number of consecutive reproductions a verified
// finding needs to count.
const MinReproductions = 3

// Per-flaw reasons.
const (
	ReasonNotFound           = "not found"
	ReasonCandidateOnly      = "found-but-unverified-candidate"
	ReasonIncompleteEvidence = "verified-but-incomplete-evidence"
	ReasonVerified           = "verified"
)

// Finding is one finding together with the operation its test targeted.
type Finding struct {
	store.Finding
	Operation string
}

// RunOutcome is everything the harness needs from one build's campaign.
type RunOutcome struct {
	// Findings are the VERIFIED findings; Candidates the unverified ones.
	Findings   []Finding
	Candidates []Finding

	TestsGenerated, TestsRun int
	// CoveragePerOperation counts tests per operation; operations with no tests
	// must be present with 0.
	CoveragePerOperation map[string]int
	// OperationAliases optionally maps an operation id to its "METHOD /path"
	// form so labels written either way can be matched.
	OperationAliases map[string]string

	// SafetyChecks are checks the harness could assess. SafetyNotAssessed
	// names checks it could not assess (the owner assesses them elsewhere).
	SafetyChecks      map[string]bool
	SafetyNotAssessed []string

	// Per finding id.
	ControlsOK      map[string]bool
	RegressionSaved map[string]bool
	Reproductions   map[string]int

	// Halted is the campaign's stop reason, informational.
	Halted string
}

// FlawResult is the scored result of one label.
type FlawResult struct {
	ID, Operation, Note string
	Verified            bool
	FindingIDs          []string
	Reason              string
	Detail              string
	Controls            bool
	Regression          bool
	Reproductions       int
	// TestsOnOperation is the exact number of tests generated for the label's
	// operation on the vulnerable build.
	TestsOnOperation int
}

// FindingRef names a finding in the report.
type FindingRef struct {
	FindingID, TestID, Property, Operation string
}

// Report is the evaluation result.
type Report struct {
	PerFlaw []FlawResult

	Labels             int
	Verified           int
	Required           int
	Recall             float64
	FixedBuildVerified int
	// FixedBuildFindings lists every verified finding on the fixed build;
	// FixedBuildCandidates lists unverified ones (informational, possible
	// false positives to investigate).
	FixedBuildFindings   []FindingRef
	FixedBuildCandidates []FindingRef
	Unlabelled           []FindingRef

	// Totals and coverage are those of the vulnerable build (the evaluated
	// one); the fixed build's are kept separately.
	TestsGenerated, TestsRun           int
	CoveragePerOperation               map[string]int
	FixedTestsGenerated, FixedTestsRun int
	FixedCoveragePerOperation          map[string]int

	SafetyChecks      map[string]bool
	SafetyNotAssessed []string
	Halted            map[string]string

	Pass        bool
	PassReasons []string
}

// RequiredDetections is the number of detected flaws needed to pass: the
// spec's 6 of 8, generalised as ceil(0.75 * n).
func RequiredDetections(n int) int {
	return int(math.Ceil(0.75 * float64(n)))
}

func norm(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// targets reports whether finding operation op is the label's operation.
func targets(l Label, op string, aliases map[string]string) bool {
	lo := norm(l.Operation)
	if norm(op) == lo {
		return true
	}
	if a, ok := aliases[op]; ok && norm(a) == lo {
		return true
	}
	return false
}

func ref(f Finding) FindingRef {
	return FindingRef{FindingID: f.ID, TestID: f.TestID, Property: f.Property, Operation: f.Operation}
}

// evidenceGap returns why a verified finding does not meet the detection bar,
// or "" when it does.
func evidenceGap(o RunOutcome, id string) string {
	var gaps []string
	if n := o.Reproductions[id]; n < MinReproductions {
		gaps = append(gaps, fmt.Sprintf("%d reproductions (need %d)", n, MinReproductions))
	}
	if !o.ControlsOK[id] {
		gaps = append(gaps, "owner/negative control not passed")
	}
	if !o.RegressionSaved[id] {
		gaps = append(gaps, "no saved regression")
	}
	return strings.Join(gaps, "; ")
}

// Evaluate runs both builds and scores the vulnerable one against labels.
func Evaluate(ctx context.Context, labels []Label, run func(build string) (RunOutcome, error)) (Report, error) {
	var rep Report
	if len(labels) == 0 {
		return rep, errors.New("bench: no labels")
	}
	if err := ctx.Err(); err != nil {
		return rep, err
	}
	fixed, err := run(BuildFixed)
	if err != nil {
		return rep, fmt.Errorf("bench: fixed build run: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return rep, err
	}
	vuln, err := run(BuildVulnerable)
	if err != nil {
		return rep, fmt.Errorf("bench: vulnerable build run: %w", err)
	}

	rep.Labels = len(labels)
	rep.Required = RequiredDetections(len(labels))
	rep.TestsGenerated, rep.TestsRun = vuln.TestsGenerated, vuln.TestsRun
	rep.CoveragePerOperation = copyCov(vuln.CoveragePerOperation)
	rep.FixedTestsGenerated, rep.FixedTestsRun = fixed.TestsGenerated, fixed.TestsRun
	rep.FixedCoveragePerOperation = copyCov(fixed.CoveragePerOperation)
	rep.Halted = map[string]string{}
	if fixed.Halted != "" {
		rep.Halted[BuildFixed] = fixed.Halted
	}
	if vuln.Halted != "" {
		rep.Halted[BuildVulnerable] = vuln.Halted
	}

	// ---- fixed build
	for _, f := range fixed.Findings {
		rep.FixedBuildFindings = append(rep.FixedBuildFindings, ref(f))
	}
	rep.FixedBuildVerified = len(rep.FixedBuildFindings)
	for _, f := range fixed.Candidates {
		rep.FixedBuildCandidates = append(rep.FixedBuildCandidates, ref(f))
	}

	// ---- vulnerable build, per flaw. One finding credits at most one flaw.
	used := map[string]bool{}
	matched := map[string]bool{}
	for _, l := range labels {
		fr := FlawResult{ID: l.ID, Operation: l.Operation, Note: l.Note, Reason: ReasonNotFound}
		fr.TestsOnOperation = coverageFor(vuln, l)
		var gapDetail string
		sawVerified := false
		for _, f := range vuln.Findings {
			if !targets(l, f.Operation, vuln.OperationAliases) {
				continue
			}
			matched[f.ID] = true
			if used[f.ID] {
				continue
			}
			sawVerified = true
			gap := evidenceGap(vuln, f.ID)
			if gap != "" {
				if gapDetail == "" {
					gapDetail = f.ID + ": " + gap
				}
				continue
			}
			used[f.ID] = true
			fr.Verified = true
			fr.Reason = ReasonVerified
			fr.FindingIDs = []string{f.ID}
			fr.Controls = vuln.ControlsOK[f.ID]
			fr.Regression = vuln.RegressionSaved[f.ID]
			fr.Reproductions = vuln.Reproductions[f.ID]
			break
		}
		if !fr.Verified {
			switch {
			case sawVerified:
				fr.Reason, fr.Detail = ReasonIncompleteEvidence, gapDetail
			default:
				for _, c := range vuln.Candidates {
					if targets(l, c.Operation, vuln.OperationAliases) {
						fr.Reason = ReasonCandidateOnly
						fr.FindingIDs = append(fr.FindingIDs, c.ID)
					}
				}
			}
		}
		if fr.Verified {
			rep.Verified++
		}
		rep.PerFlaw = append(rep.PerFlaw, fr)
	}
	rep.Recall = float64(rep.Verified) / float64(len(labels))
	for _, f := range vuln.Findings {
		if !matched[f.ID] {
			rep.Unlabelled = append(rep.Unlabelled, ref(f))
		}
	}

	// ---- safety: a check passes only when true on both builds.
	rep.SafetyChecks = map[string]bool{}
	for _, o := range []RunOutcome{fixed, vuln} {
		for k, v := range o.SafetyChecks {
			if prev, ok := rep.SafetyChecks[k]; ok {
				v = v && prev
			}
			rep.SafetyChecks[k] = v
		}
	}
	seen := map[string]bool{}
	for _, o := range []RunOutcome{fixed, vuln} {
		for _, n := range o.SafetyNotAssessed {
			if !seen[n] {
				seen[n] = true
				rep.SafetyNotAssessed = append(rep.SafetyNotAssessed, n)
			}
		}
	}
	sort.Strings(rep.SafetyNotAssessed)

	rep.score(fixed, vuln)
	return rep, nil
}

// coverageFor returns the number of tests on the label's operation.
func coverageFor(o RunOutcome, l Label) int {
	total := 0
	for op, n := range o.CoveragePerOperation {
		if targets(l, op, o.OperationAliases) {
			total += n
		}
	}
	return total
}

func copyCov(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (r *Report) score(fixed, vuln RunOutcome) {
	pass := true
	add := func(ok bool, format string, a ...any) {
		prefix := "PASS: "
		if !ok {
			prefix = "FAIL: "
			pass = false
		}
		r.PassReasons = append(r.PassReasons, prefix+fmt.Sprintf(format, a...))
	}
	add(r.Verified >= r.Required, "%d of %d labelled flaws detected (need at least %d), each with a verified finding, %d reproductions, owner and negative control and a saved regression",
		r.Verified, r.Labels, r.Required, MinReproductions)
	add(r.FixedBuildVerified == 0, "%d verified findings on the fixed build (must be 0)", r.FixedBuildVerified)

	var failed []string
	for k, v := range r.SafetyChecks {
		if !v {
			failed = append(failed, k)
		}
	}
	sort.Strings(failed)
	switch {
	case len(fixed.SafetyChecks) == 0 || len(vuln.SafetyChecks) == 0:
		add(false, "a build reported no safety checks")
	case len(failed) > 0:
		add(false, "safety checks failed: %s", strings.Join(failed, ", "))
	default:
		add(true, "all %d assessed safety checks passed", len(r.SafetyChecks))
	}
	if len(r.SafetyNotAssessed) > 0 {
		r.PassReasons = append(r.PassReasons, "NOTE: not assessed by the harness, the owner must assess: "+strings.Join(r.SafetyNotAssessed, ", "))
	}
	add(vuln.TestsRun > 0 && fixed.TestsRun > 0, "tests were executed on both builds (fixed %d, vulnerable %d)", fixed.TestsRun, vuln.TestsRun)
	if len(r.Unlabelled) > 0 {
		r.PassReasons = append(r.PassReasons, fmt.Sprintf("NOTE: %d unlabelled verified finding(s) on the vulnerable build are not scored and need human review", len(r.Unlabelled)))
	}
	r.Pass = pass
}
