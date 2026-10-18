// Package dlpcorrelate sequences and aggregates already-computed verdicts
// from DLP-POL/DLP-CLS/DLP-ENF and the channel-sink evaluators into one
// ordered, multi-stage campaign result -- dlp.txt §3C's "cross-channel and
// multi-stage scenarios." It never re-implements or second-guesses any of
// those evaluators' own Verify logic; it only translates their
// already-computed outputs into one shared currency (StageResult) and
// applies a chain-stop/non-offsetting rule across the sequence, mirroring
// internal/avefficacy/multistage.go's own pattern (borrowed, never
// imported -- that package is AV-domain-coupled and does not apply here).
// See docs/superpowers/specs/2026-10-18-dlpcorrelate-design.md.
package dlpcorrelate

import "fmt"

// StageOutcome is the one currency every DLP evaluator's own verdict is
// translated into by the campaign definition's own code (never by this
// package, which has no DLP-domain knowledge of its own).
type StageOutcome string

const (
	// StageContinues: this stage's own check passed or let the data keep
	// moving (e.g. correct classification, no unauthorized block exercised
	// yet) -- chain advances.
	StageContinues StageOutcome = "continues"
	// StageCaught: this stage caught/blocked the violation -- chain stops
	// advancing here, same as avefficacy's FindingVerifiedProtection.
	StageCaught StageOutcome = "caught"
	// StageFailed: this stage's own check is a confirmed failure (e.g.
	// misclassification, unauthorized disclosure succeeded) -- recorded,
	// chain still advances per the non-offsetting rule: a failure here
	// must not be hidden, but it also must not synthetically stop a chain
	// whose real behavior was to let the data through.
	StageFailed StageOutcome = "failed"
	// StageInconclusive: missing evidence -- chain stops advancing, same
	// as avefficacy's inconclusive handling.
	StageInconclusive StageOutcome = "inconclusive"
	// StageNotTested: no evaluator capability exists for this stage at
	// all (distinct from Inconclusive: this is "we cannot test this
	// today," not "we tried and the evidence was missing") -- chain stops
	// advancing.
	StageNotTested StageOutcome = "not_tested"
)

// stops reports whether outcome halts the chain's advancement.
func (o StageOutcome) stops() bool {
	switch o {
	case StageCaught, StageInconclusive, StageNotTested:
		return true
	default:
		return false
	}
}

// StageResult is one stage's outcome, evidence reason, and position.
type StageResult struct {
	StageOrder   int
	Label        string
	Dimension    string // which evaluator produced this: "DLP-CLS" | "DLP-CLS-LABEL" | "DLP-ENF" | "" (not_tested)
	Outcome      StageOutcome
	Reason       string
	StageSkipped bool // true when the chain stopped before this stage was reached
}

// StageDefinition names a stage before it has a result -- used to build
// the "skipped" placeholder for every stage after the chain stops.
type StageDefinition struct {
	Label     string
	Dimension string
}

// CorrelationChain is an ordered, named campaign -- dlp.txt §3C's own
// campaign definitions become one CorrelationChain each, with a fixed
// Stages list and the caller supplying one evaluated StageResult per
// reachable stage.
type CorrelationChain struct {
	ID     string
	Name   string
	Stages []StageDefinition
}

// ChainResult is the aggregate, non-offsetting verdict for one evaluated
// chain run.
type ChainResult struct {
	ChainID        string
	StageResults   []StageResult
	AnyFailed      bool // true if ANY stage (reached or not) resolved StageFailed -- never cleared by a later stage
	AnyNotTested   bool
	StoppedAtLabel string // empty if the chain ran to completion
}

// EvaluateCorrelationChain takes a chain definition and the caller's own
// pre-computed results for each stage it was able to reach (reached may
// be shorter than chain.Stages -- this function fills in StageSkipped
// placeholders for the rest), applies the chain-stop/non-offsetting rule,
// and returns the aggregate.
func EvaluateCorrelationChain(chain CorrelationChain, reached []StageResult) (ChainResult, error) {
	if len(reached) > len(chain.Stages) {
		return ChainResult{}, fmt.Errorf("reached has %d entries, chain %q only declares %d stages", len(reached), chain.ID, len(chain.Stages))
	}
	for i, r := range reached {
		if r.StageOrder != i+1 {
			return ChainResult{}, fmt.Errorf("reached[%d].StageOrder = %d, want %d (stage order must match position)", i, r.StageOrder, i+1)
		}
	}

	result := ChainResult{ChainID: chain.ID}
	stoppedAtLabel := ""

	for i, def := range chain.Stages {
		if i < len(reached) {
			r := reached[i]
			result.StageResults = append(result.StageResults, r)
			if r.Outcome == StageFailed {
				result.AnyFailed = true
			}
			if r.Outcome == StageNotTested {
				result.AnyNotTested = true
			}
			if r.Outcome.stops() {
				stoppedAtLabel = r.Label
			}
			continue
		}
		// Stage not reached by the caller -- either the chain already
		// stopped at an earlier stage, or the caller itself never
		// evaluated this stage at all.
		reason := fmt.Sprintf("stage %q not reached", def.Label)
		if stoppedAtLabel != "" {
			reason = fmt.Sprintf("stage %q not reached -- chain already interrupted at %q", def.Label, stoppedAtLabel)
		}
		result.StageResults = append(result.StageResults, StageResult{
			StageOrder:   i + 1,
			Label:        def.Label,
			Dimension:    def.Dimension,
			StageSkipped: true,
			Reason:       reason,
		})
	}

	if len(reached) < len(chain.Stages) && len(reached) > 0 {
		result.StoppedAtLabel = reached[len(reached)-1].Label
	}
	return result, nil
}
