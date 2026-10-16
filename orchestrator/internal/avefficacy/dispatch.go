package avefficacy

import (
	"fmt"
	"regexp"
	"time"

	"github.com/audspect/bas/internal/avval"
)

// This file is the real (non-fixture) bridge from a dispatched scenario
// step's outcome into avval's evidence model -- av.txt's own directive
// that a vector's efficacy must be established through real correlation,
// never equating a single execution result with a finding. It replaces
// hand-authored VectorFixture.PreventionEvidence with evidence built from
// what a dispatch actually reported.

// DispatchedStepResult is the minimal shape BuildCollectionResultsFromDispatch
// needs from one real, dispatched scenario step's outcome. The caller (once
// any avscenario-built scenario is registered for live dispatch -- a
// pre-existing gap shared by every dispatchable AV vector, not specific to
// one) maps its own scenario.Step/models.SimulationResult types onto this;
// this package never imports internal/api or internal/scenario, keeping it
// pure, the same discipline internal/rwevidence.StepInput follows.
type DispatchedStepResult struct {
	// PreventionSource is the control source the dispatched command's own
	// return-value observation is attributed to (e.g.
	// avval.ControlSourceNGAVBehavioral for AV-BEHAV-001's Win32 API
	// outcome).
	PreventionSource avval.ControlSource
	// DetectionSource is the control source a SEPARATE, independent
	// detection-telemetry check is attributed to (e.g.
	// avval.ControlSourceAVEngine for a local Defender-log lookback). Zero
	// value means no detection-telemetry check was performed at all for
	// this dispatch -- distinct from one that ran and found nothing.
	DetectionSource avval.ControlSource
	Provider        string
	// CheckResult mirrors models.CheckResult's string values:
	// "pass"/"fail"/"skipped"/"error".
	CheckResult string
	Details     string
	ObservedAt  time.Time
}

// detectionTokenPattern matches the "detection=<TOKEN>" convention every
// harness built against this bridge writes into its own stdout (see
// catalog_behavioral.go's AV-BEHAV-001 harness contract).
var detectionTokenPattern = regexp.MustCompile(`detection=(DETECTED|NOT_OBSERVED|UNAVAILABLE)`)

// BuildCollectionResultsFromDispatch turns one real dispatched step's
// outcome into the []avval.CollectionResult shape VectorFixture.
// PreventionEvidence already consumes -- a drop-in replacement for a
// hand-authored fixture, built from what the dispatch actually reported
// rather than asserted. An "error" CheckResult is a dispatch/operational
// failure, not security evidence, and is returned as a Go error rather than
// fabricated into a finding.
func BuildCollectionResultsFromDispatch(result DispatchedStepResult) ([]avval.CollectionResult, error) {
	switch result.CheckResult {
	case "error":
		return nil, fmt.Errorf("dispatch reported an operational error, not security evidence: %s", result.Details)
	case "skipped":
		out := []avval.CollectionResult{{ControlSource: result.PreventionSource, Coverage: avval.CoverageSearchIncomplete}}
		return out, nil
	case "pass", "fail":
		prevention := avval.PreventionAllowed
		if result.CheckResult == "pass" {
			prevention = avval.PreventionBlocked
		}
		out := []avval.CollectionResult{{
			ControlSource: result.PreventionSource,
			Coverage:      avval.CoverageFound,
			Observations: []avval.Observation{{
				ControlSource: result.PreventionSource,
				Provider:      result.Provider,
				ObservedAt:    result.ObservedAt,
				Prevention:    prevention,
				EvidenceKind:  avval.EvidenceObserved,
				Detail:        result.Details,
			}},
		}}
		if result.DetectionSource != "" {
			out = append(out, detectionCollectionResult(result.DetectionSource, result))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unrecognized CheckResult %q", result.CheckResult)
	}
}

// detectionCollectionResult builds the Detection-axis CollectionResult from
// the harness's own "detection=<TOKEN>" stdout convention. Absent or
// unrecognized tokens resolve to CoverageSearchIncomplete -- a parsing gap
// is never read as a verified negative.
func detectionCollectionResult(source avval.ControlSource, result DispatchedStepResult) avval.CollectionResult {
	m := detectionTokenPattern.FindStringSubmatch(result.Details)
	if m == nil {
		return avval.CollectionResult{ControlSource: source, Coverage: avval.CoverageSearchIncomplete}
	}
	switch m[1] {
	case "UNAVAILABLE":
		return avval.CollectionResult{ControlSource: source, Coverage: avval.CoverageSourceUnavailable}
	case "DETECTED":
		return avval.CollectionResult{
			ControlSource: source,
			Coverage:      avval.CoverageFound,
			Observations: []avval.Observation{{
				ControlSource: source,
				ObservedAt:    result.ObservedAt,
				Detection:     avval.DetectionDetected,
				EvidenceKind:  avval.EvidenceObserved,
				Detail:        result.Details,
			}},
		}
	default: // NOT_OBSERVED
		return avval.CollectionResult{
			ControlSource: source,
			Coverage:      avval.CoverageSearchedVerifiedNone,
			Observations: []avval.Observation{{
				ControlSource: source,
				ObservedAt:    result.ObservedAt,
				Detection:     avval.DetectionNotObservedInWindow,
				EvidenceKind:  avval.EvidenceObserved,
				Detail:        result.Details,
			}},
		}
	}
}
