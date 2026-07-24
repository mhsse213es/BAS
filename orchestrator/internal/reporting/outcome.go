package reporting

import "sync"

// Outcome Validation Framework — Phase A comparison layer.
//
// A Comparator encapsulates one outcome family's comparison semantics: given
// an expected outcome value and an observed outcome value (both opaque
// strings from the family's own vocabulary — see internal/scenario/outcome_catalog.go),
// it produces a ComparisonResult. This package never interprets what any
// outcome value means; it only ever asks the family's registered Comparator.
//
// Phase A registers exactly one family, "detection" — the extraction (not
// rewrite) of automaticVerifier's pre-existing binary detected/not-detected
// logic. Status, the field every existing scoring/report code path consumes,
// becomes derived from ComparisonResult via collapseToStatus rather than
// computed independently — binary detection is a specialization of outcome
// validation, not a system running alongside it.

// ComparisonResult is the richer internal verdict a Comparator produces,
// before collapseToStatus reduces it to a Status for existing report code.
type ComparisonResult string

const (
	Match           ComparisonResult = "Match"
	Mismatch        ComparisonResult = "Mismatch"
	MissingEvidence ComparisonResult = "MissingEvidence"
	NotApplicable   ComparisonResult = "NotApplicable"
	Unknown         ComparisonResult = "Unknown"
)

// Comparator compares one outcome family's expected and observed values.
type Comparator interface {
	Compare(expectedOutcome, observedOutcome string) ComparisonResult
}

var (
	comparatorMu       sync.RWMutex
	comparatorRegistry = map[string]Comparator{}
)

// RegisterComparator adds or replaces a family's comparator.
func RegisterComparator(family string, c Comparator) {
	comparatorMu.Lock()
	defer comparatorMu.Unlock()
	comparatorRegistry[family] = c
}

// noopComparator is the fallback for an unregistered family: it never treats
// an unrecognized family as a match or mismatch, only Unknown.
type noopComparator struct{}

func (noopComparator) Compare(string, string) ComparisonResult { return Unknown }

// comparatorFor returns the registered Comparator for family, or a no-op
// Unknown-only comparator if none is registered.
func comparatorFor(family string) Comparator {
	comparatorMu.RLock()
	defer comparatorMu.RUnlock()
	if c, ok := comparatorRegistry[family]; ok {
		return c
	}
	return noopComparator{}
}

// detectionComparator is the "detection" family's Comparator — the binary
// detected/not-detected model every expectation used before this phase.
type detectionComparator struct{}

func (detectionComparator) Compare(expected, observed string) ComparisonResult {
	switch {
	case observed == "":
		return MissingEvidence
	case observed == expected:
		return Match
	default:
		return Mismatch
	}
}

func init() {
	RegisterComparator("detection", detectionComparator{})
}

// collapseToStatus reduces a ComparisonResult to the legacy Status string
// every existing scoring/report code path consumes.
func collapseToStatus(c ComparisonResult) string {
	switch c {
	case Match:
		return StatusDetected
	case Mismatch:
		return StatusNotDetected
	case NotApplicable:
		return StatusNotApplicable
	default: // MissingEvidence, Unknown
		return StatusUnknown
	}
}
