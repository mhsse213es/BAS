package scenario

import "sync"

// Outcome Validation Framework — Phase A vocabulary layer.
//
// A validation domain (Detection Validation today; future domains like device
// control or SOAR response later) declares an OutcomeCatalog: the set of
// values an expectation may name as its ExpectedOutcome, plus the implicit
// default when a step doesn't declare one. This package only holds the
// vocabulary — comparison semantics (how two outcome values are judged to
// match) live in internal/reporting, which is where evidence is evaluated.
//
// Named outcome_catalog.go (not outcome.go) — that filename is already taken
// by this package's ExecutionOutcome/classifyExecution PASS/FAIL/ERROR/SKIPPED
// classification layer, an unrelated concept from a different feature.

// OutcomeCatalog is the set of valid outcome values for one outcome family.
type OutcomeCatalog struct {
	Family           string
	Values           []string
	ImplicitExpected string
}

var (
	outcomeMu       sync.RWMutex
	outcomeRegistry = map[string]OutcomeCatalog{}
)

// RegisterOutcomeCatalog adds or replaces a family's catalog.
func RegisterOutcomeCatalog(c OutcomeCatalog) {
	outcomeMu.Lock()
	defer outcomeMu.Unlock()
	outcomeRegistry[c.Family] = c
}

// ValidOutcome reports whether value is a recognized outcome for family. An
// unregistered family never validates anything — content referencing an
// unknown family is rejected at load time, not silently accepted.
func ValidOutcome(family, value string) bool {
	outcomeMu.RLock()
	defer outcomeMu.RUnlock()
	c, ok := outcomeRegistry[family]
	if !ok {
		return false
	}
	for _, v := range c.Values {
		if v == value {
			return true
		}
	}
	return false
}

// implicitExpected returns the family's default ExpectedOutcome, or "" if the
// family is unregistered.
func implicitExpected(family string) string {
	outcomeMu.RLock()
	defer outcomeMu.RUnlock()
	return outcomeRegistry[family].ImplicitExpected
}

// familyKnown reports whether family has a registered catalog. Used at
// load-time validation to reject content naming an unknown family — a direct
// registry check, not inferred from ImplicitExpected being non-empty (a
// future family could legitimately have no implicit default).
func familyKnown(family string) bool {
	outcomeMu.RLock()
	defer outcomeMu.RUnlock()
	_, ok := outcomeRegistry[family]
	return ok
}

func init() {
	RegisterOutcomeCatalog(OutcomeCatalog{
		Family:           "detection",
		Values:           []string{"Detected", "NotDetected"},
		ImplicitExpected: "Detected",
	})
	// "dlp" — Phase B (Data Protection Validation, DLP capability). The full
	// catalog is richer than any current verifier can prove: only Block/Allow
	// are locally observable (see internal/reporting/dlp.go's dlpComparator).
	// Warn/Justify/Audit/Quarantine/Encrypt/Redact exist so a future DLP
	// product connector can populate profiles that declare them, without a
	// catalog change.
	RegisterOutcomeCatalog(OutcomeCatalog{
		Family:           "dlp",
		Values:           []string{"Allow", "Block", "Warn", "Justify", "Audit", "Quarantine", "Encrypt", "Redact"},
		ImplicitExpected: "Block",
	})
}

// ResolveOutcomeFamily returns the outcome family for an expectation: its
// explicit OutcomeFamily, else "detection" — the implicit family every
// existing expectation belongs to today.
func ResolveOutcomeFamily(exp ExpectedDetection) string {
	if exp.OutcomeFamily != "" {
		return exp.OutcomeFamily
	}
	return "detection"
}

// ResolveExpectedOutcome returns the outcome value an expectation requires:
// its explicit ExpectedOutcome, else its resolved family's implicit default.
func ResolveExpectedOutcome(exp ExpectedDetection) string {
	if exp.ExpectedOutcome != "" {
		return exp.ExpectedOutcome
	}
	return implicitExpected(ResolveOutcomeFamily(exp))
}
