package reporting

import (
	"regexp"

	"github.com/audspect/bas/internal/scenario"
)

// DLP Validation Suite — Phase B, the first real consumer of the Outcome
// Validation Framework (Phase A). Registers the "dlp" outcome family's
// comparator and a local-observation verifier that never claims more than an
// OS-level fact proves.
//
// A local script can only observe whether the file operation it attempted
// (USB copy, clipboard write, print, archive, local staging) succeeded or was
// prevented — a primitive fact, not a policy verdict. A Warn-and-continue
// policy produces the identical local symptom as no policy at all (the
// operation succeeds either way), so a local observer that concluded
// "Allow" from a bare success would be claiming evidence it doesn't have.
// dlpComparator keeps that distinction explicit: it compares the DLP outcome
// catalog's richer vocabulary (Allow/Block/Warn/Justify/Audit/Quarantine/
// Encrypt/Redact) against one of three primitive observations, not against
// itself.

// Primitive observations a local verifier can honestly report.
const (
	ObservationSucceeded = "OperationSucceeded"
	ObservationBlocked   = "OperationBlocked"
	ObservationUnknown   = "OperationUnknown"
)

// dlpComparator is the "dlp" family's Comparator. The asymmetry is
// deliberate: an observed block is informative regardless of what was
// expected — something clearly intervened, which is real policy drift even
// against a softer expected outcome, not missing evidence. An observed
// success is only conclusive against Allow/Block; every softer expected
// outcome (Warn/Justify/Audit/Quarantine/Encrypt/Redact) stays honestly
// MissingEvidence, since success alone can't confirm which of those fired.
type dlpComparator struct{}

func (dlpComparator) Compare(expected, observed string) ComparisonResult {
	switch observed {
	case ObservationBlocked:
		if expected == "Block" {
			return Match
		}
		return Mismatch
	case ObservationSucceeded:
		switch expected {
		case "Allow":
			return Match
		case "Block":
			return Mismatch
		default:
			return MissingEvidence
		}
	default: // ObservationUnknown, or any unrecognized token
		return MissingEvidence
	}
}

func init() {
	RegisterComparator("dlp", dlpComparator{})
}

var dlpMarkerRe = regexp.MustCompile(`(?m)^DLP_OBSERVATION:\s*(\S+)$`)

// dlpVerifier resolves DLP expectations from a step's self-reported outcome
// marker. The script itself does the post-condition check (did the file land
// on the USB path, does Get-Clipboard now match, etc.) and prints exactly
// one deterministic line; this verifier only parses it. It never re-derives
// observations from vendor-specific error text — that would be exactly the
// fragile heuristic classifySkipReason's own doc comment warns against for
// third-party output. An absent or unrecognized marker always resolves to
// ObservationUnknown — never guessed as a known primitive.
type dlpVerifier struct{}

func (dlpVerifier) Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
	r := baseResult(exp, ev, "automatic")
	r.ExpectedOutcome = scenario.ResolveExpectedOutcome(exp)

	observed := ObservationUnknown
	if m := dlpMarkerRe.FindStringSubmatch(ev.RawOutput); m != nil {
		switch m[1] {
		case ObservationSucceeded, ObservationBlocked:
			observed = m[1]
		}
	}
	r.ObservedOutcome = observed
	r.Comparison = comparatorFor("dlp").Compare(r.ExpectedOutcome, r.ObservedOutcome)
	r.Status = collapseToStatus(r.Comparison)
	return r
}
