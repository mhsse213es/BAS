package reporting

import (
	"regexp"
	"strings"

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
	if isSkipMarker(ev.RawOutput) {
		// A step that never ran (client tool absent, technique not
		// applicable, etc.) produced no attempt at all -- SinkTokenObserved
		// being false here is the absence of an attempt, not evidence the
		// attempt was blocked. Checked BEFORE SinkTokenObserved so a skip
		// can never resolve to ObservationBlocked. See
		// docs/superpowers/specs/2026-09-01-sftp-exfiltration-channel-design.md.
		r.ObservedOutcome = observed // ObservationUnknown
		r.Comparison = comparatorFor("dlp").Compare(r.ExpectedOutcome, r.ObservedOutcome)
		r.Status = collapseToStatus(r.Comparison)
		return r
	}
	if ev.SinkTokenObserved != nil {
		// Sink-primary: destination-side receipt is authoritative ground
		// truth for whether the data actually left, superseding the local
		// marker for this step -- see
		// docs/superpowers/specs/2026-08-19-dlp-exfiltration-sink-service-design.md.
		if *ev.SinkTokenObserved {
			observed = ObservationSucceeded
		} else {
			observed = ObservationBlocked
		}
	} else if m := dlpMarkerRe.FindStringSubmatch(ev.RawOutput); m != nil {
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

// isSkipMarker reports whether raw's first line matches the "skip:"
// convention internal/scenario/outcome.go's classifyExecution already
// established (case-insensitive, leading whitespace tolerated). This is a
// small local equivalent, not a cross-package call: internal/scenario's
// own firstLine/classifyExecution use the identical convention, but
// firstLine is unexported there and this package deliberately stays a
// pure function throughout (see this file's own top-of-file doc comment).
func isSkipMarker(raw string) bool {
	first, _, _ := strings.Cut(strings.TrimLeft(raw, "\r\n"), "\n")
	first = strings.TrimSpace(first)
	return len(first) >= 5 && strings.EqualFold(first[:5], "skip:")
}
