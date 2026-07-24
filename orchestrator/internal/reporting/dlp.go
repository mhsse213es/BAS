package reporting

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
