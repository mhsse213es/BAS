// Package cveval is a vendor-neutral, I/O-free model for a CVE assessment's
// verdict and evidence. It mirrors internal/wafval's split: this package
// grades nothing it collects itself, only the shape of what a catalog entry
// or a lab execution hands it. It imports stdlib only. The lab adapter that
// actually drives a runtime probe against an isolated target is a separate,
// deferred concern (see internal/cvelab's Prober interface) -- this package
// never depends on it.
package cveval

import "time"

// Verdict is one of five terminal assessment states. Unlike wafval (which
// treats "not tested" as a catalog/execution status assigned above the
// evaluator), SKIPPED is a first-class verdict here: a CVE assessment that
// was skipped for missing preconditions or disabled lab access must still
// appear, explicitly, in a report -- never silently absent.
type Verdict string

const (
	VerdictVulnerable    Verdict = "VULNERABLE"
	VerdictNotVulnerable Verdict = "NOT_VULNERABLE"
	VerdictInconclusive  Verdict = "INCONCLUSIVE"
	VerdictError         Verdict = "ERROR"
	VerdictSkipped       Verdict = "SKIPPED"
)

func validVerdict(v Verdict) bool {
	switch v {
	case VerdictVulnerable, VerdictNotVulnerable, VerdictInconclusive, VerdictError, VerdictSkipped:
		return true
	default:
		return false
	}
}

// EvidenceSource says how a Result's evidence was produced. Never implied
// by which fields are populated.
type EvidenceSource string

const (
	// SourceFixture means the verdict came from comparing a caller-supplied
	// configuration indicator against the catalog entry's declared,
	// offline ConfigFixture signatures. No network I/O occurred.
	SourceFixture EvidenceSource = "fixture"
	// SourceLabRuntime means the verdict came from a real runtime probe
	// executed against an explicitly authorized, isolated-lab target.
	SourceLabRuntime EvidenceSource = "lab_runtime"
	// SourceNone means no evidence-producing step ran at all (SKIPPED/ERROR
	// before any comparison or probe).
	SourceNone EvidenceSource = ""
)

// ExecutionProfile says what kind of assessment a CVE catalog entry
// supports. Mirrored (not imported) by internal/cvecatalog's own type of
// the same name, matching wafcatalog/wafval's existing one-way dependency
// discipline: cveval never imports cvecatalog.
type ExecutionProfile string

const (
	// ProfileFixtureOnly means no safe runtime check exists for this CVE;
	// only a version/configuration comparison is possible.
	ProfileFixtureOnly ExecutionProfile = "fixture_only"
	// ProfileLabCapable means a controlled runtime probe exists for this
	// CVE, but it may only run against an explicitly authorized, isolated
	// lab target -- never by default, never against an unapproved or
	// public destination.
	ProfileLabCapable ExecutionProfile = "lab_capable"
)

// Evidence is what actually produced a verdict -- never truth, only what
// was observed or matched.
type Evidence struct {
	Source     EvidenceSource
	Detail     string // which fixture matched, or what a lab probe returned
	ObservedAt time.Time
	Target     string // empty for fixture-backed evidence; the lab target identifier for lab_runtime evidence
}

// Result is one CVE's assessment outcome.
type Result struct {
	CVEID    string
	Verdict  Verdict
	Evidence Evidence
	// Detail is the free-text reason, required for ERROR and SKIPPED, and
	// for INCONCLUSIVE when no fixture matched.
	Detail string
}

// ValidateResult rejects a Result that claims more than its evidence
// supports: never report a CVE as assessed merely because a Result value
// exists for it. VULNERABLE and NOT_VULNERABLE require real evidence
// (a non-empty Source and Detail); ERROR and SKIPPED require a free-text
// Detail explaining why, with no evidence required (there may be none to
// report); INCONCLUSIVE requires a Detail either way.
func ValidateResult(r Result) error {
	if r.CVEID == "" {
		return errCVEIDRequired
	}
	if !validVerdict(r.Verdict) {
		return newInvalidVerdictError(r.Verdict)
	}
	switch r.Verdict {
	case VerdictVulnerable, VerdictNotVulnerable:
		if r.Evidence.Source == SourceNone {
			return newMissingEvidenceError(r.Verdict)
		}
		if r.Evidence.Detail == "" {
			return newMissingEvidenceDetailError(r.Verdict)
		}
	case VerdictError, VerdictSkipped, VerdictInconclusive:
		if r.Detail == "" {
			return newMissingDetailError(r.Verdict)
		}
	}
	return nil
}
