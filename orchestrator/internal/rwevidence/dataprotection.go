package rwevidence

import "github.com/audspect/bas/internal/controlval"

// DataProtectionFromDLPResult wraps the EXISTING DLP Validation Suite's
// result (internal/reporting's Outcome Validation Framework, "dlp"
// comparator family -- see reporting/dlp.go) into a DataProtection
// CapabilityResult. It is a deliberate scope-down of the full
// "double-extortion validation" roadmap item: this adapts the one existing
// DLP signal, not a new correlated-exfiltration engine.
//
// status takes the 4 values reporting.collapseToStatus already produces
// ("Detected"/"NotDetected"/"NotApplicable"/"Unknown") as a plain string
// rather than importing the reporting package directly -- rwevidence stays
// a pure evidence/logic package with no dependency on the presentation-
// layer reporting package. The caller (wherever the DLP VerificationResult
// is produced) does that one-line translation. No new DLP engine, no
// duplicated detection logic -- same "adapt, don't reinvent" discipline as
// Prevention's adapter to controlval.
func DataProtectionFromDLPResult(tech Technique, status string, reason string) CapabilityResult {
	cr := CapabilityResult{Capability: CapabilityDataProtection, TechniqueID: tech.MitreID, Reason: reason}
	switch status {
	case "Detected":
		cr.Verdict = controlval.VerdictPass
	case "NotDetected":
		cr.Verdict = controlval.VerdictFail
	case "NotApplicable":
		cr.Verdict = controlval.VerdictSkipped
		cr.SkipReason = controlval.SkipNotApplicable
	default: // "Unknown" or anything unrecognized -- fail closed
		cr.Verdict = controlval.VerdictSkipped
		cr.SkipReason = controlval.SkipInsufficientEvidence
	}
	return cr
}
