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

// SinkDataProtectionStatus turns the DLP sink's own evidence for one step into
// the status string DataProtectionFromDLPResult consumes. tokens is how many
// sink tokens the run issued for this technique, receipts how many of those
// tokens the sink received a POST for.
//
// A receipt means the data reached the sink, so DLP did not stop it (NotDetected).
// No receipt is not proof of a block: a transport failure looks the same, so
// this stays Unknown (fail closed) rather than claiming Detected. More than one
// token for the same run and technique is ambiguous, so it is also Unknown.
// Zero tokens means the step never used the sink, and returns "" so the caller
// records SkipInsufficientEvidence exactly as it does for any uncaptured step.
func SinkDataProtectionStatus(tokens, receipts int) (status, reason string) {
	switch {
	case tokens == 0:
		return "", "step did not use the DLP sink"
	case tokens > 1:
		return "Unknown", "more than one sink token for this run and technique; cannot attribute receipts"
	case receipts > 0:
		return "NotDetected", "sink received the synthetic payload; DLP did not block it"
	default:
		return "Unknown", "no sink receipt; cannot separate a DLP block from a transport failure"
	}
}
