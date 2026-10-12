package rwevidence

import "github.com/audspect/bas/internal/controlval"

// DetectionFromProfileResult wraps the existing windows_vss_inhibition
// detection-profile verification result (already live, Microsoft-Defender
// auto-verified, wired across all 7 ransomware scenarios) into a Detection
// CapabilityResult. No new detection plumbing in this slice -- a
// detectverify-based rwdetect bridge (mirroring latdetect/addetect) for
// real alert-latency measurement is a separable later phase.
//
// tested distinguishes "the profile ran and gave a definitive result" from
// "nothing has evaluated this yet": when tested is false, profileVerified
// is ignored and the result is Skipped/SkipNotTested.
func DetectionFromProfileResult(tech Technique, tested bool, profileVerified bool, reason string) CapabilityResult {
	cr := CapabilityResult{Capability: CapabilityDetection, TechniqueID: tech.MitreID, Reason: reason}
	switch {
	case !tested:
		cr.Verdict = controlval.VerdictSkipped
		cr.SkipReason = controlval.SkipNotTested
	case profileVerified:
		cr.Verdict = controlval.VerdictPass
	default:
		cr.Verdict = controlval.VerdictFail
	}
	return cr
}
