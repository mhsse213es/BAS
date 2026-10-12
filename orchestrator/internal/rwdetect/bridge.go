// Package rwdetect bridges rwevidence's Detection capability toward the
// existing, generic detectverify.Connector interface -- mirroring
// internal/addetect's one-way bridge pattern exactly (addetect bridges
// AD-M08 the same way). Depends one-way on rwevidence and detectverify
// only; neither of those packages gains any rwdetect-awareness.
//
// This package performs no I/O and calls no Connector itself: wiring a
// real Connector into rwevidence.StepDependencies.Detection is a separate,
// later, lab-gated piece of work (Track I in the ransomware-mastery
// roadmap, same category as the real Recovery/Prevention observers). This
// package only builds the request and converts the eventual result -- the
// bridge's shape, not its real wiring.
package rwdetect

import (
	"fmt"
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/rwevidence"
)

// VerifyRequestFor builds a detectverify.VerifyRequest for checking
// whether executing tech was detected, given caller-supplied run/host/
// timing context (tech itself carries none of that -- it describes a
// technique, not an execution). Returns ok=false when tech.MitreID is
// empty: detectverify is keyed on TechniqueID, so a technique with no 1:1
// MITRE mapping cannot be checked this way.
func VerifyRequestFor(tech rwevidence.Technique, runID, expectationID, hostName, hostIP string, executedAt, windowStart, windowEnd time.Time) (detectverify.VerifyRequest, bool) {
	if tech.MitreID == "" {
		return detectverify.VerifyRequest{}, false
	}
	return detectverify.VerifyRequest{
		RunID:          runID,
		ExpectationID:  expectationID,
		TechniqueID:    tech.MitreID,
		HostName:       hostName,
		HostIP:         hostIP,
		StepExecutedAt: executedAt,
		WindowStart:    windowStart,
		WindowEnd:      windowEnd,
	}, true
}

// DetectionLookupResultFor converts a resolved detectverify.VerifyResult
// into rwevidence.DetectionLookup's (tested, verified, reason) return
// shape. tested is always true here: by the time a VerifyResult exists,
// the query against the provider actually ran and returned a definitive
// Detected/NotDetected verdict -- a transport/auth error surfaces as a
// non-nil error from Connector.Verify itself, before any VerifyResult
// exists, and that error propagates directly as LookupDetection's own
// error return, never through this converter.
func DetectionLookupResultFor(result detectverify.VerifyResult) (tested bool, verified bool, reason string) {
	tested = true
	verified = result.Verdict == detectverify.VerdictDetected
	if !verified {
		return tested, verified, "no matching alerts found in the query window"
	}
	plural := "s"
	if len(result.MatchedAlerts) == 1 {
		plural = ""
	}
	return tested, verified, fmt.Sprintf("%d alert%s matched, confidence=%s", len(result.MatchedAlerts), plural, result.Confidence)
}
