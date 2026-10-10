// Package latdetect bridges lateral-movement techniques (internal/latmove)
// into the existing, generic detectverify.Connector interface -- the
// movement-path's step 6 (did the connected EDR/SIEM detect it). Depends
// one-way on latmove and detectverify only; neither of those packages gains
// any lateral-movement- or detection-awareness. Mirrors addetect's bridge to
// adprimitive exactly, applied to this technique family.
//
// Detection effectiveness and control efficacy (latmove's ControlProvider)
// are INDEPENDENT axes, same invariant controlval enforces: a technique can
// execute and succeed with no SIEM alert, or get blocked and still alert.
// Neither reads the other's result.
package latdetect

import (
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/latmove"
)

// VerifyRequestFor builds a detectverify.VerifyRequest for checking whether
// executing tech against destination was detected, given caller-supplied
// run/host/timing context (tech itself carries none of that -- it describes a
// technique, not an execution). Returns ok=false when tech.MitreID is empty:
// detectverify is keyed on TechniqueID, so a technique with no MITRE mapping
// cannot be checked this way.
func VerifyRequestFor(tech latmove.Technique, runID, expectationID, hostName, hostIP string, executedAt, windowStart, windowEnd time.Time) (detectverify.VerifyRequest, bool) {
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
