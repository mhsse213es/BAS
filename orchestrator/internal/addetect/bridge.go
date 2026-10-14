// Package addetect bridges AD-M08 ("Detection & Prevention Validation")
// into the existing, generic detectverify.Connector interface. Depends
// one-way on adprimitive and detectverify only; neither of those
// packages gains any AD-awareness.
package addetect

import (
	"time"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/detectverify"
)

// VerifyRequestFor builds a detectverify.VerifyRequest for checking
// whether executing p was detected, given caller-supplied run/host/
// timing context (p itself carries none of that -- it describes a
// technique, not an execution). Returns ok=false when p.TechniqueID is
// empty: detectverify is keyed on TechniqueID, so a primitive with no
// 1:1 MITRE mapping cannot be checked this way.
func VerifyRequestFor(p adprimitive.Primitive, runID, expectationID, hostName, hostIP string, executedAt, windowStart, windowEnd time.Time) (detectverify.VerifyRequest, bool) {
	if p.TechniqueID == "" {
		return detectverify.VerifyRequest{}, false
	}
	return detectverify.VerifyRequest{
		RunID:          runID,
		ExpectationID:  expectationID,
		TechniqueID:    p.TechniqueID,
		HostName:       hostName,
		HostIP:         hostIP,
		StepExecutedAt: executedAt,
		WindowStart:    windowStart,
		WindowEnd:      windowEnd,
	}, true
}
