package admatrix

import (
	"time"

	"github.com/audspect/bas/internal/addetect"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/detectverify"
)

// TelemetryEvidence is a detection-verification outcome offered as evidence that
// a capability's execution was observed. It is tagged with the run and target it
// pertains to so attribution can be enforced -- evidence from a different run or
// target is not evidence about this one.
type TelemetryEvidence struct {
	Present  bool                      // false => no verification was performed (evidence missing)
	RunID    string                    // the run this result pertains to
	TargetID string                    // the target host this result pertains to
	Result   detectverify.VerifyResult // the detectverify outcome (Detected / NotDetected)
}

// EvidenceVerdict is the honest coverage outcome of weighing detection evidence.
type EvidenceVerdict struct {
	Status CoverageStatus
	Reason string
}

// AdvanceWithTelemetry decides the highest honestly-supported coverage status
// for capability p, GIVEN it was actually executed in run runID against target
// targetID (the precondition for having any detection evidence at all). It
// advances to telemetry_observed ONLY when ALL hold:
//   - p is detection-checkable: addetect.VerifyRequestFor can build a request
//     for it (requires a MITRE technique id; detectverify is keyed on it);
//   - evidence is present;
//   - the evidence is attributable to exactly this run AND this target;
//   - the verdict is a conclusive Detected.
//
// Missing, un-checkable, non-attributable, or NotDetected evidence never
// advances past executed. A sensor mapping or a planned detection is never
// treated as an observed detection -- only a real, attributable Detected result
// is. The timing arguments are the step execution time and padded query window,
// passed through to addetect/detectverify exactly as a live check would use them.
func AdvanceWithTelemetry(p adprimitive.Primitive, runID, targetID string, executedAt, windowStart, windowEnd time.Time, ev TelemetryEvidence) EvidenceVerdict {
	executed := func(reason string) EvidenceVerdict {
		return EvidenceVerdict{Status: StatusExecuted, Reason: reason}
	}

	// Detection-checkable only if the addetect bridge can build a request
	// (ExpectationID/HostIP are not needed to decide checkability here).
	if _, ok := addetect.VerifyRequestFor(p, runID, "", targetID, "", executedAt, windowStart, windowEnd); !ok {
		return executed("capability has no MITRE technique id; not detection-checkable via detectverify")
	}
	if !ev.Present {
		return executed("executed; no detection evidence gathered")
	}
	if ev.RunID != runID || ev.TargetID != targetID {
		return executed("detection evidence is not attributable to this run and target; ignored")
	}
	if ev.Result.Verdict != detectverify.VerdictDetected {
		return executed("executed; security control did not detect it (detection gap)")
	}

	reason := "execution observed by detection telemetry, attributable to this run and target"
	if ev.Result.Confidence != "" {
		reason = "execution observed by detection telemetry (" + ev.Result.Confidence + " confidence), attributable to this run and target"
	}
	return EvidenceVerdict{Status: StatusTelemetryObserved, Reason: reason}
}
