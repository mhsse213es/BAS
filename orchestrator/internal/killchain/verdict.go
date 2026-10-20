package killchain

import (
	"fmt"
	"strings"
)

// StageInput is everything the verdict engine reads for one stage.
type StageInput struct {
	State      StageState
	Policy     StagePolicy
	Evidence   *StageEvidence
	ExecFailed bool
}

// StageVerdict is the derived verdict plus the reasons behind it. The dimension
// values stay in the evidence, so prevention, detection and response are
// reported beside the verdict rather than replaced by it.
type StageVerdict struct {
	Verdict Verdict  `json:"verdict"`
	Reasons []string `json:"reasons"`
}

// Evaluate returns the verdict for one stage. It is a pure function. The same
// input always gives the same output.
//
// Precedence, highest first (docs/fullkillchain-foundation-audit.md section 4.2):
//  1. ERROR: execution failed.
//  2. NOT_TESTED: the stage was never reached, or was cancelled.
//  3. INCONCLUSIVE: interrupted, no evidence, missing or contradictory
//     evidence, unhealthy telemetry, or an unknown outcome.
//  4. ALLOWED: a verified policy violation was observed.
//  5. BLOCKED: prevention verified and the action was attempted but not executed.
//  6. DETECTED_NOT_CONTAINED: detected, containment required and not verified.
//  7. DETECTED: detected with complete evidence.
//  8. NOT_DETECTED: complete window, healthy telemetry, no detection.
func Evaluate(in StageInput) StageVerdict {
	if in.ExecFailed || in.State == StateFailed {
		return verdict(VerdictError, "execution failed")
	}
	if in.State == StateNotReached || in.State == StateCancelled {
		return verdict(VerdictNotTested, "stage not reached: an upstream stage closed the path or the campaign was cancelled")
	}
	if in.State == StateInterrupted {
		return verdict(VerdictInconclusive, "stage interrupted; partial evidence kept, not re-executed")
	}
	if in.State != StateCompleted {
		return verdict(VerdictInconclusive, fmt.Sprintf("stage is %s and has no terminal result", in.State))
	}
	if in.Evidence == nil {
		return verdict(VerdictInconclusive, "no evidence recorded for a completed stage")
	}

	e := in.Evidence
	if missing := e.Missing(); len(missing) > 0 {
		return verdict(VerdictInconclusive, "missing evidence: "+strings.Join(missing, ", "))
	}

	var reasons []string
	if e.Prevention.Value == PreventionBlocked && e.GroundTruth.Executed == TriYes {
		reasons = append(reasons, "prevention reports blocked, but ground truth shows the action executed")
	}
	if e.Prevention.Value == PreventionBlocked && e.GroundTruth.Attempted != TriYes {
		reasons = append(reasons, "prevention reports blocked, but ground truth records no attempt")
	}
	if e.Prevention.Value == PreventionUnknown {
		reasons = append(reasons, "prevention outcome is unknown")
	}
	if e.Detection.Value == DetectionInconclusive {
		reasons = append(reasons, "detection outcome is inconclusive")
	}
	if e.Detection.Value == DetectionNotDetected && e.Detection.TelemetryHealth != TelemetryHealthy {
		reasons = append(reasons, "no detection, but telemetry was not confirmed healthy")
	}
	if e.Detection.Value == DetectionNotDetected && e.Detection.WindowComplete != TriYes {
		reasons = append(reasons, "no detection, but the observation window did not complete")
	}
	if e.Detection.Value == DetectionDetected && in.Policy.ContainmentRequired && e.Response.Value == ResponseInconclusive {
		reasons = append(reasons, "containment required, but response is inconclusive")
	}
	if len(reasons) > 0 {
		return StageVerdict{Verdict: VerdictInconclusive, Reasons: reasons}
	}

	if e.Prevention.Value == PreventionAllowed && e.GroundTruth.Executed == TriYes && in.Policy.ShouldBlock {
		return verdict(VerdictAllowed, "action executed although the verified policy "+policyName(in.Policy)+" requires it to be prevented")
	}
	if e.Prevention.Value == PreventionBlocked && e.GroundTruth.Attempted == TriYes && e.GroundTruth.Executed == TriNo {
		return verdict(VerdictBlocked, "prevention verified: the action was attempted and did not execute")
	}
	if e.Detection.Value == DetectionDetected && e.Response.Value == ResponseNotContained && in.Policy.ContainmentRequired {
		return verdict(VerdictDetectedNotContained, "detected, but containment required by the policy was not verified")
	}
	if e.Detection.Value == DetectionDetected {
		return verdict(VerdictDetected, "expected behaviour detected with complete evidence")
	}
	if e.Detection.Value == DetectionNotDetected {
		return verdict(VerdictNotDetected, "observation window completed with healthy telemetry and no detection")
	}
	return verdict(VerdictInconclusive, "no rule decided this stage")
}

func verdict(v Verdict, reason string) StageVerdict {
	return StageVerdict{Verdict: v, Reasons: []string{reason}}
}

func policyName(p StagePolicy) string {
	if p.Source != "" {
		return "(" + p.Source + ")"
	}
	return "for this stage"
}
