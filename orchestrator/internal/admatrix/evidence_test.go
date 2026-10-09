package admatrix

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/detectverify"
)

func dcsyncPrim() adprimitive.Primitive  { return adprimitive.DCSyncCatalog[0] }   // has TechniqueID T1003.006
func aclNoTechID() adprimitive.Primitive { return adprimitive.ACLAbuseCatalog[0] } // acl-forcechangepassword: no TechniqueID

var (
	t0 = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	w0 = t0.Add(-time.Minute)
	w1 = t0.Add(time.Minute)
)

func detectedEv(run, target string) TelemetryEvidence {
	return TelemetryEvidence{Present: true, RunID: run, TargetID: target,
		Result: detectverify.VerifyResult{Verdict: detectverify.VerdictDetected, Confidence: "high"}}
}

// present + positive + attributable + checkable -> advances to telemetry_observed
func TestAdvanceWithTelemetry_DetectedAttributableAdvances(t *testing.T) {
	v := AdvanceWithTelemetry(dcsyncPrim(), "run-1", "dc01", t0, w0, w1, detectedEv("run-1", "dc01"))
	if v.Status != StatusTelemetryObserved {
		t.Fatalf("detected + attributable must advance to telemetry_observed, got %q (%s)", v.Status, v.Reason)
	}
}

// missing evidence -> stays executed
func TestAdvanceWithTelemetry_MissingEvidenceStaysExecuted(t *testing.T) {
	v := AdvanceWithTelemetry(dcsyncPrim(), "run-1", "dc01", t0, w0, w1, TelemetryEvidence{Present: false})
	if v.Status != StatusExecuted {
		t.Fatalf("missing evidence must stay executed, got %q", v.Status)
	}
}

// incomplete: capability not detection-checkable (no MITRE technique id)
func TestAdvanceWithTelemetry_UncheckableCapabilityStaysExecuted(t *testing.T) {
	if aclNoTechID().TechniqueID != "" {
		t.Fatalf("precondition: ACL abuse primitive must have no technique id, got %q", aclNoTechID().TechniqueID)
	}
	v := AdvanceWithTelemetry(aclNoTechID(), "run-1", "dc01", t0, w0, w1, detectedEv("run-1", "dc01"))
	if v.Status != StatusExecuted {
		t.Fatalf("un-checkable capability must not advance, got %q (%s)", v.Status, v.Reason)
	}
}

// ambiguous: evidence not attributable to this run/target
func TestAdvanceWithTelemetry_WrongAttributionDoesNotAdvance(t *testing.T) {
	wrongRun := AdvanceWithTelemetry(dcsyncPrim(), "run-1", "dc01", t0, w0, w1, detectedEv("run-OTHER", "dc01"))
	wrongTarget := AdvanceWithTelemetry(dcsyncPrim(), "run-1", "dc01", t0, w0, w1, detectedEv("run-1", "dc99"))
	if wrongRun.Status != StatusExecuted || wrongTarget.Status != StatusExecuted {
		t.Fatalf("evidence from a different run/target must not advance: run=%q target=%q", wrongRun.Status, wrongTarget.Status)
	}
}

// negative: executed but the control did not detect it (detection gap)
func TestAdvanceWithTelemetry_NotDetectedStaysExecuted(t *testing.T) {
	ev := TelemetryEvidence{Present: true, RunID: "run-1", TargetID: "dc01",
		Result: detectverify.VerifyResult{Verdict: detectverify.VerdictNotDetected}}
	v := AdvanceWithTelemetry(dcsyncPrim(), "run-1", "dc01", t0, w0, w1, ev)
	if v.Status != StatusExecuted {
		t.Fatalf("NotDetected must stay executed (detection gap), got %q", v.Status)
	}
	if v.Reason == "" {
		t.Fatal("a non-advancing verdict must explain why")
	}
}
