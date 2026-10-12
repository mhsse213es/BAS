package rwdetect

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/rwevidence"
)

func TestVerifyRequestFor_NoMitreIDReturnsFalse(t *testing.T) {
	tech := rwevidence.Technique{ID: "archive-staging-via-utility"} // no MitreID
	_, ok := VerifyRequestFor(tech, "run-1", "exp-1", "HOST01", "10.0.0.5", time.Time{}, time.Time{}, time.Time{})
	if ok {
		t.Fatal("expected ok=false for a technique with no MitreID")
	}
}

func TestVerifyRequestFor_MapsEveryFieldUnchanged(t *testing.T) {
	tech := rwevidence.Technique{ID: "vss-inhibition", MitreID: "T1490"}
	executedAt := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	windowStart := executedAt.Add(-5 * time.Minute)
	windowEnd := executedAt.Add(10 * time.Minute)

	got, ok := VerifyRequestFor(tech, "run-1", "exp-42", "HOST01", "10.0.0.10", executedAt, windowStart, windowEnd)
	if !ok {
		t.Fatal("expected ok=true for a technique with a MitreID")
	}
	want := detectverify.VerifyRequest{
		RunID:          "run-1",
		ExpectationID:  "exp-42",
		TechniqueID:    "T1490",
		HostName:       "HOST01",
		HostIP:         "10.0.0.10",
		StepExecutedAt: executedAt,
		WindowStart:    windowStart,
		WindowEnd:      windowEnd,
	}
	if got != want {
		t.Fatalf("expected %+v, got %+v", want, got)
	}
}

func TestDetectionLookupResultFor_DetectedSingleAlert(t *testing.T) {
	result := detectverify.VerifyResult{
		Verdict:       detectverify.VerdictDetected,
		Confidence:    detectverify.ConfidenceHigh,
		MatchedAlerts: []detectverify.MatchedAlert{{AlertID: "a1", RuleName: "VSS Deletion"}},
	}
	tested, verified, reason := DetectionLookupResultFor(result)
	if !tested || !verified {
		t.Fatalf("tested=%v verified=%v, want true/true", tested, verified)
	}
	if reason != "1 alert matched, confidence=high" {
		t.Fatalf("reason = %q, want singular wording for exactly 1 alert", reason)
	}
}

func TestDetectionLookupResultFor_DetectedMultipleAlerts(t *testing.T) {
	result := detectverify.VerifyResult{
		Verdict:    detectverify.VerdictDetected,
		Confidence: detectverify.ConfidenceMedium,
		MatchedAlerts: []detectverify.MatchedAlert{
			{AlertID: "a1"}, {AlertID: "a2"},
		},
	}
	tested, verified, reason := DetectionLookupResultFor(result)
	if !tested || !verified {
		t.Fatalf("tested=%v verified=%v, want true/true", tested, verified)
	}
	if reason != "2 alerts matched, confidence=medium" {
		t.Fatalf("reason = %q, want plural wording for 2 alerts", reason)
	}
}

func TestDetectionLookupResultFor_NotDetected(t *testing.T) {
	result := detectverify.VerifyResult{Verdict: detectverify.VerdictNotDetected}
	tested, verified, reason := DetectionLookupResultFor(result)
	if !tested {
		t.Fatal("tested should always be true -- the query ran and returned a definitive verdict")
	}
	if verified {
		t.Fatal("verified should be false for VerdictNotDetected")
	}
	if reason != "no matching alerts found in the query window" {
		t.Fatalf("reason = %q, want the fixed no-match string", reason)
	}
}
