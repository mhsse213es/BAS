package detectverify

import (
	"testing"
	"time"
)

func TestMatchAlerts_NoAlerts_NotDetected(t *testing.T) {
	result := matchAlerts(VerifyRequest{TechniqueID: "T1059.001"}, nil)
	if result.Verdict != VerdictNotDetected {
		t.Fatalf("Verdict = %q, want %q", result.Verdict, VerdictNotDetected)
	}
	if len(result.MatchedAlerts) != 0 {
		t.Fatalf("MatchedAlerts = %+v, want none", result.MatchedAlerts)
	}
}

func TestMatchAlerts_TechniqueTaggedAlert_HighConfidence(t *testing.T) {
	stepTime := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	alertTime := stepTime.Add(90 * time.Second)
	req := VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: stepTime}
	alerts := []normalizedAlert{
		{AlertID: "a1", Timestamp: alertTime, Techniques: []string{"T1059.001"}, InvestigationURL: "https://example/a1"},
	}

	result := matchAlerts(req, alerts)
	if result.Verdict != VerdictDetected || result.Confidence != ConfidenceHigh {
		t.Fatalf("result = %+v, want Detected/high", result)
	}
	if result.DetectionLatency != 90*time.Second {
		t.Fatalf("DetectionLatency = %v, want 90s", result.DetectionLatency)
	}
	if result.InvestigationURL != "https://example/a1" {
		t.Fatalf("InvestigationURL = %q", result.InvestigationURL)
	}
}

func TestMatchAlerts_UntaggedAlert_MediumConfidence(t *testing.T) {
	stepTime := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	req := VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: stepTime}
	alerts := []normalizedAlert{
		{AlertID: "a1", Timestamp: stepTime.Add(time.Minute)}, // no Techniques tag
	}

	result := matchAlerts(req, alerts)
	if result.Verdict != VerdictDetected || result.Confidence != ConfidenceMedium {
		t.Fatalf("result = %+v, want Detected/medium", result)
	}
}

func TestMatchAlerts_PrefersEarliestTechniqueTaggedAlert(t *testing.T) {
	stepTime := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	req := VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: stepTime}
	alerts := []normalizedAlert{
		{AlertID: "later", Timestamp: stepTime.Add(3 * time.Minute), Techniques: []string{"T1059.001"}},
		{AlertID: "earlier", Timestamp: stepTime.Add(1 * time.Minute), Techniques: []string{"T1059.001"}},
		{AlertID: "untagged", Timestamp: stepTime.Add(10 * time.Second)}, // earliest overall, but untagged
	}

	result := matchAlerts(req, alerts)
	if result.DetectionLatency != time.Minute {
		t.Fatalf("DetectionLatency = %v, want 1m (from the earliest TAGGED alert, not the earliest overall)", result.DetectionLatency)
	}
	if len(result.MatchedAlerts) != 3 {
		t.Fatalf("MatchedAlerts = %d, want all 3 alerts recorded", len(result.MatchedAlerts))
	}
}

func TestContainsTechnique_CaseInsensitiveAndTrimmed(t *testing.T) {
	if !containsTechnique([]string{" t1059.001 "}, "T1059.001") {
		t.Fatal("expected a case-insensitive, whitespace-tolerant match")
	}
	if containsTechnique([]string{"T1055"}, "T1059.001") {
		t.Fatal("expected no match for a different technique")
	}
	if containsTechnique(nil, "") {
		t.Fatal("expected no match when the wanted technique is empty")
	}
}
