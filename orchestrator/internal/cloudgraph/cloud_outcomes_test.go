package cloudgraph

import (
	"testing"
	"time"
)

// TestCloudControlOutcome_AllowedAndObserved verifies match between prediction and observation
func TestCloudControlOutcome_AllowedAndObserved(t *testing.T) {
	evaluation := &EvaluationResult{
		State:     PolicySupported,
		AllowedBy: "identity-policy",
	}

	correlation := &EventSearchResult{
		EventsFound:    []*CloudEvent{{Result: "Success"}},
		MatchQuality:   "perfect",
		Confidence:     "high",
		TelemetryDelay: 2 * time.Second,
	}

	outcome := NewCloudControlOutcome(evaluation, correlation, "S3ReadControl")

	if !outcome.GraphVsExecutionMatch {
		t.Error("Expected graph and execution to match")
	}
	if outcome.EventCorrelation != "perfect" {
		t.Errorf("Expected perfect correlation, got %s", outcome.EventCorrelation)
	}
	if outcome.ExecutionOutcome != "Allowed" {
		t.Errorf("Expected Allowed, got %s", outcome.ExecutionOutcome)
	}
}

// TestCloudControlOutcome_BlockedButObservedMFAChallenge verifies gap detection
func TestCloudControlOutcome_BlockedButObservedMFAChallenge(t *testing.T) {
	evaluation := &EvaluationResult{
		State:     Blocked,
		BlockedBy: "implicit-deny",
	}

	correlation := &EventSearchResult{
		EventsFound:  []*CloudEvent{{Result: "MFAChallenge"}},
		MatchQuality: "perfect",
	}

	outcome := NewCloudControlOutcome(evaluation, correlation, "MFAGateControl")

	if outcome.GraphVsExecutionMatch {
		t.Error("Expected mismatch between Blocked prediction and MFAChallenged reality")
	}
	if outcome.Mismatch == "" {
		t.Error("Expected mismatch reason documented")
	}
	if outcome.ExecutionOutcome != "MFAChallenged" {
		t.Errorf("Expected MFAChallenged, got %s", outcome.ExecutionOutcome)
	}
}

// TestCloudControlOutcome_MissingTelemetry verifies Unknown when evidence unavailable
func TestCloudControlOutcome_MissingTelemetry(t *testing.T) {
	evaluation := &EvaluationResult{
		State: PolicySupported,
	}

	correlation := &EventSearchResult{
		EventsFound:      []*CloudEvent{},
		SearchStatus:     "partial",
		MatchQuality:     "none",
		Confidence:       "low",
		MissingTelemetry: []string{"cloudtrail-disabled", "logs-older-than-retention"},
	}

	outcome := NewCloudControlOutcome(evaluation, correlation, "S3ReadControl")

	if outcome.ExecutionOutcome != "Unknown" {
		t.Errorf("Expected Unknown outcome when evidence missing, got %s", outcome.ExecutionOutcome)
	}
	if len(outcome.MissingTelemetry) == 0 {
		t.Error("Expected missing telemetry documented")
	}
	if outcome.ControlVerdictReason == "" {
		t.Error("Expected verdict reason explaining why outcome is Unknown")
	}
}

// TestCloudControlOutcome_BlockedAndObservedFailure verifies correctly matched block
func TestCloudControlOutcome_BlockedAndObservedFailure(t *testing.T) {
	evaluation := &EvaluationResult{
		State:     Blocked,
		BlockedBy: "explicit-deny",
	}

	correlation := &EventSearchResult{
		EventsFound:  []*CloudEvent{{Result: "Failure"}},
		MatchQuality: "perfect",
	}

	outcome := NewCloudControlOutcome(evaluation, correlation, "S3DeleteControl")

	if !outcome.GraphVsExecutionMatch {
		t.Error("Expected match: predicted Blocked, observed Failure")
	}
	if outcome.ExecutionOutcome != "Blocked" {
		t.Errorf("Expected Blocked, got %s", outcome.ExecutionOutcome)
	}
}
