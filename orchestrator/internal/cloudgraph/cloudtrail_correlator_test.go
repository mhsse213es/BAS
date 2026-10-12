package cloudgraph

import (
	"testing"
	"time"
)

// TestEventCorrelator_FindEventsPerfectMatch verifies event found with exact match
func TestEventCorrelator_FindEventsPerfectMatch(t *testing.T) {
	correlator := &SyntheticEventCorrelator{}

	principal := "arn:aws:iam::123456789012:user/test-user"
	action := "s3:GetObject"
	resource := "arn:aws:s3:::test-bucket/object.txt"
	actionTime := time.Now().UTC()
	windowSize := 30 * time.Second

	correlator.addSyntheticEvent(&CloudEvent{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Timestamp: actionTime,
		Result:    "Success",
		Source:    "cloudtrail",
	})

	result := correlator.FindEvents(principal, action, resource, actionTime, windowSize)

	if len(result.EventsFound) != 1 {
		t.Errorf("Expected 1 event, got %d", len(result.EventsFound))
	}
	if result.MatchQuality != "perfect" {
		t.Errorf("Expected perfect match, got %s", result.MatchQuality)
	}
	if result.SearchStatus != "success" {
		t.Errorf("Expected success, got %s", result.SearchStatus)
	}
}

// TestEventCorrelator_FindEventsPartialMatch verifies degraded confidence when resource mismatch
func TestEventCorrelator_FindEventsPartialMatch(t *testing.T) {
	correlator := &SyntheticEventCorrelator{}

	principal := "arn:aws:iam::123456789012:user/test-user"
	action := "s3:GetObject"
	resource := "arn:aws:s3:::test-bucket/object.txt"
	actionTime := time.Now().UTC()

	correlator.addSyntheticEvent(&CloudEvent{
		Principal: principal,
		Action:    action,
		Resource:  "arn:aws:s3:::different-bucket/file.txt",
		Timestamp: actionTime,
		Result:    "Success",
	})

	result := correlator.FindEvents(principal, action, resource, actionTime, 30*time.Second)

	if result.MatchQuality != "partial" {
		t.Errorf("Expected partial match, got %s", result.MatchQuality)
	}
	if result.Confidence != "medium" {
		t.Errorf("Expected medium confidence, got %s", result.Confidence)
	}
}

// TestEventCorrelator_FindEventsDelayedEvent verifies TelemetryDelay calculation
func TestEventCorrelator_FindEventsDelayedEvent(t *testing.T) {
	correlator := &SyntheticEventCorrelator{}

	principal := "arn:aws:iam::123456789012:user/test-user"
	action := "sts:AssumeRole"
	resource := "arn:aws:iam::123456789012:role/test-role"
	actionTime := time.Now().UTC()
	eventTime := actionTime.Add(5 * time.Second)

	correlator.addSyntheticEvent(&CloudEvent{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Timestamp: eventTime,
		Result:    "Success",
	})

	result := correlator.FindEvents(principal, action, resource, actionTime, 30*time.Second)

	if result.TelemetryDelay != 5*time.Second {
		t.Errorf("Expected 5s delay, got %v", result.TelemetryDelay)
	}
}

// TestEventCorrelator_NoEventFound verifies Unknown when event not found
func TestEventCorrelator_NoEventFound(t *testing.T) {
	correlator := &SyntheticEventCorrelator{}

	principal := "arn:aws:iam::123456789012:user/test-user"
	action := "s3:DeleteBucket"
	resource := "arn:aws:s3:::test-bucket"
	actionTime := time.Now().UTC()

	result := correlator.FindEvents(principal, action, resource, actionTime, 30*time.Second)

	if result.SearchStatus != "success" {
		t.Errorf("Search should succeed (return no results)")
	}
	if result.MatchQuality != "none" {
		t.Errorf("Expected none, got %s", result.MatchQuality)
	}
	if len(result.EventsFound) != 0 {
		t.Errorf("Expected no events, got %d", len(result.EventsFound))
	}
}

// TestEventCorrelator_EventOutsideWindowIsExcluded verifies window boundary enforcement
func TestEventCorrelator_EventOutsideWindowIsExcluded(t *testing.T) {
	correlator := &SyntheticEventCorrelator{}

	principal := "arn:aws:iam::123456789012:user/test-user"
	action := "s3:GetObject"
	resource := "arn:aws:s3:::test-bucket/object.txt"
	actionTime := time.Now().UTC()

	// Event 60s after action, outside the 30s window
	correlator.addSyntheticEvent(&CloudEvent{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Timestamp: actionTime.Add(60 * time.Second),
		Result:    "Success",
	})

	result := correlator.FindEvents(principal, action, resource, actionTime, 30*time.Second)

	if result.MatchQuality != "none" {
		t.Errorf("Expected none (event outside window), got %s", result.MatchQuality)
	}
	if len(result.EventsFound) != 0 {
		t.Errorf("Expected 0 events (outside window), got %d", len(result.EventsFound))
	}
}
