package emailgwefficacy

import (
	"testing"
	"time"
)

func TestInWindow_InvertedWindow_ContainsNothing(t *testing.T) {
	now := time.Now()
	window := TimeWindow{Start: now.Add(time.Hour), End: now.Add(-time.Hour)}
	if inWindow(now, window) {
		t.Error("inWindow(now, inverted window) = true, want false -- an inverted window must never be treated as unbounded")
	}
}

func TestInWindow_BoundaryTimestamps_Inclusive(t *testing.T) {
	now := time.Now()
	window := TimeWindow{Start: now, End: now.Add(time.Hour)}
	if !inWindow(now, window) {
		t.Error("inWindow(window.Start, window) = false, want true -- the window's own start must be inclusive")
	}
	if !inWindow(window.End, window) {
		t.Error("inWindow(window.End, window) = false, want true -- the window's own end must be inclusive")
	}
}

func TestLatestByTimestamp_PicksMostRecent(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	records := []EnforcementEvidence{
		{Action: "allow", Timestamp: older},
		{Action: "quarantine", Timestamp: newer},
	}
	latest := latestByTimestamp(records, func(e EnforcementEvidence) time.Time { return e.Timestamp })
	if latest.Action != "quarantine" {
		t.Errorf("latestByTimestamp picked Action %q, want %q", latest.Action, "quarantine")
	}
}

func TestLatestByTimestamp_TieKeepsFirstOccurrence(t *testing.T) {
	ts := time.Now()
	records := []EnforcementEvidence{
		{Action: "first", Timestamp: ts},
		{Action: "second", Timestamp: ts},
	}
	latest := latestByTimestamp(records, func(e EnforcementEvidence) time.Time { return e.Timestamp })
	if latest.Action != "first" {
		t.Errorf("latestByTimestamp on a tie picked Action %q, want %q -- a strict After comparison must never treat an equal timestamp as later", latest.Action, "first")
	}
}

func TestFixtureMailEvidenceProvider_FiltersByMessageAndWindow(t *testing.T) {
	now := time.Now()
	target := MessageRef{SenderProfile: "spoofed-exec", Recipient: "cfo@example.com", MessageClass: "spf-fail"}
	other := MessageRef{SenderProfile: "spoofed-exec", Recipient: "cfo@example.com", MessageClass: "macro-attachment"}

	provider := NewFixtureMailEvidenceProvider(
		[]EnforcementEvidence{
			{Message: target, Action: "quarantine", Timestamp: now},
			{Message: other, Action: "deliver", Timestamp: now},                       // wrong message, must be excluded
			{Message: target, Action: "deliver", Timestamp: now.Add(-24 * time.Hour)}, // outside window, must be excluded
		},
		nil,
	)

	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	records, err := provider.EnforcementEvidenceFor(target, window)
	if err != nil {
		t.Fatalf("EnforcementEvidenceFor returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("EnforcementEvidenceFor returned %d records, want 1 (wrong-message and out-of-window records must be excluded)", len(records))
	}
	if records[0].Action != "quarantine" {
		t.Errorf("surviving record Action = %q, want %q", records[0].Action, "quarantine")
	}
}

func TestFixtureMailEvidenceProvider_NoMatch_ReturnsEmptyNotError(t *testing.T) {
	provider := NewFixtureMailEvidenceProvider(nil, nil)
	window := TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)}

	enf, err := provider.EnforcementEvidenceFor(MessageRef{}, window)
	if err != nil {
		t.Errorf("EnforcementEvidenceFor returned error %v, want nil -- a successful search finding nothing is not a collection failure", err)
	}
	if len(enf) != 0 {
		t.Errorf("EnforcementEvidenceFor returned %d records, want 0", len(enf))
	}

	det, err := provider.DetectionEvidenceFor(MessageRef{}, window)
	if err != nil {
		t.Errorf("DetectionEvidenceFor returned error %v, want nil", err)
	}
	if len(det) != 0 {
		t.Errorf("DetectionEvidenceFor returned %d records, want 0", len(det))
	}
}
