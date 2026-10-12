package dxcorrelate

import (
	"testing"
	"time"
)

func row(leg Leg, action string, efficacy ControlEfficacyStatus, behavior BehaviorStatus, at time.Time) AttemptRow {
	return AttemptRow{Leg: leg, Action: action, ControlEfficacy: efficacy, Behavior: behavior, CreatedAt: at}
}

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func TestCorrelate_AllThreeOccurredInOrder_IsThreeLegConfirmed(t *testing.T) {
	rows := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0),
		row(LegTransfer, "a2", EfficacyNotDetected, BehaviorOccurred, t0.Add(time.Hour)),
		row(LegEncryption, "a3", EfficacyNoEvidence, BehaviorOccurred, t0.Add(2*time.Hour)),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationThreeLegConfirmed {
		t.Fatalf("Classification = %q, want three_leg_confirmed", result.Classification)
	}
	if len(result.Legs) != 3 {
		t.Fatalf("len(Legs) = %d, want 3", len(result.Legs))
	}
}

func TestCorrelate_StagingAndTransferOccurred_EncryptionNotEstablished_IsExfiltrationConfirmed(t *testing.T) {
	rows := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0),
		row(LegTransfer, "a2", EfficacyNotDetected, BehaviorOccurred, t0.Add(time.Hour)),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationExfiltrationConfirmedEncryptionNotEstablished {
		t.Fatalf("Classification = %q, want exfiltration_confirmed_encryption_not_established", result.Classification)
	}
}

func TestCorrelate_EncryptionOccurredAlone_IsEncryptionConfirmed(t *testing.T) {
	rows := []AttemptRow{
		row(LegEncryption, "a3", EfficacyNoEvidence, BehaviorOccurred, t0),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationEncryptionConfirmedExfiltrationNotEstablished {
		t.Fatalf("Classification = %q, want encryption_confirmed_exfiltration_not_established", result.Classification)
	}
}

func TestCorrelate_StagingOnly_IsPartialBehaviorEvidence(t *testing.T) {
	rows := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationPartialBehaviorEvidence {
		t.Fatalf("Classification = %q, want partial_behavior_evidence", result.Classification)
	}
}

func TestCorrelate_NoRows_IsInsufficientBehaviorEvidence(t *testing.T) {
	result := Correlate(nil)
	if result.Classification != ClassificationInsufficientBehaviorEvidence {
		t.Fatalf("Classification = %q, want insufficient_behavior_evidence", result.Classification)
	}
	for _, l := range result.Legs {
		if l.ControlEfficacy != EfficacyNoEvidence {
			t.Errorf("%s ControlEfficacy = %q, want no_evidence", l.Leg, l.ControlEfficacy)
		}
		if l.Behavior != BehaviorNotEstablished {
			t.Errorf("%s Behavior = %q, want not_established", l.Leg, l.Behavior)
		}
	}
}

func TestCorrelate_DuplicateOccurredRowsForOneLeg_DeterministicallyUsesEarliest(t *testing.T) {
	rowsA := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0.Add(2*time.Hour)),
		row(LegStaging, "a2", EfficacyNotDetected, BehaviorOccurred, t0), // earliest
	}
	resultA := Correlate(rowsA)
	var stagingA LegEvidence
	for _, l := range resultA.Legs {
		if l.Leg == LegStaging {
			stagingA = l
		}
	}
	if !stagingA.CreatedAt.Equal(t0) {
		t.Fatalf("staging CreatedAt = %v, want the earliest Occurred row's timestamp %v", stagingA.CreatedAt, t0)
	}
	// Same two rows, different slice order -- must produce the identical result (deterministic).
	rowsB := []AttemptRow{rowsA[1], rowsA[0]}
	resultB := Correlate(rowsB)
	if resultA.Classification != resultB.Classification {
		t.Fatalf("order-dependent result: %q vs %q", resultA.Classification, resultB.Classification)
	}
}

func TestCorrelate_OutOfOrderEvidence_DowngradesToPartialWithAnomaly(t *testing.T) {
	rows := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0.Add(2*time.Hour)), // staging AFTER transfer
		row(LegTransfer, "a2", EfficacyNotDetected, BehaviorOccurred, t0),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationPartialBehaviorEvidence {
		t.Fatalf("Classification = %q, want partial_behavior_evidence for out-of-order evidence", result.Classification)
	}
	if result.Anomaly == "" {
		t.Fatal("Anomaly is empty, want a non-empty explanation of the ordering violation")
	}
}

func TestCorrelate_TemporallyUnrelatedEvidence_DowngradesToPartialWithAnomaly(t *testing.T) {
	// Correctly ordered, but far outside MaxCorrelationWindow -- a DIFFERENT
	// rule from the ordering test above; this must not be confused with it.
	rows := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0),
		row(LegTransfer, "a2", EfficacyNotDetected, BehaviorOccurred, t0.Add(MaxCorrelationWindow+time.Hour)),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationPartialBehaviorEvidence {
		t.Fatalf("Classification = %q, want partial_behavior_evidence for temporally-unrelated evidence", result.Classification)
	}
	if result.Anomaly == "" {
		t.Fatal("Anomaly is empty, want a non-empty explanation of the time-window violation")
	}
}

func TestCorrelate_WithinWindowAndOrder_StaysConfirmed(t *testing.T) {
	rows := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0),
		row(LegTransfer, "a2", EfficacyNotDetected, BehaviorOccurred, t0.Add(MaxCorrelationWindow-time.Hour)),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationExfiltrationConfirmedEncryptionNotEstablished {
		t.Fatalf("Classification = %q, want exfiltration_confirmed_encryption_not_established", result.Classification)
	}
	if result.Anomaly != "" {
		t.Fatalf("Anomaly = %q, want empty for evidence within the window and correctly ordered", result.Anomaly)
	}
}
