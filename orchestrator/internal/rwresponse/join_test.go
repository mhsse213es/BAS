package rwresponse

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
)

func row(technique, action, capability string, verdict controlval.Verdict, skipReason controlval.SkipReason, at time.Time) db.RWAttemptRow {
	return db.RWAttemptRow{TechniqueID: technique, Action: action, Capability: capability, Verdict: verdict, SkipReason: skipReason, CreatedAt: at}
}

var t0 = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func TestBuildEffectivenessReport_AllThreeDimensionsPresent(t *testing.T) {
	rows := []db.RWAttemptRow{
		row("T1490", "a1", "detection", controlval.VerdictFail, "", t0),
		row("T1490", "a1", "containment", controlval.VerdictPass, "", t0),
		row("T1490", "a1", "recovery", controlval.VerdictPass, "", t0),
	}
	report := BuildEffectivenessReport(rows, nil)
	if len(report.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(report.Rows))
	}
	r := report.Rows[0]
	if r.Detection == nil || r.Containment == nil || r.Recovery == nil {
		t.Fatalf("expected all three dimensions present, got %+v", r)
	}
	if r.Detection.Verdict != controlval.VerdictFail {
		t.Errorf("Detection.Verdict = %q, want FAIL", r.Detection.Verdict)
	}
}

func TestBuildEffectivenessReport_MissingDimensionIsNilNotZeroValue(t *testing.T) {
	rows := []db.RWAttemptRow{
		row("T1490", "a1", "containment", controlval.VerdictPass, "", t0),
		row("T1490", "a1", "recovery", controlval.VerdictPass, "", t0),
		// no detection row at all
	}
	report := BuildEffectivenessReport(rows, nil)
	r := report.Rows[0]
	if r.Detection != nil {
		t.Fatalf("Detection = %+v, want nil -- no detection row exists for this technique", r.Detection)
	}
	if r.Containment == nil || r.Recovery == nil {
		t.Fatal("Containment and Recovery should both be present")
	}
}

func TestBuildEffectivenessReport_PreventionAndDataProtectionRowsNeverRead(t *testing.T) {
	rows := []db.RWAttemptRow{
		row("T1486", "a1", "prevention", controlval.VerdictFail, "", t0),
		row("T1486", "a1", "data_protection", controlval.VerdictFail, "", t0),
	}
	report := BuildEffectivenessReport(rows, nil)
	if len(report.Rows) != 1 {
		t.Fatalf("got %d rows, want 1 -- the technique must still appear even with only Prevention/DataProtection rows", len(report.Rows))
	}
	r := report.Rows[0]
	if r.Detection != nil || r.Containment != nil || r.Recovery != nil {
		t.Fatalf("expected all three dimensions nil (Prevention/DataProtection are never translated), got %+v", r)
	}
}

func TestBuildEffectivenessReport_DuplicateRowsForSameCapability_DeterministicallyUsesEarliest(t *testing.T) {
	rowsA := []db.RWAttemptRow{
		row("T1490", "a2", "detection", controlval.VerdictPass, "", t0.Add(2*time.Hour)),
		row("T1490", "a1", "detection", controlval.VerdictFail, "", t0), // earliest
	}
	reportA := BuildEffectivenessReport(rowsA, nil)
	if reportA.Rows[0].Detection.Action != "a1" {
		t.Fatalf("Detection.Action = %q, want the earliest row's action a1", reportA.Rows[0].Detection.Action)
	}
	// Same two rows, different slice order -- must produce the identical result (deterministic).
	rowsB := []db.RWAttemptRow{rowsA[1], rowsA[0]}
	reportB := BuildEffectivenessReport(rowsB, nil)
	if reportA.Rows[0].Detection.Verdict != reportB.Rows[0].Detection.Verdict {
		t.Fatalf("order-dependent result: %q vs %q", reportA.Rows[0].Detection.Verdict, reportB.Rows[0].Detection.Verdict)
	}
}

func TestBuildEffectivenessReport_ResponseLatencyAlwaysNotEstablishable(t *testing.T) {
	rows := []db.RWAttemptRow{row("T1490", "a1", "detection", controlval.VerdictFail, "", t0)}
	lat := 3 * time.Second
	report := BuildEffectivenessReport(rows, []DetectionLatencyEvidence{{TechniqueID: "T1490", Action: "a1", Latency: lat}})
	r := report.Rows[0]
	if r.DetectionLatency == nil || *r.DetectionLatency != lat {
		t.Fatalf("DetectionLatency = %v, want %v", r.DetectionLatency, lat)
	}
	if r.ResponseLatency != ResponseLatencyNotEstablishable {
		t.Fatalf("ResponseLatency = %q, want not_establishable even when DetectionLatency is present -- the two are independent", r.ResponseLatency)
	}
}

func TestBuildEffectivenessReport_DetectionLatencyNilWithoutMatch(t *testing.T) {
	rows := []db.RWAttemptRow{row("T1490", "a1", "detection", controlval.VerdictFail, "", t0)}
	report := BuildEffectivenessReport(rows, nil)
	if report.Rows[0].DetectionLatency != nil {
		t.Fatalf("DetectionLatency = %v, want nil when no latency evidence supplied", report.Rows[0].DetectionLatency)
	}
}

func TestBuildEffectivenessReport_NoRows_ReturnsEmptyNotNilSlice(t *testing.T) {
	report := BuildEffectivenessReport(nil, nil)
	if report.Rows == nil {
		t.Fatal("Rows is nil, want an empty (non-nil) slice")
	}
	if len(report.Rows) != 0 {
		t.Fatalf("got %d rows, want 0", len(report.Rows))
	}
}
