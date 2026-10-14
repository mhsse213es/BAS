package tcv

import (
	"context"
	"testing"
	"time"
)

func TestMetrics_NoClockStartedIsNoClock(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-metrics-no-clock")
	store := NewStore(sharedDB.Pool)

	m, err := store.Metrics(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if m.ThreatToEmulation.State != StateNoClock || m.ThreatToGeneration.State != StateNoClock {
		t.Fatalf("metrics = %+v, want StateNoClock for both threat-clock metrics", m)
	}
}

func TestMetrics_ClockStartedNoCoverageIsOpen(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-metrics-open")
	start := time.Now().Add(-2 * time.Hour)
	if err := RecordThreatClockStart(ctx, sharedDB.Pool, threatID, start, "sync-1"); err != nil {
		t.Fatal(err)
	}
	store := NewStore(sharedDB.Pool)

	m, err := store.Metrics(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if m.ThreatToEmulation.State != StateOpen {
		t.Fatalf("ThreatToEmulation.State = %q, want open", m.ThreatToEmulation.State)
	}
	if m.ThreatToEmulation.ElapsedSeconds == nil || *m.ThreatToEmulation.ElapsedSeconds < 3600 {
		t.Fatalf("ThreatToEmulation.ElapsedSeconds = %v, want >= ~7200 (elapsed since start, moves over time)", m.ThreatToEmulation.ElapsedSeconds)
	}
	if m.ThreatToEmulation.TCVSeconds != nil {
		t.Fatalf("ThreatToEmulation.TCVSeconds = %v, want nil while open", m.ThreatToEmulation.TCVSeconds)
	}
}

func TestMetrics_CoverageBeforeClockStartIsPreExistingZero(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-metrics-preexisting")
	vid := seedContentVersion(t, "cv-metrics-preexisting")
	covered := time.Now().Add(-48 * time.Hour)
	start := time.Now()

	if err := RecordCoverageFirst(ctx, sharedDB.Pool, threatID, RelationshipEmulates, vid, covered); err != nil {
		t.Fatal(err)
	}
	if err := RecordThreatClockStart(ctx, sharedDB.Pool, threatID, start, "sync-1"); err != nil {
		t.Fatal(err)
	}
	store := NewStore(sharedDB.Pool)

	m, err := store.Metrics(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if m.ThreatToEmulation.State != StatePreExisting {
		t.Fatalf("State = %q, want pre_existing (coverage predates the clock start)", m.ThreatToEmulation.State)
	}
	if m.ThreatToEmulation.TCVSeconds == nil || *m.ThreatToEmulation.TCVSeconds != 0 {
		t.Fatalf("TCVSeconds = %v, want exactly 0 (never negative)", m.ThreatToEmulation.TCVSeconds)
	}
}

func TestMetrics_CoverageAfterClockStartIsMeasured(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-metrics-measured")
	vid := seedContentVersion(t, "cv-metrics-measured")
	start := time.Now().Add(-3 * time.Hour)
	covered := time.Now()

	if err := RecordThreatClockStart(ctx, sharedDB.Pool, threatID, start, "sync-1"); err != nil {
		t.Fatal(err)
	}
	if err := RecordCoverageFirst(ctx, sharedDB.Pool, threatID, RelationshipGeneratedFor, vid, covered); err != nil {
		t.Fatal(err)
	}
	store := NewStore(sharedDB.Pool)

	m, err := store.Metrics(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if m.ThreatToGeneration.State != StateMeasured {
		t.Fatalf("State = %q, want measured", m.ThreatToGeneration.State)
	}
	if m.ThreatToGeneration.TCVSeconds == nil || *m.ThreatToGeneration.TCVSeconds < 10000 {
		t.Fatalf("TCVSeconds = %v, want roughly 10800 (3 hours)", m.ThreatToGeneration.TCVSeconds)
	}
	// The other three metrics are unaffected -- never collapsed together.
	if m.ThreatToEmulation.State != StateOpen {
		t.Fatalf("ThreatToEmulation.State = %q, want open (no emulates coverage recorded)", m.ThreatToEmulation.State)
	}
	if m.IntelligenceToGeneration.State != StateNoClock {
		t.Fatalf("IntelligenceToGeneration.State = %q, want no_clock (intelligence clock never started)", m.IntelligenceToGeneration.State)
	}
}
