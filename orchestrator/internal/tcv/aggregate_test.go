package tcv

import (
	"context"
	"testing"
	"time"
)

func TestAggregateMetrics_OpenAndPreExistingDoNotChangeSampleSize(t *testing.T) {
	ctx := context.Background()
	before, err := AggregateMetrics(ctx, sharedDB.Pool)
	if err != nil {
		t.Fatalf("AggregateMetrics (before): %v", err)
	}
	now := time.Now()

	// Open: clock started, no coverage yet -- must be excluded.
	openThreat := seedThreat(t, "APT-aggregate-open")
	if err := RecordThreatClockStart(ctx, sharedDB.Pool, openThreat, now.Add(-time.Hour), "sync-open"); err != nil {
		t.Fatal(err)
	}

	// PreExisting: coverage before the clock started -- must be excluded.
	preThreat := seedThreat(t, "APT-aggregate-preexisting")
	if err := RecordThreatClockStart(ctx, sharedDB.Pool, preThreat, now, "sync-pre"); err != nil {
		t.Fatal(err)
	}
	preVID := seedContentVersion(t, "cv-aggregate-pre")
	if err := RecordCoverageFirst(ctx, sharedDB.Pool, preThreat, RelationshipEmulates, preVID, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	after, err := AggregateMetrics(ctx, sharedDB.Pool)
	if err != nil {
		t.Fatalf("AggregateMetrics (after): %v", err)
	}
	if after.SampleSize != before.SampleSize {
		t.Fatalf("SampleSize changed from %d to %d after adding only an Open and a PreExisting threat -- neither must count", before.SampleSize, after.SampleSize)
	}
}

func TestAggregateMetrics_MeasuredThreatIncreasesSampleSizeByOne(t *testing.T) {
	ctx := context.Background()
	before, err := AggregateMetrics(ctx, sharedDB.Pool)
	if err != nil {
		t.Fatalf("AggregateMetrics (before): %v", err)
	}

	measuredThreat := seedThreat(t, "APT-aggregate-measured")
	start := time.Now().Add(-200 * time.Second)
	if err := RecordThreatClockStart(ctx, sharedDB.Pool, measuredThreat, start, "sync-measured"); err != nil {
		t.Fatal(err)
	}
	measuredVID := seedContentVersion(t, "cv-aggregate-measured")
	if err := RecordCoverageFirst(ctx, sharedDB.Pool, measuredThreat, RelationshipEmulates, measuredVID, start.Add(100*time.Second)); err != nil {
		t.Fatal(err)
	}

	after, err := AggregateMetrics(ctx, sharedDB.Pool)
	if err != nil {
		t.Fatalf("AggregateMetrics (after): %v", err)
	}
	if after.SampleSize != before.SampleSize+1 {
		t.Fatalf("SampleSize = %d, want %d (exactly one new Measured threat added)", after.SampleSize, before.SampleSize+1)
	}
	if after.MedianSeconds == nil {
		t.Fatal("MedianSeconds = nil, want a real value once at least one threat is Measured")
	}
}
