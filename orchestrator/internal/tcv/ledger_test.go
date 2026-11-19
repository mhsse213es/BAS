package tcv

import (
	"context"
	"testing"
	"time"
)

func TestEvent_IdempotencyKey(t *testing.T) {
	// A validation event keys on content_version_id + source_pk.
	v := Event{Type: EventValidationResulted, ContentVersionID: "cv1", SourcePK: "val7"}
	if got, want := v.idempotencyKey(), "validation_resulted:cv1:val7"; got != want {
		t.Errorf("idempotencyKey = %q, want %q", got, want)
	}
	// A threat-only event falls back to threat_id when there is no version.
	o := Event{Type: EventThreatObserved, ThreatID: "t1", SourcePK: "obs9"}
	if got, want := o.idempotencyKey(), "threat_observed:t1:obs9"; got != want {
		t.Errorf("idempotencyKey = %q, want %q", got, want)
	}
}

func TestRecordPipelineEvent_WriteOnceAndPayload(t *testing.T) {
	ctx := context.Background()
	pool := sharedDB.Pool
	now := time.Now().UTC().Truncate(time.Second)

	ev := Event{
		Type:             EventContentCreated,
		ThreatID:         "t-ledger-1",
		ContentVersionID: "cv-ledger-1",
		EventTime:        now,
		SourceTable:      "content_generation_attempts",
		SourcePK:         "cga-ledger-1",
		Payload:          map[string]any{"outcome": "created"},
	}
	if err := RecordPipelineEvent(ctx, pool, ev); err != nil {
		t.Fatalf("RecordPipelineEvent: %v", err)
	}

	var count int
	var gotType, gotPayloadOutcome string
	var gotEventTime time.Time
	if err := pool.QueryRow(ctx,
		`SELECT count(*), max(event_type), max(payload->>'outcome'), max(event_time)
		 FROM tcf_pipeline_events WHERE idempotency_key = $1`, ev.idempotencyKey()).
		Scan(&count, &gotType, &gotPayloadOutcome, &gotEventTime); err != nil {
		t.Fatal(err)
	}
	if count != 1 || gotType != "content_created" || gotPayloadOutcome != "created" {
		t.Fatalf("row = count:%d type:%q payload.outcome:%q, want 1/content_created/created", count, gotType, gotPayloadOutcome)
	}
	if !gotEventTime.Equal(now) {
		t.Errorf("event_time = %v, want %v", gotEventTime, now)
	}

	// Recording the same event again is a no-op (write-once).
	if err := RecordPipelineEvent(ctx, pool, ev); err != nil {
		t.Fatalf("RecordPipelineEvent (second): %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM tcf_pipeline_events WHERE idempotency_key = $1`, ev.idempotencyKey()).
		Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("after duplicate record, count = %d, want 1", count)
	}

	// A different source_pk is a distinct event.
	ev2 := ev
	ev2.SourcePK = "cga-ledger-2"
	if err := RecordPipelineEvent(ctx, pool, ev2); err != nil {
		t.Fatalf("RecordPipelineEvent (distinct): %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM tcf_pipeline_events WHERE content_version_id = 'cv-ledger-1'`).
		Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("distinct events for cv-ledger-1 = %d, want 2", count)
	}
}
