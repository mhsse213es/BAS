package tcv

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// EventType is one of the TCV SLA ledger's event kinds (spec 2026-10-31 §5).
// The values match the event_type CHECK in db/tcf_pipeline_events_schema.go.
type EventType string

const (
	EventThreatObserved       EventType = "threat_observed"
	EventThreatEligible       EventType = "threat_eligible"
	EventGenerationAttempted  EventType = "generation_attempted"
	EventGenerationFailed     EventType = "generation_failed"
	EventContentCreated       EventType = "content_created"
	EventValidationDispatched EventType = "validation_dispatched"
	EventValidationResulted   EventType = "validation_resulted"
	EventValidatedCoverage    EventType = "validated_coverage"
	EventPublishedExecutable  EventType = "published_executable"
	EventSuperseded           EventType = "superseded"
	EventRetired              EventType = "retired"
	EventRejected             EventType = "rejected"
)

// Event is one append-only row for the tcf_pipeline_events ledger. It
// references the authoritative source row (SourceTable/SourcePK) and copies
// that row's own timestamp into EventTime; it never copies mutable facts, so
// the ledger cannot drift from the source. ID fields left empty are stored as
// SQL NULL. Payload carries read-convenience fields (outcome, reason_code,
// source type, content type) copied from the source for segmentation.
type Event struct {
	Type                EventType
	ThreatID            string
	ContentID           string
	ContentVersionID    string
	GenerationAttemptID string
	ValidationRunID     string
	EventTime           time.Time
	SourceTable         string
	SourcePK            string
	Payload             map[string]any
}

// idempotencyKey is the deterministic dedup key for an event: the event kind,
// the version it concerns (or the threat when no version exists yet), and the
// authoritative source row's key. Every event derives from exactly one source
// row, so this key makes replay (sync cycles, reconciliation) a no-op.
func (e Event) idempotencyKey() string {
	anchor := e.ContentVersionID
	if anchor == "" {
		anchor = e.ThreatID
	}
	return string(e.Type) + ":" + anchor + ":" + e.SourcePK
}

// RecordPipelineEvent appends one event, write-once. It never updates or
// deletes; a duplicate idempotency_key is silently ignored (ON CONFLICT DO
// NOTHING). q is the caller's transaction or the pool -- but callers wire this
// log-and-continue, never letting a ledger failure roll back the source write.
func RecordPipelineEvent(ctx context.Context, q Querier, e Event) error {
	payload := e.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("tcv: marshal pipeline-event payload: %w", err)
	}
	if _, err := q.Exec(ctx,
		`INSERT INTO tcf_pipeline_events
			(event_type, threat_id, content_id, content_version_id,
			 generation_attempt_id, validation_run_id, event_time,
			 source_table, source_pk, payload, idempotency_key)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 ON CONFLICT (idempotency_key) DO NOTHING`,
		e.Type, nullIfEmpty(e.ThreatID), nullIfEmpty(e.ContentID), nullIfEmpty(e.ContentVersionID),
		nullIfEmpty(e.GenerationAttemptID), nullIfEmpty(e.ValidationRunID), e.EventTime,
		e.SourceTable, e.SourcePK, raw, e.idempotencyKey()); err != nil {
		return fmt.Errorf("tcv: record pipeline event %s: %w", e.Type, err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
