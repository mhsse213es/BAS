package tcv

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ReconcilePipelineEvents re-derives pipeline events from the authoritative
// source tables and idempotently inserts any the forward writers missed. The
// forward emits are log-and-continue outside the source transaction, so a
// crash between a source write and its ledger insert leaves a gap; this heals
// it. Every emit here uses the same idempotency key the forward writer would,
// so events already present are no-ops (ON CONFLICT DO NOTHING) and durations
// stay keyed to source event-time.
//
// threat_eligible is deliberately NOT reconciled: eligibility is a decision
// made inside the generator (a threat clearing minTechniques on a given
// cycle), not a fact recorded in any source row, so it cannot be
// reconstructed and is only ever written forward.
//
// since bounds the work to source rows whose own timestamp is at or after it:
// a zero time reconciles all of history (the one-time boot backfill), while a
// recent cutoff keeps the periodic heal O(window) rather than O(total history),
// since a forward-path gap is healed within one tick of occurring. All four
// sub-passes run even if one fails (their errors are joined), so a persistent
// failure in one source never starves the heals of the others.
func ReconcilePipelineEvents(ctx context.Context, pool *pgxpool.Pool, since time.Time) error {
	return errors.Join(
		reconcileThreatObserved(ctx, pool, since),
		reconcileGenerationEvents(ctx, pool, since),
		reconcileLifecycleEvents(ctx, pool, since),
		reconcileValidationResulted(ctx, pool, since),
	)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// reconcileThreatObserved mirrors the 2C threat clock (threat_clock_starts,
// clock='threat') -- the write-once trusted-observation record the forward
// threat_observed event shadows, at the same observed_at. source_pk is the
// threat id, matching the forward key.
func reconcileThreatObserved(ctx context.Context, pool *pgxpool.Pool, since time.Time) error {
	rows, err := pool.Query(ctx, `SELECT threat_id, started_at FROM threat_clock_starts WHERE clock = 'threat' AND started_at >= $1`, since)
	if err != nil {
		return fmt.Errorf("tcv: reconcile threat_observed: %w", err)
	}
	type rec struct {
		tid string
		at  time.Time
	}
	var recs []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.tid, &r.at); err != nil {
			rows.Close()
			return fmt.Errorf("tcv: reconcile threat_observed: %w", err)
		}
		recs = append(recs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("tcv: reconcile threat_observed: %w", err)
	}
	for _, r := range recs {
		if err := RecordPipelineEvent(ctx, pool, Event{
			Type:        EventThreatObserved,
			ThreatID:    r.tid,
			EventTime:   r.at,
			SourceTable: "source_observations",
			SourcePK:    r.tid,
			Payload:     map[string]any{"reconciled": true},
		}); err != nil {
			return fmt.Errorf("tcv: reconcile threat_observed: %w", err)
		}
	}
	return nil
}

// reconcileGenerationEvents re-derives generation_attempted (every attempt),
// generation_failed (outcome=failed) and content_created (outcome=created)
// from content_generation_attempts, keyed by the attempt row id.
func reconcileGenerationEvents(ctx context.Context, pool *pgxpool.Pool, since time.Time) error {
	rows, err := pool.Query(ctx, `SELECT id, threat_id, content_version_id, outcome, reason_code, started_at, completed_at
		FROM content_generation_attempts WHERE started_at >= $1`, since)
	if err != nil {
		return fmt.Errorf("tcv: reconcile generation events: %w", err)
	}
	type rec struct {
		id, outcome, reason string
		tid, cvid           *string
		started, completed  time.Time
	}
	var recs []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.id, &r.tid, &r.cvid, &r.outcome, &r.reason, &r.started, &r.completed); err != nil {
			rows.Close()
			return fmt.Errorf("tcv: reconcile generation events: %w", err)
		}
		recs = append(recs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("tcv: reconcile generation events: %w", err)
	}
	for _, r := range recs {
		tid, cvid := deref(r.tid), deref(r.cvid)
		emit := func(typ EventType, at time.Time) error {
			return RecordPipelineEvent(ctx, pool, Event{
				Type: typ, ThreatID: tid, ContentVersionID: cvid, GenerationAttemptID: r.id,
				EventTime: at, SourceTable: "content_generation_attempts", SourcePK: r.id,
				Payload: map[string]any{"outcome": r.outcome, "reason_code": r.reason},
			})
		}
		if err := emit(EventGenerationAttempted, r.started); err != nil {
			return fmt.Errorf("tcv: reconcile generation events: %w", err)
		}
		switch r.outcome {
		case "failed":
			if err := emit(EventGenerationFailed, r.completed); err != nil {
				return fmt.Errorf("tcv: reconcile generation events: %w", err)
			}
		case "created":
			if err := emit(EventContentCreated, r.completed); err != nil {
				return fmt.Errorf("tcv: reconcile generation events: %w", err)
			}
		}
	}
	return nil
}

// lifecycleEventType maps a content_version_events.to_lifecycle to its ledger
// milestone, matching contentregistry.recordLifecycleEvent. The second return
// is false for transitions that are not milestones (DRAFT/APPROVED).
func lifecycleEventType(to string) (EventType, bool) {
	switch to {
	case "VALIDATING":
		return EventValidationDispatched, true
	case "VALIDATED":
		return EventValidatedCoverage, true
	case "PUBLISHED", "PUBLISHED_LOCAL":
		return EventPublishedExecutable, true
	case "RETIRED":
		return EventRetired, true
	case "REJECTED":
		return EventRejected, true
	}
	return "", false
}

// reconcileLifecycleEvents re-derives the lifecycle milestones from
// content_version_events, keyed by the event row id.
func reconcileLifecycleEvents(ctx context.Context, pool *pgxpool.Pool, since time.Time) error {
	rows, err := pool.Query(ctx, `SELECT id, content_version_id, to_lifecycle, at
		FROM content_version_events
		WHERE to_lifecycle IN ('VALIDATING','VALIDATED','PUBLISHED','PUBLISHED_LOCAL','RETIRED','REJECTED') AND at >= $1`, since)
	if err != nil {
		return fmt.Errorf("tcv: reconcile lifecycle events: %w", err)
	}
	type rec struct {
		id, cvid, to string
		at           time.Time
	}
	var recs []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.id, &r.cvid, &r.to, &r.at); err != nil {
			rows.Close()
			return fmt.Errorf("tcv: reconcile lifecycle events: %w", err)
		}
		recs = append(recs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("tcv: reconcile lifecycle events: %w", err)
	}
	for _, r := range recs {
		typ, ok := lifecycleEventType(r.to)
		if !ok {
			continue
		}
		if err := RecordPipelineEvent(ctx, pool, Event{
			Type: typ, ContentVersionID: r.cvid, EventTime: r.at,
			SourceTable: "content_version_events", SourcePK: r.id,
			Payload: map[string]any{"to_lifecycle": r.to},
		}); err != nil {
			return fmt.Errorf("tcv: reconcile lifecycle events: %w", err)
		}
	}
	return nil
}

// reconcileValidationResulted re-derives validation_resulted from EXECUTION
// content_validations joined to a factory_validation run -- the join is what
// excludes customer detection-validation rows from the factory SLA. Keyed by
// run_id, matching the forward emit.
func reconcileValidationResulted(ctx context.Context, pool *pgxpool.Pool, since time.Time) error {
	rows, err := pool.Query(ctx, `SELECT cv.content_version_id, cv.run_id, cv.outcome, cv.created_at
		FROM content_validations cv
		JOIN scenario_runs sr ON sr.id = cv.run_id
		WHERE cv.level = 'EXECUTION' AND cv.outcome <> 'NO_DATA' AND sr.execution_kind = 'factory_validation' AND cv.created_at >= $1`, since)
	if err != nil {
		return fmt.Errorf("tcv: reconcile validation_resulted: %w", err)
	}
	type rec struct {
		cvid, runID, outcome string
		at                   time.Time
	}
	var recs []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.cvid, &r.runID, &r.outcome, &r.at); err != nil {
			rows.Close()
			return fmt.Errorf("tcv: reconcile validation_resulted: %w", err)
		}
		recs = append(recs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("tcv: reconcile validation_resulted: %w", err)
	}
	for _, r := range recs {
		if err := RecordPipelineEvent(ctx, pool, Event{
			Type: EventValidationResulted, ContentVersionID: r.cvid, ValidationRunID: r.runID,
			EventTime: r.at, SourceTable: "content_validations", SourcePK: r.runID,
			Payload: map[string]any{"outcome": r.outcome, "run_id": r.runID},
		}); err != nil {
			return fmt.Errorf("tcv: reconcile validation_resulted: %w", err)
		}
	}
	return nil
}
