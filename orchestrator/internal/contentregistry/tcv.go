package contentregistry

import (
	"context"
	"log"
	"time"

	"github.com/audspect/bas/internal/tcv"
)

// recordLifecycleEvent emits the SLA ledger event for one lifecycle
// transition (spec §5), keyed by the content_version_events row id so the
// Task-6 reconciler -- reading the same rows -- produces identical
// idempotency keys. Only milestone targets map to an event; DRAFT/APPROVED
// transitions (and VALIDATING->DRAFT validation failures) map to none.
// published_executable fires on publish regardless of validation, but
// validated_coverage fires ONLY on ->VALIDATED, so a hand-authored
// PUBLISHED_LOCAL version is never recorded as validated coverage.
func (r *Registry) recordLifecycleEvent(ctx context.Context, versionID string, to Lifecycle, eventID string, at time.Time) {
	var typ tcv.EventType
	switch to {
	case LifecycleValidating:
		typ = tcv.EventValidationDispatched
	case LifecycleValidated:
		typ = tcv.EventValidatedCoverage
	case LifecyclePublished, LifecyclePublishedLocal:
		typ = tcv.EventPublishedExecutable
	case LifecycleRetired:
		typ = tcv.EventRetired
	case LifecycleRejected:
		typ = tcv.EventRejected
	default:
		return
	}
	if err := tcv.RecordPipelineEvent(ctx, r.pool, tcv.Event{
		Type:             typ,
		ContentVersionID: versionID,
		EventTime:        at,
		SourceTable:      "content_version_events",
		SourcePK:         eventID,
		Payload:          map[string]any{"to_lifecycle": string(to)},
	}); err != nil {
		log.Printf("[contentregistry/tcv] record %s for %s: %v", typ, versionID, err)
	}
}

// qualifiesForTCVStop reports whether this origin/trust/lifecycle
// combination should stop a TCV clock (spec §10.3-§10.4). This is a
// strict SUBSET of Executable(): passing devBuild=false always excludes
// the dev-only combination (an unsigned VENDOR scenario accepted only
// because signing is disabled locally), which lets a scenario run in dev
// but must never count toward a customer-facing coverage metric
// (acceptance test 32). The two real executable combinations do not
// depend on devBuild, so this cannot exclude them.
func qualifiesForTCVStop(origin Origin, trust Trust, lc Lifecycle) bool {
	return Executable(origin, trust, lc, false)
}

// recordCoverageIfExecutable checks whether versionID, in its CURRENT
// origin/trust/lifecycle state, qualifies as executable coverage and, for
// every threat this version is linked to via content_version_threats,
// records a write-once coverage-first stop (spec §10.3). Idempotent
// (threat_coverage_firsts is write-once) -- safe to call after every state
// change a version goes through, not only the one that actually flips it
// to executable. q is the caller's own transaction when one is open, so
// the coverage write is atomic with the state change that caused it.
func (r *Registry) recordCoverageIfExecutable(ctx context.Context, q tcv.Querier, versionID string, origin Origin, trust Trust, lc Lifecycle) error {
	if !qualifiesForTCVStop(origin, trust, lc) {
		return nil
	}
	rows, err := q.Query(ctx, `SELECT threat_id, relationship_kind FROM content_version_threats WHERE content_version_id = $1`, versionID)
	if err != nil {
		return err
	}
	type link struct{ threatID, kind string }
	var links []link
	for rows.Next() {
		var l link
		if err := rows.Scan(&l.threatID, &l.kind); err != nil {
			rows.Close()
			return err
		}
		links = append(links, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	now := time.Now()
	for _, l := range links {
		if err := tcv.RecordCoverageFirst(ctx, q, l.threatID, tcv.RelationshipKind(l.kind), versionID, now); err != nil {
			return err
		}
	}
	return nil
}
