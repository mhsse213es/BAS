package api

import (
	"context"
	"time"
)

// recordLegacyUsage records one successful legacy-protocol request (see
// routes.go:79-97's allowlist) against agentID's day, or against the
// fleet-level unattributed counter when agentID is empty. Fire-and-forget,
// matching auditLogAs's existing async pattern (audit.go) -- a slow or
// failed write here must never add latency or an error path to the actual
// agent-facing response.
//
// The GREATEST() upsert means an out-of-order write (an older request's
// response completing after a newer one, due to real network jitter) can
// never move last_seen_at backwards -- see the spec's schema section for
// why this matters for the 30-day eligibility window's correctness.
func (h *Handler) recordLegacyUsage(ctx context.Context, agentID, endpoint string, seenAt time.Time) {
	day := seenAt.UTC().Truncate(24 * time.Hour)
	if agentID != "" {
		go func() {
			_, _ = h.db.Exec(context.Background(),
				`INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint)
				 VALUES ($1, $2, $3, $4)
				 ON CONFLICT (agent_id, day) DO UPDATE
				   SET last_seen_at = GREATEST(legacy_transport_log.last_seen_at, EXCLUDED.last_seen_at),
				       endpoint     = CASE WHEN EXCLUDED.last_seen_at > legacy_transport_log.last_seen_at
				                           THEN EXCLUDED.endpoint ELSE legacy_transport_log.endpoint END`,
				agentID, day, seenAt.UTC(), endpoint)
		}()
		return
	}
	go func() {
		_, _ = h.db.Exec(context.Background(),
			`INSERT INTO legacy_transport_unattributed (day, last_seen_at, request_count)
			 VALUES ($1, $2, 1)
			 ON CONFLICT (day) DO UPDATE
			   SET last_seen_at  = GREATEST(legacy_transport_unattributed.last_seen_at, EXCLUDED.last_seen_at),
			       request_count = legacy_transport_unattributed.request_count + 1`,
			day, seenAt.UTC())
	}()
}
