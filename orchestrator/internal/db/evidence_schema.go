package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureEvidenceSchema creates the TCF Phase 2B evidence tables (spec
// 2026-10-06 §5-§8). Must run after EnsureThreatIdentitySchema (threats,
// threat_actor_profiles.id) and before EnsureAppRole. Idempotent.
func EnsureEvidenceSchema(ctx context.Context, pool *pgxpool.Pool) error {
	for _, s := range evidenceTables {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("evidence schema: %w\n%s", err, s)
		}
	}
	return nil
}

var evidenceTables = []string{
	`CREATE TABLE IF NOT EXISTS source_instances (
		id               text        PRIMARY KEY,
		source_type      text        NOT NULL CHECK (source_type IN ('bundle','misp','opencti','otx')),
		display_name     text        NOT NULL,
		observation_mode text        NOT NULL CHECK (observation_mode IN ('snapshot','activity_window')),
		created_at       timestamptz NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS source_trust_versions (
		id                 bigserial   PRIMARY KEY,
		source_instance_id text        NOT NULL REFERENCES source_instances(id),
		trust_state        text        NOT NULL CHECK (trust_state IN ('trusted','untrusted')),
		effective_at       timestamptz NOT NULL DEFAULT NOW(),
		changed_by         text        NOT NULL,
		reason             text        NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_source_trust_versions_instance_effective
		ON source_trust_versions (source_instance_id, effective_at DESC)`,
	`CREATE TABLE IF NOT EXISTS source_syncs (
		id                 text        PRIMARY KEY DEFAULT ('sync-' || gen_random_uuid()::text),
		source_instance_id text        NOT NULL REFERENCES source_instances(id),
		started_at         timestamptz NOT NULL,
		completed_at       timestamptz,
		status             text        NOT NULL CHECK (status IN ('succeeded','failed')),
		completeness       text        NOT NULL CHECK (completeness IN ('complete','partial','truncated','failed')),
		authoritative      boolean     NOT NULL,
		diagnostic         text        NOT NULL DEFAULT '',
		CHECK (status = 'succeeded' OR completeness = 'failed'),
		CHECK (NOT authoritative OR completeness = 'complete')
	)`,
	`CREATE TABLE IF NOT EXISTS source_observations (
		id                  text        PRIMARY KEY DEFAULT ('obs-' || gen_random_uuid()::text),
		sync_id             text        NOT NULL REFERENCES source_syncs(id),
		source_instance_id  text        NOT NULL REFERENCES source_instances(id),
		external_id         text        NOT NULL DEFAULT '',
		raw_name            text        NOT NULL,
		record_hash         text        NOT NULL,
		observed_at         timestamptz NOT NULL,
		raw                 jsonb       NOT NULL,
		trust_version_id    bigint      NOT NULL REFERENCES source_trust_versions(id),
		candidate_id        text        REFERENCES actor_resolution_candidates(id)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_source_observations_sync ON source_observations (sync_id)`,
	`CREATE TABLE IF NOT EXISTS threat_sources (
		id                     text        PRIMARY KEY DEFAULT ('tsrc-' || gen_random_uuid()::text),
		threat_id              text        NOT NULL REFERENCES threats(id),
		observation_id         text        NOT NULL REFERENCES source_observations(id),
		provider               text        NOT NULL,
		external_id            text        NOT NULL DEFAULT '',
		observed_at            timestamptz NOT NULL,
		source_confidence      smallint,
		record_hash            text        NOT NULL,
		first_seen_at_generation text      NOT NULL DEFAULT '',
		linked_by              text        NOT NULL CHECK (linked_by IN ('resolver','admin')),
		linked_ref             text        NOT NULL DEFAULT '',
		UNIQUE (observation_id)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_threat_sources_threat ON threat_sources (threat_id)`,
	`CREATE TABLE IF NOT EXISTS technique_claims (
		id                          text        PRIMARY KEY DEFAULT ('claim-' || gen_random_uuid()::text),
		observation_id              text        NOT NULL REFERENCES source_observations(id),
		sync_id                     text        NOT NULL REFERENCES source_syncs(id),
		source_instance_id          text        NOT NULL REFERENCES source_instances(id),
		threat_id                   text        NOT NULL REFERENCES threats(id),
		technique_id                text        NOT NULL,
		kind                        text        NOT NULL CHECK (kind IN ('claim','retraction')),
		via                         text        NOT NULL DEFAULT '',
		via_name                    text        NOT NULL DEFAULT '',
		start_time                  timestamptz,
		stop_time                   timestamptz,
		raw_confidence              text,
		normalized_confidence       smallint,
		confidence_mapping_version  text,
		trust_version_id            bigint      NOT NULL REFERENCES source_trust_versions(id),
		observed_at                 timestamptz NOT NULL,
		record_hash                 text        NOT NULL,
		UNIQUE (source_instance_id, threat_id, technique_id, via, via_name, record_hash)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_technique_claims_threat_technique
		ON technique_claims (threat_id, technique_id, source_instance_id, observed_at DESC)`,
	`CREATE TABLE IF NOT EXISTS threat_techniques (
		threat_id                text        NOT NULL REFERENCES threats(id),
		technique_id              text        NOT NULL,
		first_seen_at             timestamptz,
		last_seen_at              timestamptz NOT NULL,
		supporting_source_count   int         NOT NULL DEFAULT 0,
		best_confidence           smallint,
		status                    text        NOT NULL CHECK (status IN ('active','retracted')),
		status_reason             text        NOT NULL CHECK (status_reason IN ('supported','source_retraction','trust_revocation')),
		projected_at              timestamptz NOT NULL DEFAULT NOW(),
		PRIMARY KEY (threat_id, technique_id)
	)`,
	`CREATE TABLE IF NOT EXISTS content_generations (
		id                       text        PRIMARY KEY DEFAULT ('gen-' || gen_random_uuid()::text),
		threat_id                text        NOT NULL REFERENCES threats(id),
		content_id               text        NOT NULL,
		content_version_id       text,
		generation_number        int         NOT NULL,
		policy_version            text        NOT NULL,
		technique_set_hash        text        NOT NULL,
		evidence_snapshot_hash    text        NOT NULL,
		evidence_snapshot         jsonb       NOT NULL,
		generated_at              timestamptz NOT NULL DEFAULT NOW(),
		UNIQUE (threat_id, generation_number)
	)`,
}
