package iocregistry

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RegisterGenerated records a freshly generated artifact identity. First real producer
// of Status=generated (unused since Phase 0+A defined the lifecycle). Upsert semantics
// match ExtractFromDetectionAlert's dedup contract, but a *new* generated value is
// expected to be a new (type, value) pair essentially every call (random suffix) -- the
// ON CONFLICT path exists for correctness, not as the common case.
func RegisterGenerated(ctx context.Context, pool *pgxpool.Pool, t Type, value, scenarioID, runID, agentID, techniqueID string) error {
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO iocs (type, value, source, origin, status)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (type, value) DO UPDATE SET
			last_seen = NOW(),
			sighting_count = iocs.sighting_count + 1
		RETURNING id`,
		string(t), value, string(SourceVariant), string(OriginGenerated), string(StatusGenerated),
	).Scan(&id)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO ioc_sightings (ioc_id, scenario_id, run_id, agent_id, technique_id)
		VALUES ($1, $2, $3, $4, $5)`,
		id, scenarioID, runID, agentID, techniqueID)
	return err
}
