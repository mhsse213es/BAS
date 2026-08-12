package openaev

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type SQLStore struct {
	pool *pgxpool.Pool
}

func NewSQLStore(pool *pgxpool.Pool) *SQLStore {
	return &SQLStore{pool: pool}
}

// SyncState returns the last-known source_updated_at and content_hash for a
// scenario, so the Importer can decide whether a fresh Fetch is even needed.
func (s *SQLStore) SyncState(ctx context.Context, openaevScenarioID string) (time.Time, string, bool, error) {
	var updatedAt time.Time
	var hash string
	err := s.pool.QueryRow(ctx,
		`SELECT source_updated_at, content_hash FROM openaev_scenarios WHERE openaev_scenario_id = $1`,
		openaevScenarioID,
	).Scan(&updatedAt, &hash)
	if err != nil {
		return time.Time{}, "", false, nil // not found is not an error here
	}
	return updatedAt, hash, true, nil
}

// Upsert writes both the bundle (full detail, keyed by content hash) and the
// scenario summary row in one transaction. sync_revision only increments when
// the content actually changed, per the "OpenAEV always wins" sync policy —
// no merge, just replace.
func (s *SQLStore) Upsert(ctx context.Context, scenario Scenario, detail Detail, contentHash string, sizeBytes, sourceVersion int) error {
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		return err
	}

	// pgx sends a nil Go slice as SQL NULL, not '{}' — the columns below are
	// NOT NULL, so a scenario with no platforms/techniques/tags must still
	// pass an empty (non-nil) slice, not rely on the column's DEFAULT (which
	// only applies when the column is omitted from the INSERT, not when NULL
	// is explicitly supplied).
	platforms := scenario.Platforms
	if platforms == nil {
		platforms = []string{}
	}
	techniqueIDs := scenario.TechniqueIDs
	if techniqueIDs == nil {
		techniqueIDs = []string{}
	}
	tags := scenario.Tags
	if tags == nil {
		tags = []string{}
	}
	sourceType := scenario.SourceType
	if sourceType == "" {
		sourceType = "scenario"
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO openaev_bundles (id, openaev_scenario_id, bundle, content_hash, size_bytes, source_version)
		 VALUES ($1, $2, $3::jsonb, $1, $4, $5)
		 ON CONFLICT (id) DO NOTHING`,
		contentHash, scenario.OpenAEVScenarioID, detailJSON, sizeBytes, sourceVersion,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO openaev_scenarios
		   (openaev_scenario_id, name, category, severity, platforms, technique_ids, tags,
		    objectives_count, injects_count, source_updated_at, content_hash, bundle_id,
		    sync_revision, updated_at, source_type)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, 1, NOW(), $12)
		 ON CONFLICT (openaev_scenario_id) DO UPDATE SET
		   name = EXCLUDED.name,
		   category = EXCLUDED.category,
		   severity = EXCLUDED.severity,
		   platforms = EXCLUDED.platforms,
		   technique_ids = EXCLUDED.technique_ids,
		   tags = EXCLUDED.tags,
		   objectives_count = EXCLUDED.objectives_count,
		   injects_count = EXCLUDED.injects_count,
		   source_updated_at = EXCLUDED.source_updated_at,
		   bundle_id = EXCLUDED.bundle_id,
		   sync_revision = CASE
		     WHEN openaev_scenarios.content_hash <> EXCLUDED.content_hash
		     THEN openaev_scenarios.sync_revision + 1
		     ELSE openaev_scenarios.sync_revision
		   END,
		   content_hash = EXCLUDED.content_hash,
		   source_type = EXCLUDED.source_type,
		   updated_at = NOW()`,
		scenario.OpenAEVScenarioID, scenario.Name, scenario.Category, scenario.Severity,
		platforms, techniqueIDs, tags,
		scenario.ObjectivesCount, scenario.InjectsCount, scenario.SourceUpdatedAt, contentHash,
		sourceType,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// List returns synced scenarios/exercises, optionally filtered by
// sourceType ("scenario" | "exercise"). An empty sourceType returns every
// row regardless of source.
func (s *SQLStore) List(ctx context.Context, sourceType string) ([]Scenario, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT openaev_scenario_id, name, category, severity, platforms, technique_ids, tags,
		        objectives_count, injects_count, source_updated_at, source_type
		   FROM openaev_scenarios
		  WHERE ($1 = '' OR source_type = $1)
		  ORDER BY name`, sourceType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Scenario
	for rows.Next() {
		var sc Scenario
		if err := rows.Scan(&sc.OpenAEVScenarioID, &sc.Name, &sc.Category, &sc.Severity,
			&sc.Platforms, &sc.TechniqueIDs, &sc.Tags, &sc.ObjectivesCount, &sc.InjectsCount,
			&sc.SourceUpdatedAt, &sc.SourceType); err != nil {
			continue
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *SQLStore) Get(ctx context.Context, openaevScenarioID string) (Scenario, Detail, bool, error) {
	var sc Scenario
	var bundleJSON []byte
	err := s.pool.QueryRow(ctx,
		`SELECT s.openaev_scenario_id, s.name, s.category, s.severity, s.platforms, s.technique_ids,
		        s.tags, s.objectives_count, s.injects_count, s.source_updated_at, s.source_type, COALESCE(b.bundle::text, '{}')::jsonb
		   FROM openaev_scenarios s
		   LEFT JOIN openaev_bundles b ON b.id = s.bundle_id
		  WHERE s.openaev_scenario_id = $1`,
		openaevScenarioID,
	).Scan(&sc.OpenAEVScenarioID, &sc.Name, &sc.Category, &sc.Severity, &sc.Platforms, &sc.TechniqueIDs,
		&sc.Tags, &sc.ObjectivesCount, &sc.InjectsCount, &sc.SourceUpdatedAt, &sc.SourceType, &bundleJSON)
	if err != nil {
		return Scenario{}, Detail{}, false, nil
	}
	var detail Detail
	json.Unmarshal(bundleJSON, &detail)
	return sc, detail, true, nil
}
