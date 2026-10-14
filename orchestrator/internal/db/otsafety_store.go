package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/otsafety"
)

// EnsureOTSafetyImportSchema creates the ot_safety_imports table.
func EnsureOTSafetyImportSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS ot_safety_imports (
			id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type     text        NOT NULL,
			imported_by     text,
			imported_at     timestamptz NOT NULL DEFAULT NOW(),
			config_version  text,
			limitations     text[],
			ot_safety_data  jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("ot_safety_imports: ensure schema: %w", err)
	}
	return nil
}

// otSafetyData is the shape persisted in the ot_safety_data jsonb
// column -- just the two slices that make an import's content, not
// its metadata (which live in their own columns).
type otSafetyData struct {
	SensitiveZones   []otsafety.SensitiveZone   `json:"sensitiveZones"`
	RequiredTransits []otsafety.RequiredTransit `json:"requiredTransits"`
}

// InsertOTSafetyImport writes a new ot_safety_imports row. The caller
// supplies imp.ID already generated.
func InsertOTSafetyImport(ctx context.Context, pool *pgxpool.Pool, imp *otsafety.OTSafetyImport) error {
	data, err := json.Marshal(otSafetyData{SensitiveZones: imp.SensitiveZones, RequiredTransits: imp.RequiredTransits})
	if err != nil {
		return fmt.Errorf("ot_safety_imports: marshal ot safety data for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO ot_safety_imports (id, source_type, imported_by, config_version, limitations, ot_safety_data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("ot_safety_imports: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanOTSafetyImport(row pgx.Row) (*otsafety.OTSafetyImport, error) {
	imp := &otsafety.OTSafetyImport{}
	var importedBy, configVersion *string
	var data []byte
	if err := row.Scan(&imp.ID, &imp.SourceType, &importedBy, &imp.ImportedAt, &configVersion, &imp.Limitations, &data); err != nil {
		return nil, err
	}
	if importedBy != nil {
		imp.ImportedBy = *importedBy
	}
	if configVersion != nil {
		imp.ConfigVersion = *configVersion
	}
	var sd otSafetyData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, fmt.Errorf("ot_safety_imports: unmarshal ot safety data for %s: %w", imp.ID, err)
	}
	imp.SensitiveZones, imp.RequiredTransits = sd.SensitiveZones, sd.RequiredTransits
	return imp, nil
}

// GetOTSafetyImport returns one import by id. A missing id returns an
// error satisfying errors.Is(err, pgx.ErrNoRows).
func GetOTSafetyImport(ctx context.Context, pool *pgxpool.Pool, id string) (*otsafety.OTSafetyImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, ot_safety_data
		 FROM ot_safety_imports WHERE id = $1`, id)
	imp, err := scanOTSafetyImport(row)
	if err != nil {
		return nil, fmt.Errorf("ot_safety_imports: get %s: %w", id, err)
	}
	return imp, nil
}

// ListOTSafetyImports returns up to limit rows, newest first.
func ListOTSafetyImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*otsafety.OTSafetyImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, ot_safety_data
		 FROM ot_safety_imports ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("ot_safety_imports: list: %w", err)
	}
	defer rows.Close()
	var out []*otsafety.OTSafetyImport
	for rows.Next() {
		imp, err := scanOTSafetyImport(rows)
		if err != nil {
			return nil, fmt.Errorf("ot_safety_imports: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ot_safety_imports: list rows: %w", err)
	}
	return out, nil
}
