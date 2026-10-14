package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/zoneisolation"
)

// EnsureZoneIsolationImportSchema creates the zone_isolation_imports table.
func EnsureZoneIsolationImportSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS zone_isolation_imports (
			id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type     text        NOT NULL,
			imported_by     text,
			imported_at     timestamptz NOT NULL DEFAULT NOW(),
			config_version  text,
			limitations     text[],
			isolation_data  jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("zone_isolation_imports: ensure schema: %w", err)
	}
	return nil
}

// zoneIsolationData is the shape persisted in the isolation_data jsonb
// column -- just the declared pairs, not the import's own metadata
// (which live in their own columns).
type zoneIsolationData struct {
	ZonePairIsolations []zoneisolation.ZonePairIsolation `json:"zonePairIsolations"`
}

// InsertZoneIsolationImport writes a new zone_isolation_imports row.
// The caller supplies imp.ID already generated.
func InsertZoneIsolationImport(ctx context.Context, pool *pgxpool.Pool, imp *zoneisolation.IsolationImport) error {
	data, err := json.Marshal(zoneIsolationData{ZonePairIsolations: imp.ZonePairIsolations})
	if err != nil {
		return fmt.Errorf("zone_isolation_imports: marshal isolation data for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO zone_isolation_imports (id, source_type, imported_by, config_version, limitations, isolation_data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("zone_isolation_imports: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanZoneIsolationImport(row pgx.Row) (*zoneisolation.IsolationImport, error) {
	imp := &zoneisolation.IsolationImport{}
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
	var zd zoneIsolationData
	if err := json.Unmarshal(data, &zd); err != nil {
		return nil, fmt.Errorf("zone_isolation_imports: unmarshal isolation data for %s: %w", imp.ID, err)
	}
	imp.ZonePairIsolations = zd.ZonePairIsolations
	return imp, nil
}

// GetZoneIsolationImport returns one import by id. A missing id
// returns an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetZoneIsolationImport(ctx context.Context, pool *pgxpool.Pool, id string) (*zoneisolation.IsolationImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, isolation_data
		 FROM zone_isolation_imports WHERE id = $1`, id)
	imp, err := scanZoneIsolationImport(row)
	if err != nil {
		return nil, fmt.Errorf("zone_isolation_imports: get %s: %w", id, err)
	}
	return imp, nil
}

// ListZoneIsolationImports returns up to limit rows, newest first.
func ListZoneIsolationImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*zoneisolation.IsolationImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, isolation_data
		 FROM zone_isolation_imports ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("zone_isolation_imports: list: %w", err)
	}
	defer rows.Close()
	var out []*zoneisolation.IsolationImport
	for rows.Next() {
		imp, err := scanZoneIsolationImport(rows)
		if err != nil {
			return nil, fmt.Errorf("zone_isolation_imports: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("zone_isolation_imports: list rows: %w", err)
	}
	return out, nil
}
