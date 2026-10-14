package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/networkefficacy"
)

// EnsureNetworkControlExpectationSchema creates the
// network_control_expectations table.
func EnsureNetworkControlExpectationSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS network_control_expectations (
			id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type     text        NOT NULL,
			imported_by     text,
			imported_at     timestamptz NOT NULL DEFAULT NOW(),
			config_version  text,
			limitations     text[],
			expectations_data jsonb     NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("network_control_expectations: ensure schema: %w", err)
	}
	return nil
}

// InsertNetworkControlExpectationImport writes a new
// network_control_expectations row. The caller supplies imp.ID already
// generated.
func InsertNetworkControlExpectationImport(ctx context.Context, pool *pgxpool.Pool, imp *networkefficacy.ControlExpectationImport) error {
	data, err := json.Marshal(imp.Expectations)
	if err != nil {
		return fmt.Errorf("network_control_expectations: marshal expectations for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO network_control_expectations (id, source_type, imported_by, config_version, limitations, expectations_data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("network_control_expectations: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanNetworkControlExpectationImport(row pgx.Row) (*networkefficacy.ControlExpectationImport, error) {
	imp := &networkefficacy.ControlExpectationImport{}
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
	if err := json.Unmarshal(data, &imp.Expectations); err != nil {
		return nil, fmt.Errorf("network_control_expectations: unmarshal expectations for %s: %w", imp.ID, err)
	}
	return imp, nil
}

// GetNetworkControlExpectationImport returns one import by id. A
// missing id returns an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetNetworkControlExpectationImport(ctx context.Context, pool *pgxpool.Pool, id string) (*networkefficacy.ControlExpectationImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, expectations_data
		 FROM network_control_expectations WHERE id = $1`, id)
	imp, err := scanNetworkControlExpectationImport(row)
	if err != nil {
		return nil, fmt.Errorf("network_control_expectations: get %s: %w", id, err)
	}
	return imp, nil
}

// ListNetworkControlExpectationImports returns up to limit rows, newest
// first.
func ListNetworkControlExpectationImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*networkefficacy.ControlExpectationImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, expectations_data
		 FROM network_control_expectations ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("network_control_expectations: list: %w", err)
	}
	defer rows.Close()
	var out []*networkefficacy.ControlExpectationImport
	for rows.Next() {
		imp, err := scanNetworkControlExpectationImport(rows)
		if err != nil {
			return nil, fmt.Errorf("network_control_expectations: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("network_control_expectations: list rows: %w", err)
	}
	return out, nil
}
