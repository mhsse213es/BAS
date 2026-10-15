package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/targetscope"
)

// EnsureTargetScopeImportSchema creates the target_scope_imports table.
func EnsureTargetScopeImportSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS target_scope_imports (
			id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type         text        NOT NULL,
			imported_by         text,
			imported_at         timestamptz NOT NULL DEFAULT NOW(),
			config_version      text,
			limitations         text[],
			target_scope_data   jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("target_scope_imports: ensure schema: %w", err)
	}
	return nil
}

// targetScopeData is the shape persisted in the target_scope_data
// jsonb column -- just the content, not the metadata (which live in
// their own columns).
type targetScopeData struct {
	AuthorizedTargets []targetscope.AuthorizedTarget `json:"authorizedTargets"`
}

// InsertTargetScopeImport writes a new target_scope_imports row. The
// caller supplies imp.ID already generated.
func InsertTargetScopeImport(ctx context.Context, pool *pgxpool.Pool, imp *targetscope.TargetScopeImport) error {
	data, err := json.Marshal(targetScopeData{AuthorizedTargets: imp.AuthorizedTargets})
	if err != nil {
		return fmt.Errorf("target_scope_imports: marshal target scope data for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO target_scope_imports (id, source_type, imported_by, config_version, limitations, target_scope_data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("target_scope_imports: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanTargetScopeImport(row pgx.Row) (*targetscope.TargetScopeImport, error) {
	imp := &targetscope.TargetScopeImport{}
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
	var sd targetScopeData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, fmt.Errorf("target_scope_imports: unmarshal target scope data for %s: %w", imp.ID, err)
	}
	imp.AuthorizedTargets = sd.AuthorizedTargets
	return imp, nil
}

// GetTargetScopeImport returns one import by id. A missing id returns
// an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetTargetScopeImport(ctx context.Context, pool *pgxpool.Pool, id string) (*targetscope.TargetScopeImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, target_scope_data
		 FROM target_scope_imports WHERE id = $1`, id)
	imp, err := scanTargetScopeImport(row)
	if err != nil {
		return nil, fmt.Errorf("target_scope_imports: get %s: %w", id, err)
	}
	return imp, nil
}

// ListTargetScopeImports returns up to limit rows, newest first.
func ListTargetScopeImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*targetscope.TargetScopeImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, target_scope_data
		 FROM target_scope_imports ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("target_scope_imports: list: %w", err)
	}
	defer rows.Close()
	var out []*targetscope.TargetScopeImport
	for rows.Next() {
		imp, err := scanTargetScopeImport(rows)
		if err != nil {
			return nil, fmt.Errorf("target_scope_imports: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("target_scope_imports: list rows: %w", err)
	}
	return out, nil
}
