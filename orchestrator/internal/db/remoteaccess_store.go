package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/remoteaccess"
)

// EnsureRemoteAccessImportSchema creates the remote_access_imports table.
func EnsureRemoteAccessImportSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS remote_access_imports (
			id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type     text        NOT NULL,
			imported_by     text,
			imported_at     timestamptz NOT NULL DEFAULT NOW(),
			config_version  text,
			limitations     text[],
			remote_access_data jsonb    NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("remote_access_imports: ensure schema: %w", err)
	}
	return nil
}

// remoteAccessData is the shape persisted in the remote_access_data
// jsonb column -- just the two slices that make an import's content,
// not its metadata (which live in their own columns).
type remoteAccessData struct {
	Tunnels  []remoteaccess.VPNTunnel        `json:"tunnels"`
	Transits []remoteaccess.MandatoryTransit `json:"transits"`
}

// InsertRemoteAccessImport writes a new remote_access_imports row. The
// caller supplies imp.ID already generated.
func InsertRemoteAccessImport(ctx context.Context, pool *pgxpool.Pool, imp *remoteaccess.RemoteAccessImport) error {
	data, err := json.Marshal(remoteAccessData{Tunnels: imp.Tunnels, Transits: imp.Transits})
	if err != nil {
		return fmt.Errorf("remote_access_imports: marshal remote access data for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO remote_access_imports (id, source_type, imported_by, config_version, limitations, remote_access_data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("remote_access_imports: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanRemoteAccessImport(row pgx.Row) (*remoteaccess.RemoteAccessImport, error) {
	imp := &remoteaccess.RemoteAccessImport{}
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
	var rd remoteAccessData
	if err := json.Unmarshal(data, &rd); err != nil {
		return nil, fmt.Errorf("remote_access_imports: unmarshal remote access data for %s: %w", imp.ID, err)
	}
	imp.Tunnels, imp.Transits = rd.Tunnels, rd.Transits
	return imp, nil
}

// GetRemoteAccessImport returns one import by id. A missing id returns
// an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetRemoteAccessImport(ctx context.Context, pool *pgxpool.Pool, id string) (*remoteaccess.RemoteAccessImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, remote_access_data
		 FROM remote_access_imports WHERE id = $1`, id)
	imp, err := scanRemoteAccessImport(row)
	if err != nil {
		return nil, fmt.Errorf("remote_access_imports: get %s: %w", id, err)
	}
	return imp, nil
}

// ListRemoteAccessImports returns up to limit rows, newest first.
func ListRemoteAccessImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*remoteaccess.RemoteAccessImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, remote_access_data
		 FROM remote_access_imports ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("remote_access_imports: list: %w", err)
	}
	defer rows.Close()
	var out []*remoteaccess.RemoteAccessImport
	for rows.Next() {
		imp, err := scanRemoteAccessImport(rows)
		if err != nil {
			return nil, fmt.Errorf("remote_access_imports: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("remote_access_imports: list rows: %w", err)
	}
	return out, nil
}
